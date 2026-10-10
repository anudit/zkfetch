//! Prover.

mod client;
mod conn;
mod control;
mod future;
mod prove;
pub mod state;

pub use conn::TlsConnection;
pub use control::ProverControl;
pub use future::ProverFuture;
pub use tlsn_core::ProverOutput;

use crate::{
    Error, Mpc, PROXY_STREAM_PREFIX, ProtocolConfig, Proxy, Result, TlsOutput,
    deps::{ProverDeps, ProverMpcDeps, ProverProxyDeps},
    msg::{ProveRequestMsg, Response, TlsCommitRequestMsg},
    prover::{
        client::{MpcTlsClient, ProxyTlsClient, TlsClient},
        future::FutureState,
        state::ConnectedProj,
    },
    tag::verify_tags,
};

use futures::{AsyncRead, AsyncWrite, ready};
use mpz_common::Context;
use mpz_vm_core::Execute;
use serio::{SinkExt, stream::IoStreamExt};
use std::{fmt::Debug, marker::PhantomData, pin::Pin, task::Poll};
use tls_client::ServerName as TlsServerName;
use tlsn_core::{
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig, tls_commit::TlsCommitConfig,
    },
    connection::{HandshakeData, ServerName},
    transcript::{TlsTranscript, Transcript},
};
use tlsn_mux::{Handle, Stream};
use tracing::{Span, debug, info_span, instrument};

const BUF_CAP: usize = 16 * 1024 * 1024;

pub use client::ProxyClientHello;

/// A prover instance.
pub struct Prover<T: state::ProverState = state::Initialized> {
    config: ProverConfig,
    span: Span,
    ctx: Option<Context>,
    mux_handle: Handle,
    low_latency: bool,
    state: T,
}

impl<T: state::ProverState> Debug for Prover<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prover")
            .field("config", &self.config)
            .field("span", &self.span)
            .field("ctx", &self.ctx)
            .field("mux_handle", &"{{ .. }}")
            .field("state", &"{{ .. }}")
            .finish()
    }
}

impl Prover<state::Initialized> {
    /// Creates a new prover.
    ///
    /// # Arguments
    ///
    /// * `ctx` - A thread context.
    /// * `mux_handle` - A handle for the multiplexer.
    /// * `config` - The configuration for the prover.
    pub(crate) fn new(ctx: Context, mux_handle: Handle, config: ProverConfig) -> Self {
        let span = info_span!("prover");
        Self {
            config,
            span,
            ctx: Some(ctx),
            mux_handle,
            low_latency: false,
            state: state::Initialized::default(),
        }
    }

    /// Uses an exclusively leased persistent Ferret pool for a proxy session.
    pub fn with_vole_pool(mut self, pool: &mut crate::vole_pool::ProverVolePool) -> Self {
        self.low_latency = pool.low_latency;
        self.state.pool = Some(pool.session_handle());
        self
    }

    /// Starts the TLS commitment protocol.
    ///
    /// This initiates the TLS commitment protocol, including performing any
    /// necessary preprocessing operations.
    ///
    /// # Arguments
    ///
    /// * `config` - The TLS commitment configuration.
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub async fn commit<P: ProtocolConfig>(
        mut self,
        config: P,
    ) -> Result<Prover<state::CommitAccepted<P::Commit>>> {
        let mut ctx = self
            .ctx
            .take()
            .ok_or_else(|| Error::internal().with_msg("commitment protocol context was dropped"))?;

        if self.state.pool.is_some() && !matches!(config.clone().into(), TlsCommitConfig::Proxy(_))
        {
            return Err(Error::config().with_msg("persistent VOLE is supported only in proxy mode"));
        }

        let opened = self
            .state
            .pool
            .as_ref()
            .and_then(|p| p.opened_host.as_ref());
        if let Some(host) = opened {
            match config.clone().into() {
                TlsCommitConfig::Proxy(c)
                    if c.server_name().as_str() == host
                        && c.tls_version() == tlsn_core::connection::TlsVersion::V1_3 => {}
                _ => {
                    return Err(Error::config()
                        .with_msg("configuration differs from authenticated opening"));
                }
            }
        }
        if opened.is_none() {
            if let Some(pool) = &self.state.pool {
                ctx.io_mut()
                    .send(pool.binding)
                    .await
                    .map_err(|e| Error::io().with_source(e))?;
            }

            // Sends protocol configuration to verifier for compatibility check.
            ctx.io_mut()
                .send(TlsCommitRequestMsg {
                    config: config.clone().into(),
                    version: crate::VERSION.clone(),
                })
                .await
                .map_err(|e| {
                    Error::io()
                        .with_msg("commitment protocol failed to send request")
                        .with_source(e)
                })?;
        }

        // The authenticated pool opening opts both peers into pipelined setup.
        // Config and Ferret initialization travel in the same outbound flight.
        if self.state.pool.is_none() {
            ctx.io_mut()
                .expect_next::<Response>()
                .await
                .map_err(|e| {
                    Error::io()
                        .with_msg("commitment protocol failed to receive response")
                        .with_source(e)
                })?
                .result
                .map_err(|e| {
                    Error::user()
                        .with_msg("commitment protocol rejected by verifier")
                        .with_source(e)
                })?;
        }

        let commit_config: TlsCommitConfig = config.into();
        let mut deps = ProverDeps::new(commit_config, ctx, self.state.pool.as_ref());
        deps.setup().await?;

        debug!("setup complete");

        Ok(Prover {
            config: self.config,
            span: self.span,
            ctx: None,
            mux_handle: self.mux_handle,
            low_latency: self.low_latency,
            state: state::CommitAccepted {
                deps,
                _pd: PhantomData,
            },
        })
    }
}

impl Prover<state::CommitAccepted<Mpc>> {
    /// Connects to the server via MPC-TLS.
    ///
    /// This method is used for MPC mode only.
    ///
    /// # Arguments
    ///
    /// * `config` - The TLS client configuration.
    /// * `server_socket` - The connection to the server.
    ///
    /// # Returns
    ///
    /// * handle to the TLS connection
    /// * the connected prover
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub fn connect<S: AsyncWrite + AsyncRead + Send + Unpin>(
        self,
        config: TlsClientConfig,
        server_socket: S,
    ) -> Result<(TlsConnection, Prover<state::Connected<S>>)> {
        let ProverDeps::Mpc(ProverMpcDeps { vm, mpc_tls, keys }) = self.state.deps else {
            unreachable!("mpc-tls received incorrect deps")
        };

        let ServerName::Dns(server_name) = config.server_name();
        let server_name =
            TlsServerName::try_from(server_name.as_ref()).expect("name was validated");
        let span = self.span.clone();

        let keys = keys.expect("keys should be available");
        let client = MpcTlsClient::new(keys, vm, span, &config, server_name, mpc_tls)?;
        let tls_client: Box<dyn TlsClient<Error = Error> + Send> = Box::new(client);

        let control = ProverControl {
            decrypt: tls_client.decrypt(),
        };

        let (client_io, tlsn_conn) = futures_plex::duplex(BUF_CAP);
        let (client_to_server, server_to_client) = futures_plex::duplex(BUF_CAP);

        let prover = Prover {
            ctx: self.ctx,
            mux_handle: self.mux_handle,
            low_latency: self.low_latency,
            config: self.config,
            span: self.span,
            state: state::Connected {
                server_name: config.server_name().clone(),
                tls_client,
                control,
                client_io,
                output: None,
                server_socket,
                client_to_server,
                server_to_client,
                client_closed: false,
                server_closed: false,
            },
        };

        let conn = TlsConnection::new(tlsn_conn);

        Ok((conn, prover))
    }
}

impl Prover<state::CommitAccepted<Proxy>> {
    /// Connects to the proxy.
    ///
    /// This method is used for proxy mode only. The proxy stream through the
    /// verifier is opened internally.
    ///
    /// # Arguments
    ///
    /// * `config` - The TLS client configuration.
    ///
    /// # Returns
    ///
    /// * handle to the TLS connection
    /// * the connected prover
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub fn connect(
        self,
        config: TlsClientConfig,
    ) -> Result<(TlsConnection, Prover<state::Connected<Stream>>)> {
        self.connect_inner(config, None)
    }

    /// Continues a TLS handshake whose ClientHello was sent in the opening.
    pub fn connect_opened(
        self,
        config: TlsClientConfig,
        hello: ProxyClientHello,
    ) -> Result<(TlsConnection, Prover<state::Connected<Stream>>)> {
        self.connect_inner(config, Some(hello))
    }

    fn connect_inner(
        self,
        config: TlsClientConfig,
        hello: Option<ProxyClientHello>,
    ) -> Result<(TlsConnection, Prover<state::Connected<Stream>>)> {
        let ProverDeps::Proxy(ProverProxyDeps {
            prover: proxy_prover,
            pipeline_tls,
            id,
        }) = self.state.deps
        else {
            unreachable!("proxy-tls received incorrect deps")
        };

        let mut proxy_id = PROXY_STREAM_PREFIX.to_vec();
        proxy_id.extend_from_slice(id.as_bytes());
        let proxy_socket = self.mux_handle.new_stream(&proxy_id)?;

        let ServerName::Dns(server_name) = config.server_name();
        let server_name =
            TlsServerName::try_from(server_name.as_ref()).expect("name was validated");

        let client = match hello {
            Some(hello) => ProxyTlsClient::from_hello(proxy_prover, hello, true)?,
            None => ProxyTlsClient::new(proxy_prover, &config, server_name)?,
        };
        let _ = pipeline_tls;
        let tls_client: Box<dyn TlsClient<Error = Error> + Send> = Box::new(client);

        let control = ProverControl {
            decrypt: tls_client.decrypt(),
        };

        let (client_io, tlsn_conn) = futures_plex::duplex(BUF_CAP);
        let (client_to_server, server_to_client) = futures_plex::duplex(BUF_CAP);

        let prover = Prover {
            ctx: self.ctx,
            mux_handle: self.mux_handle,
            low_latency: self.low_latency,
            config: self.config,
            span: self.span,
            state: state::Connected {
                server_name: config.server_name().clone(),
                tls_client,
                control,
                client_io,
                output: None,
                server_socket: proxy_socket,
                client_to_server,
                server_to_client,
                client_closed: false,
                server_closed: false,
            },
        };

        let conn = TlsConnection::new(tlsn_conn);

        Ok((conn, prover))
    }
}

impl<S> Prover<state::Connected<S>>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    /// Returns a [`ProverControl`] for connection specific settings.
    pub fn control(&self) -> ProverControl {
        self.state.control.clone()
    }

    fn poll(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Error>> {
        let mut state = Pin::new(&mut self.state).project();

        Self::io_to_tls_client(&mut state, cx)?;

        if state.output.is_none()
            && let Poll::Ready(output) = state.tls_client.poll(cx)?
        {
            *state.output = Some(output);
        }

        Self::io_from_tls_client(&mut state, cx)?;

        if *state.server_closed && state.output.is_some() {
            ready!(state.client_io.poll_close(cx))?;
            ready!(state.server_socket.poll_close(cx))?;

            return Poll::Ready(Ok(()));
        }

        Poll::Pending
    }
}

impl<S> IntoFuture for Prover<state::Connected<S>>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type Output = Result<Prover<state::Committed>, Error>;
    type IntoFuture = ProverFuture<S>;

    fn into_future(self) -> Self::IntoFuture {
        ProverFuture {
            state: FutureState::Connected {
                prover: Box::new(self),
            },
        }
    }
}

impl<S> Prover<state::Connected<S>>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    async fn finish(self) -> Result<Prover<state::Committed>, Error> {
        let (
            mut ctx,
            mut vm,
            TlsOutput {
                #[cfg(feature = "d1-experimental")]
                epoch_ciphertext,
                #[cfg(feature = "d1-experimental")]
                native_keys,
                keys,
                tls_transcript,
                deferred_schedule,
            },
        ) = self
            .state
            .output
            .ok_or(Error::internal().with_msg("prover has not yet closed the connection"))?;

        // Prove tag verification of received records.
        // The prover drops the proof output.
        let _ = verify_tags(
            &mut vm,
            (keys.server_write_key, keys.server_write_iv),
            keys.server_write_mac_key,
            tls_transcript.version(),
            tls_transcript.recv().to_vec(),
        )
        .map_err(|err| {
            Error::internal()
                .with_msg("tag verification setup failed")
                .with_source(err)
        })?;

        if deferred_schedule.is_none() {
            vm.execute_all(&mut ctx).await.map_err(|err| {
                Error::internal()
                    .with_msg("tag verification zk execution failed")
                    .with_source(err)
            })?;
        }

        debug!("verified tags from server");

        let transcript = tls_transcript.to_transcript().map_err(|e| {
            Error::internal()
                .with_msg("prover could not create transcript")
                .with_source(e)
        })?;

        let prover = Prover {
            config: self.config,
            span: self.span,
            ctx: Some(ctx),
            mux_handle: self.mux_handle,
            low_latency: self.low_latency,
            state: state::Committed {
                #[cfg(feature = "d1-experimental")]
                field_ready: false,
                #[cfg(feature = "d1-experimental")]
                epoch_ciphertext,
                #[cfg(feature = "d1-experimental")]
                native_keys,
                vm,
                deferred_schedule,
                server_name: self.state.server_name,
                keys,
                tls_transcript,
                transcript,
            },
        };

        Ok(prover)
    }

    fn io_to_tls_client(
        state: &mut ConnectedProj<S>,
        cx: &mut std::task::Context<'_>,
    ) -> Result<(), Error> {
        // tls_conn -> tls_client
        // Always poll to register wakers, then check wants_write()
        if let Poll::Ready(mut simplex) = state.client_io.as_mut().poll_lock_read(cx)
            && let Poll::Ready(buf) = simplex.poll_get(cx)?
        {
            if !buf.is_empty() {
                if state.tls_client.wants_write() {
                    let write = state.tls_client.write(buf)?;
                    if write > 0 {
                        simplex.advance(write);
                    }
                } else {
                    cx.waker().wake_by_ref();
                }
            } else if !*state.client_closed && !*state.server_closed {
                *state.client_closed = true;
                state.tls_client.client_close();
            }
        }

        // server_socket -> buf
        if let Poll::Ready(write) = state
            .server_to_client
            .poll_write_from(cx, state.server_socket.as_mut())?
        {
            if write == 0 && !*state.server_closed {
                *state.server_closed = true;
            } else if write > 0 {
                cx.waker().wake_by_ref();
            }
        }

        // buf -> tls_client
        // Always poll to register wakers, then check wants_read_tls()
        if let Poll::Ready(mut simplex) = state.client_to_server.as_mut().poll_lock_read(cx)
            && let Poll::Ready(buf) = simplex.poll_get(cx)?
        {
            if state.tls_client.wants_read_tls() {
                let read = state.tls_client.read_tls(buf)?;
                if read > 0 {
                    simplex.advance(read);
                    cx.waker().wake_by_ref();
                }
            } else if !buf.is_empty() {
                cx.waker().wake_by_ref();
            }
        } else if *state.server_closed {
            state.tls_client.server_close();
        }

        Ok(())
    }

    fn io_from_tls_client(
        state: &mut ConnectedProj<S>,
        cx: &mut std::task::Context<'_>,
    ) -> Result<(), Error> {
        // tls_client -> buf
        // Always poll to register wakers, then check wants_write_tls()
        if let Poll::Ready(mut simplex) = state.client_to_server.as_mut().poll_lock_write(cx)
            && let Poll::Ready(buf) = simplex.poll_mut(cx)?
        {
            let write = state.tls_client.write_tls(buf)?;
            if write > 0 {
                simplex.advance_mut(write);
            } else if state.tls_client.wants_write_tls() {
                cx.waker().wake_by_ref();
            }
        }

        // buf -> server_socket
        match state
            .server_to_client
            .poll_read_to(cx, state.server_socket.as_mut())
        {
            // do not attempt to write into closed sockets
            Poll::Ready(Err(err)) if matches!(err.kind(), std::io::ErrorKind::BrokenPipe) => {}
            Poll::Ready(Err(err)) if matches!(err.kind(), std::io::ErrorKind::ConnectionReset) => {}
            Poll::Ready(Err(err)) => return Err(Error::from(err)),
            _ => {}
        }

        // tls_client -> tls_conn
        // Always poll to register wakers, then check wants_read()
        if let Poll::Ready(mut simplex) = state.client_io.as_mut().poll_lock_write(cx)
            && let Poll::Ready(buf) = simplex.poll_mut(cx)?
            && state.tls_client.wants_read()
        {
            let read = state.tls_client.read(buf)?;
            if read > 0 {
                simplex.advance_mut(read);
            }
        }

        Ok(())
    }
}

impl Prover<state::Committed> {
    /// Borrow the unfiltered application-epoch ciphertext captured by the proxy.
    #[cfg(feature = "d1-experimental")]
    pub fn application_epoch_ciphertext(&self) -> Option<&crate::ApplicationEpochCiphertext> {
        self.state.epoch_ciphertext.as_ref()
    }

    /// Borrow locally retained keys for an experimental presentation. Keys are
    /// available only for native TLS 1.3 proxy sessions, never from VM decoding.
    #[cfg(feature = "d1-experimental")]
    pub fn application_key_secrets(&self) -> Option<&crate::ApplicationKeySecrets> {
        self.state.native_keys.as_ref()
    }

    /// Prove an experimental field relation borrowing the existing TLS
    /// application key. Both parties must explicitly negotiate this operation.
    /// The public circuit and binding must be reconstructed from notary policy.
    /// This operation currently follows the existing session proof; it does
    /// not remove its tag/hash work or constitute the completed D1 protocol.
    #[cfg(all(feature = "d1-experimental", not(tlsn_insecure)))]
    pub async fn prove_application_key_relation(
        &mut self,
        direction: tlsn_core::transcript::Direction,
        circuit: &zkf_ir::Circuit,
        witness: &zkf_ir::Witness,
        binding: &[u8],
    ) -> Result<()> {
        if !self.state.field_ready || self.state.epoch_ciphertext.is_none() || self.state.deferred_schedule.is_some() {
            return Err(Error::user().with_msg("accept the TLS schedule proof before field relations"));
        }
        let prefix = match direction {
            tlsn_core::transcript::Direction::Sent => self.state.keys.client_write_key,
            tlsn_core::transcript::Direction::Received => self.state.keys.server_write_key,
        };
        let ctx = self.ctx.as_mut().ok_or_else(|| Error::internal().with_msg("proving context was dropped"))?;
        zkf_ir::backend::mpz::prove(&mut self.state.vm, ctx, circuit, witness, prefix, binding)
            .await.map_err(|e| Error::internal().with_msg(format!("application key relation failed: {e}")))
    }

    /// Combined Fiat--Shamir relation borrowing both session keys in order.
    #[cfg(all(feature = "d1-experimental", not(tlsn_insecure)))]
    pub async fn prove_application_keys_relation(
        &mut self,
        circuit: &zkf_ir::Circuit,
        witness: &zkf_ir::Witness,
        binding: &[u8],
    ) -> Result<()> {
        if !self.state.field_ready || self.state.epoch_ciphertext.is_none() || self.state.deferred_schedule.is_some() {
            return Err(Error::user().with_msg("accept the TLS schedule proof before field relations"));
        }
        let prefixes = [self.state.keys.client_write_key, self.state.keys.server_write_key];
        let ctx = self.ctx.as_mut().ok_or_else(|| Error::internal().with_msg("proving context was dropped"))?;
        zkf_ir::backend::mpz::prove_profiled_prefixes(&mut self.state.vm, ctx, circuit, witness, &prefixes, binding, true)
            .await.map_err(|e| Error::internal().with_msg(format!("application key relation failed: {e}")))
    }

    /// Returns the TLS transcript.
    pub fn tls_transcript(&self) -> &TlsTranscript {
        &self.state.tls_transcript
    }

    /// Returns the transcript.
    pub fn transcript(&self) -> &Transcript {
        &self.state.transcript
    }

    /// Proves information to the verifier.
    ///
    /// # Arguments
    ///
    /// * `config` - The disclosure configuration.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn prove(&mut self, config: &ProveConfig) -> Result<ProverOutput> {
        let ctx = self
            .ctx
            .as_mut()
            .ok_or_else(|| Error::internal().with_msg("proving context was dropped"))?;
        let state::Committed {
            vm,
            keys,
            server_name,
            tls_transcript,
            transcript,
            deferred_schedule,
            ..
        } = &mut self.state;

        let handshake = config.server_identity().then(|| {
            (
                server_name.clone(),
                HandshakeData {
                    certs: tls_transcript
                        .server_cert_chain()
                        .expect("server cert chain is present")
                        .to_vec(),
                    sig: tls_transcript
                        .server_signature()
                        .expect("server signature is present")
                        .clone(),
                    binding: tls_transcript.certificate_binding().clone(),
                },
            )
        });

        let partial_transcript = config
            .reveal()
            .map(|(sent, recv)| transcript.to_partial(sent.clone(), recv.clone()));

        let msg = ProveRequestMsg {
            request: config.to_request(),
            handshake,
            transcript: partial_transcript,
        };

        if self.low_latency {
            vm.bind_statement(
                &bincode::serialize(&msg).map_err(|e| Error::internal().with_source(e))?,
            );
        }
        ctx.io_mut().send(msg).await.map_err(|e| {
            Error::io()
                .with_msg("failed to send prove configuration")
                .with_source(e)
        })?;
        if !self.low_latency {
            ctx.io_mut()
                .expect_next::<Response>()
                .await
                .map_err(|e| {
                    Error::io()
                        .with_msg("failed to receive prove response from verifier")
                        .with_source(e)
                })?
                .result
                .map_err(|e| {
                    Error::user()
                        .with_msg("proving rejected by verifier")
                        .with_source(e)
                })?;
        }

        let output = prove::prove(ctx, vm, keys, transcript, tls_transcript, config).await?;
        if let Some(schedule) = deferred_schedule.take() {
            schedule.verify()?;
        }

        #[cfg(feature = "d1-experimental")]
        { self.state.field_ready |= config.server_identity(); }

        Ok(output)
    }

    /// Closes the connection with the verifier.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn close(self) -> Result<()> {
        Ok(())
    }
}
