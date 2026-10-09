//! Verifier.

pub mod state;
pub(crate) mod verify;

pub use tlsn_core::{VerifierOutput, webpki::ServerCertVerifier};

use crate::{
    Error, Mpc, PROXY_STREAM_PREFIX, Proxy, Result,
    deps::{VerifierDeps, VerifierMpcDeps, VerifierProxyDeps},
    msg::{ProveRequestMsg, Response, TlsCommitRequestMsg},
    proxy::InspectReader,
    tag::verify_tags,
};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use mpz_common::Context;
use mpz_vm_core::prelude::*;
use serio::{SinkExt, stream::IoStreamExt};
use std::{marker::PhantomData, sync::Arc};
use tlsn_core::{
    config::{
        prove::ProveRequest,
        tls_commit::{TlsCommitConfig, mpc::MpcTlsConfig, proxy::ProxyTlsConfig},
        verifier::VerifierConfig,
    },
    connection::{ConnectionInfo, ServerName},
    transcript::TlsTranscript,
};
use tlsn_mux::Handle;
use tracing::{Span, debug, info, info_span, instrument};

/// Information about the TLS session.
#[derive(Debug)]
pub struct SessionInfo {
    /// Server's name.
    pub server_name: ServerName,
    /// Connection information.
    pub connection_info: ConnectionInfo,
}

/// A Verifier instance.
pub struct Verifier<T: state::VerifierState = state::Initialized> {
    config: VerifierConfig,
    span: Span,
    ctx: Option<Context>,
    mux_handle: Handle,
    low_latency: bool,
    state: T,
}

impl Verifier<state::Initialized> {
    /// Creates a new verifier.
    ///
    /// # Arguments
    ///
    /// * `ctx` - A thread context.
    /// * `mux_handle` - A handle for the multiplexer.
    /// * `config` - The configuration for the verifier.
    pub(crate) fn new(ctx: Context, mux_handle: Handle, config: VerifierConfig) -> Self {
        let span = info_span!("verifier");
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
    pub fn with_vole_pool(mut self, pool: &mut crate::vole_pool::VerifierVolePool) -> Self {
        self.low_latency = pool.low_latency;
        self.state.pool = Some(pool.session_handle());
        self
    }

    /// Start from the proxy configuration already authenticated in the opening.
    pub fn commit_opened(mut self, config: ProxyTlsConfig) -> Result<VerifierCommitStart> {
        let pool = self
            .state
            .pool
            .as_ref()
            .ok_or_else(|| Error::config().with_msg("opened configuration requires a pool"))?;
        if !pool.low_latency
            || pool.opened_host.as_deref() != Some(config.server_name().as_str())
            || config.tls_version() != tlsn_core::connection::TlsVersion::V1_3
        {
            return Err(
                Error::config().with_msg("configuration differs from authenticated opening")
            );
        }
        let ctx = self
            .ctx
            .take()
            .ok_or_else(|| Error::internal().with_msg("commitment protocol context was dropped"))?;
        Ok(VerifierCommitStart::Proxy(Verifier {
            config: self.config,
            span: self.span,
            ctx: Some(ctx),
            mux_handle: self.mux_handle,
            low_latency: self.low_latency,
            state: state::CommitStart {
                config: config.into(),
                pool: self.state.pool,
                _pd: PhantomData,
            },
        }))
    }

    /// Starts the TLS commitment protocol.
    ///
    /// This initiates the TLS commitment protocol, receiving the prover's
    /// configuration and providing the opportunity to accept or reject it.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn commit(mut self) -> Result<VerifierCommitStart> {
        let mut ctx = self
            .ctx
            .take()
            .ok_or_else(|| Error::internal().with_msg("commitment protocol context was dropped"))?;

        if let Some(pool) = &self.state.pool {
            let binding: [u8; 32] = ctx
                .io_mut()
                .expect_next()
                .await
                .map_err(|e| Error::io().with_source(e))?;
            if binding != pool.binding {
                return Err(Error::config().with_msg("persistent pool lease binding mismatch"));
            }
        }

        // Receives protocol configuration from prover to perform compatibility check.
        let TlsCommitRequestMsg { config, version } =
            ctx.io_mut().expect_next().await.map_err(|e| {
                Error::io()
                    .with_msg("commitment protocol failed to receive request")
                    .with_source(e)
            })?;

        if self.state.pool.is_some() && !matches!(&config, TlsCommitConfig::Proxy(_)) {
            return Err(Error::config().with_msg("persistent VOLE is supported only in proxy mode"));
        }

        if version != *crate::VERSION {
            let msg = format!(
                "prover version does not match with verifier: {version} != {}",
                *crate::VERSION
            );
            ctx.io_mut()
                .send(Response::err(Some(msg.clone())))
                .await
                .map_err(|e| {
                    Error::io()
                        .with_msg("commitment protocol failed to send version mismatch response")
                        .with_source(e)
                })?;

            return Err(Error::config().with_msg(msg));
        }

        let verifier = match &config {
            TlsCommitConfig::Mpc(_) => VerifierCommitStart::Mpc(Verifier {
                config: self.config,
                span: self.span,
                ctx: Some(ctx),
                mux_handle: self.mux_handle,
                low_latency: self.low_latency,
                state: state::CommitStart {
                    config,
                    pool: self.state.pool,
                    _pd: PhantomData,
                },
            }),
            TlsCommitConfig::Proxy(_) => VerifierCommitStart::Proxy(Verifier {
                config: self.config,
                span: self.span,
                ctx: Some(ctx),
                mux_handle: self.mux_handle,
                low_latency: self.low_latency,
                state: state::CommitStart {
                    config,
                    pool: self.state.pool,
                    _pd: PhantomData,
                },
            }),
            _ => return Err(Error::config().with_msg("unknown protocol requested")),
        };

        Ok(verifier)
    }
}

/// Commit started verifiers for different protocols.
pub enum VerifierCommitStart {
    /// Verifier for MPC protocol.
    Mpc(Verifier<state::CommitStart<Mpc>>),
    /// Verifier for Proxy protocol.
    Proxy(Verifier<state::CommitStart<Proxy>>),
}

impl<P> Verifier<state::CommitStart<P>> {
    /// Accepts the proposed protocol configuration.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn accept(mut self) -> Result<Verifier<state::CommitAccepted<P>>> {
        let mut ctx = self
            .ctx
            .take()
            .ok_or_else(|| Error::internal().with_msg("commitment protocol context was dropped"))?;

        if self.state.pool.is_none() {
            ctx.io_mut().send(Response::ok()).await.map_err(|e| {
                Error::io()
                    .with_msg("commitment protocol failed to send acceptance")
                    .with_source(e)
            })?;
        }

        let mut deps = VerifierDeps::new(&self.state.config, ctx, self.state.pool.as_ref());
        deps.setup().await?;

        debug!("setup complete");

        let verifier = Verifier {
            config: self.config,
            span: self.span,
            ctx: None,
            mux_handle: self.mux_handle,
            low_latency: self.low_latency,
            state: state::CommitAccepted {
                deps,
                _pd: PhantomData,
            },
        };

        Ok(verifier)
    }

    /// Rejects the proposed protocol configuration.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn reject(mut self, msg: Option<&str>) -> Result<()> {
        let mut ctx = self
            .ctx
            .take()
            .ok_or_else(|| Error::internal().with_msg("commitment protocol context was dropped"))?;

        ctx.io_mut().send(Response::err(msg)).await.map_err(|e| {
            Error::io()
                .with_msg("commitment protocol failed to send rejection")
                .with_source(e)
        })?;

        Ok(())
    }
}

impl Verifier<state::CommitStart<Mpc>> {
    /// Returns the commit config.
    pub fn config(&self) -> &MpcTlsConfig {
        let TlsCommitConfig::Mpc(config) = &self.state.config else {
            unreachable!("mpc-tls received incorrect config")
        };
        config
    }
}

impl Verifier<state::CommitStart<Proxy>> {
    /// Returns the commit config.
    pub fn config(&self) -> &ProxyTlsConfig {
        let TlsCommitConfig::Proxy(config) = &self.state.config else {
            unreachable!("proxy-tls received incorrect config")
        };
        config
    }
}

impl Verifier<state::CommitAccepted<Mpc>> {
    /// Runs the verifier until the TLS connection is closed.
    ///
    /// This method is used for MPC mode only.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn run(self) -> Result<Verifier<state::Committed>> {
        let VerifierDeps::Mpc(VerifierMpcDeps { vm, mpc_tls, keys }) = self.state.deps else {
            unreachable!("mpc-tls received incorrect deps")
        };

        info!("starting MPC-TLS");
        let (mut ctx, tls_transcript) = mpc_tls.run().await.map_err(|e| {
            Error::internal()
                .with_msg("mpc-tls execution failed")
                .with_source(e)
        })?;

        info!("finished MPC-TLS");

        {
            let mut vm = vm.try_lock().expect("VM should not be locked");

            debug!("finalizing mpc");

            vm.finalize(&mut ctx).await.map_err(|e| {
                Error::internal()
                    .with_msg("mpc finalization failed")
                    .with_source(e)
            })?;

            debug!("mpc finalized");
        }

        // Pull out ZK VM.
        let (_, mut vm) = Arc::into_inner(vm)
            .expect("vm should have only 1 reference")
            .into_inner()
            .into_inner();
        let keys = keys.expect("keys should be available");

        // Prepare for the prover to prove tag verification of the received
        // records.
        let tag_proof = verify_tags(
            &mut vm,
            (keys.server_write_key, keys.server_write_iv),
            keys.server_write_mac_key,
            tls_transcript.version(),
            tls_transcript.recv().to_vec(),
        )
        .map_err(|e| {
            Error::internal()
                .with_msg("tag verification setup failed")
                .with_source(e)
        })?;

        vm.execute_all(&mut ctx).await.map_err(|e| {
            Error::internal()
                .with_msg("tag verification zk execution failed")
                .with_source(e)
        })?;

        // Verify the tags.
        // After the verification, the entire TLS trancript becomes
        // authenticated from the verifier's perspective.
        tag_proof.verify().map_err(|e| {
            Error::internal()
                .with_msg("tag verification failed")
                .with_source(e)
        })?;

        debug!("verified tags successfully");

        Ok(Verifier {
            config: self.config,
            span: self.span,
            ctx: Some(ctx),
            mux_handle: self.mux_handle,
            low_latency: self.low_latency,
            state: state::Committed {
                deferred_schedule: None,
                deferred_tags: None,
                vm,
                keys,
                tls_transcript,
            },
        })
    }
}

impl Verifier<state::CommitAccepted<Proxy>> {
    /// Runs the verifier until the TLS connection is closed.
    ///
    /// This method is used for proxy mode only.
    ///
    /// # Arguments
    ///
    /// * `server_socket` - The connection to the server.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn run<T>(self, server_socket: T) -> Result<Verifier<state::Committed>>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin,
    {
        self.run_opened(server_socket, Vec::new()).await
    }

    /// Relays a connection whose public ClientHello was already policy-checked
    /// and forwarded by the session opening. The bytes remain in the transcript.
    pub async fn run_opened<T>(
        self,
        server_socket: T,
        client_hello: Vec<u8>,
    ) -> Result<Verifier<state::Committed>>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin,
    {
        let VerifierDeps::Proxy(VerifierProxyDeps {
            verifier,
            pipeline_tls,
            id,
            server_name,
        }) = self.state.deps
        else {
            unreachable!("proxy-tls received incorrect deps")
        };

        let opened = !client_hello.is_empty();
        let opened_time = web_time::UNIX_EPOCH
            .elapsed()
            .expect("system time")
            .as_secs();
        let mut sent_buf = client_hello;
        let mut recv_buf = Vec::new();

        info!("starting Proxy-TLS");

        let mut proxy_id = PROXY_STREAM_PREFIX.to_vec();
        proxy_id.extend_from_slice(id.as_bytes());

        let prover_socket = self.mux_handle.new_stream(&proxy_id)?;

        let (prover_read, mut prover_write) = prover_socket.split();
        let (server_read, mut server_write) = server_socket.split();

        let mut prover_reader = InspectReader::new(
            prover_read,
            &mut sent_buf,
            crate::proxy::PROXY_MAX_SENT_BYTES,
        );
        let mut server_reader = InspectReader::new(
            server_read,
            &mut recv_buf,
            crate::proxy::PROXY_MAX_RECV_BYTES,
        );

        let relay = async {
            futures::future::try_join(
                async {
                    futures::io::copy(&mut prover_reader, &mut server_write).await?;
                    server_write.close().await
                },
                async {
                    futures::io::copy(&mut server_reader, &mut prover_write).await?;
                    prover_write.close().await
                },
            )
            .await
            .map_err(|e| {
                Error::io()
                    .with_msg("proxy traffic forwarding failed")
                    .with_source(e)
            })?;
            Ok::<_, Error>(())
        };
        let _ = pipeline_tls;
        relay.await?;
        info!("proxying TLS traffic finished");

        // A prover that closes without sending anything must not panic the
        // notary (zkfetch P6).
        let conn_time = prover_reader
            .first_read()
            .or_else(|| opened.then_some(opened_time))
            .ok_or_else(|| Error::io().with_msg("prover sent no TLS traffic"))?;

        crate::proxy::validate_sni(&sent_buf, &server_name)?;

        // TLS 1.3 checks the Finished messages while finalizing (zkfetch P4).
        let (mut ctx, mut vm, output, finished_checks) = match *verifier {
            crate::proxy::AnyProxyVerifier::V12(verifier) => {
                let (ctx, vm, output, cf, sf) =
                    verifier.finalize(&sent_buf, &recv_buf, conn_time).await?;
                (ctx, vm, output, Some((cf, sf)))
            }
            crate::proxy::AnyProxyVerifier::V13(verifier) => {
                let (ctx, vm, output) = verifier.finalize(&sent_buf, &recv_buf, conn_time).await?;
                (ctx, vm, output, None)
            }
        };

        let deferred_schedule = output.deferred_schedule;
        let keys = output.keys;
        let tls_transcript = output.tls_transcript;

        // Prepare for the prover to prove tag verification of the received
        // records.
        let tag_proof = verify_tags(
            &mut vm,
            (keys.server_write_key, keys.server_write_iv),
            keys.server_write_mac_key,
            tls_transcript.version(),
            tls_transcript.recv().to_vec(),
        )
        .map_err(|e| {
            Error::internal()
                .with_msg("tag verification setup failed")
                .with_source(e)
        })?;

        let deferred_tags = if deferred_schedule.is_some() {
            Some(tag_proof)
        } else {
            vm.execute_all(&mut ctx).await.map_err(|e| {
                Error::internal()
                    .with_msg("tag verification zk execution failed")
                    .with_source(e)
            })?;

            // Verify the tags.
            // After the verification, the entire TLS trancript becomes
            // authenticated from the verifier's perspective.
            tag_proof.verify().map_err(|e| {
                Error::internal()
                    .with_msg("tag verification failed")
                    .with_source(e)
            })?;
            debug!("verified tags successfully");

            None
        };

        // Verify finished records
        if let Some((cf_vd_check, sf_vd_check)) = finished_checks {
            cf_vd_check.check(&mut vm)?;
            sf_vd_check.check(&mut vm)?;
            debug!("verified finished records successfully");
        }

        Ok(Verifier {
            config: self.config,
            span: self.span,
            ctx: Some(ctx),
            mux_handle: self.mux_handle,
            low_latency: self.low_latency,
            state: state::Committed {
                deferred_schedule,
                deferred_tags,
                vm,
                keys,
                tls_transcript,
            },
        })
    }
}

impl Verifier<state::Committed> {
    /// Returns the TLS transcript.
    pub fn tls_transcript(&self) -> &TlsTranscript {
        &self.state.tls_transcript
    }

    /// Begins verification of statements from the prover.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn verify(mut self) -> Result<Verifier<state::Verify>> {
        let mut ctx = self
            .ctx
            .take()
            .ok_or_else(|| Error::internal().with_msg("verification context was dropped"))?;
        let state::Committed {
            mut vm,
            keys,
            tls_transcript,
            deferred_schedule,
            deferred_tags,
        } = self.state;

        let msg: ProveRequestMsg = ctx.io_mut().expect_next().await.map_err(|e| {
            Error::io()
                .with_msg("verification failed to receive prove request")
                .with_source(e)
        })?;

        if self.low_latency {
            vm.bind_statement(
                &bincode::serialize(&msg).map_err(|e| Error::internal().with_source(e))?,
            );
        }
        let ProveRequestMsg {
            request,
            handshake,
            transcript,
        } = msg;

        Ok(Verifier {
            config: self.config,
            span: self.span,
            ctx: Some(ctx),
            mux_handle: self.mux_handle,
            low_latency: self.low_latency,
            state: state::Verify {
                vm,
                keys,
                tls_transcript,
                deferred_schedule,
                deferred_tags,
                request,
                handshake,
                transcript,
            },
        })
    }

    /// Closes the connection with the prover.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn close(self) -> Result<()> {
        Ok(())
    }
}

impl Verifier<state::Verify> {
    /// Returns the proving request.
    pub fn request(&self) -> &ProveRequest {
        &self.state.request
    }

    /// Accepts the proving request.
    pub async fn accept(mut self) -> Result<(VerifierOutput, Verifier<state::Committed>)> {
        let mut ctx = self
            .ctx
            .take()
            .ok_or_else(|| Error::internal().with_msg("verification context was dropped"))?;
        let state::Verify {
            mut vm,
            keys,
            tls_transcript,
            deferred_schedule,
            deferred_tags,
            request,
            handshake,
            transcript,
        } = self.state;

        if !self.low_latency {
            ctx.io_mut().send(Response::ok()).await.map_err(|e| {
                Error::io()
                    .with_msg("verification failed to send acceptance")
                    .with_source(e)
            })?;
        }

        let cert_verifier = ServerCertVerifier::new(self.config.root_store()).map_err(|e| {
            Error::config()
                .with_msg("failed to create certificate verifier")
                .with_source(e)
        })?;

        let output = verify::verify(
            &mut ctx,
            &mut vm,
            &keys,
            &cert_verifier,
            &tls_transcript,
            request,
            handshake,
            transcript,
        )
        .await?;
        if let Some(schedule) = deferred_schedule {
            schedule.verify()?;
        }
        if let Some(tags) = deferred_tags {
            tags.verify().map_err(|e| {
                Error::internal()
                    .with_msg("tag verification failed")
                    .with_source(e)
            })?;
        }

        Ok((
            output,
            Verifier {
                config: self.config,
                span: self.span,
                ctx: Some(ctx),
                mux_handle: self.mux_handle,
                low_latency: self.low_latency,
                state: state::Committed {
                    vm,
                    keys,
                    tls_transcript,
                    deferred_schedule: None,
                    deferred_tags: None,
                },
            },
        ))
    }

    /// Rejects the proving request.
    pub async fn reject(mut self, msg: Option<&str>) -> Result<Verifier<state::Committed>> {
        let mut ctx = self
            .ctx
            .take()
            .ok_or_else(|| Error::internal().with_msg("verification context was dropped"))?;
        let state::Verify {
            vm,
            keys,
            tls_transcript,
            deferred_schedule,
            deferred_tags,
            ..
        } = self.state;

        ctx.io_mut().send(Response::err(msg)).await.map_err(|e| {
            Error::io()
                .with_msg("verification failed to send rejection")
                .with_source(e)
        })?;

        Ok(Verifier {
            config: self.config,
            span: self.span,
            ctx: Some(ctx),
            mux_handle: self.mux_handle,
            low_latency: self.low_latency,
            state: state::Committed {
                vm,
                keys,
                tls_transcript,
                deferred_schedule,
                deferred_tags,
            },
        })
    }
}
