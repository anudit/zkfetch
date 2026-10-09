use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
};

use futures::{AsyncRead, AsyncWrite};
use mpz_common::{Executor, LocalRunner, io::Io, mux::Mux};
use tlsn_core::config::{prover::ProverConfig, verifier::VerifierConfig};
use tlsn_mux::{Connection, Handle};

use crate::{
    Error, Result,
    prover::{Prover, state as prover_state},
    verifier::{Verifier, state as verifier_state},
};

/// A TLSNotary session over a communication channel.
///
/// Wraps an async IO stream and provides multiplexing for the protocol. Use
/// [`new_prover`](Self::new_prover) or [`new_verifier`](Self::new_verifier) to
/// create protocol participants.
///
/// The session must be polled continuously (either directly or via
/// [`split`](Self::split)) to drive the underlying connection. After the
/// session closes, the underlying IO can be reclaimed with
/// [`try_take`](Self::try_take).
///
/// **Important**: The order in which provers and verifiers are created must
/// match on both sides. For example, if the prover side calls `new_prover`
/// then `new_verifier`, the verifier side must call `new_verifier` then
/// `new_prover`.
#[must_use = "session must be polled continuously to make progress, including during closing."]
pub struct Session<Io> {
    conn: Option<Connection<Io>>,
    executor: Executor,
    handle: Handle,
}

impl<Io> Session<Io>
where
    Io: AsyncRead + AsyncWrite + Unpin,
{
    /// Creates a new session.
    pub fn new(io: Io) -> Self {
        Self::with_close_sync(io, true)
    }

    /// Creates a session whose final reply is delivered inside the multiplexer.
    /// No underlying IO is reused, so closing needs no peer acknowledgement.
    pub fn pipelined(io: Io) -> Self {
        Self::with_close_sync(io, false)
    }

    fn with_close_sync(io: Io, close_sync: bool) -> Self {
        let mut mux_config = tlsn_mux::Config::default();

        mux_config.set_keep_alive(true);
        mux_config.set_close_sync(close_sync);
        if !close_sync {
            mux_config.set_initial_stream_credit(2 * 1024 * 1024);
        }

        let conn = tlsn_mux::Connection::new(io, mux_config);
        let handle = conn.handle().expect("handle should be available");
        let executor = build_executor(MuxHandle {
            handle: handle.clone(),
        });

        Self {
            conn: Some(conn),
            executor,
            handle,
        }
    }

    /// Creates a new prover.
    pub fn new_prover(
        &mut self,
        config: ProverConfig,
    ) -> Result<Prover<prover_state::Initialized>> {
        let ctx = self.executor.new_context().map_err(|e| {
            Error::internal()
                .with_msg("failed to create new prover")
                .with_source(e)
        })?;

        Ok(Prover::new(ctx, self.handle.clone(), config))
    }

    /// Creates a new verifier.
    pub fn new_verifier(
        &mut self,
        config: VerifierConfig,
    ) -> Result<Verifier<verifier_state::Initialized>> {
        let ctx = self.executor.new_context().map_err(|e| {
            Error::internal()
                .with_msg("failed to create new verifier")
                .with_source(e)
        })?;

        Ok(Verifier::new(ctx, self.handle.clone(), config))
    }

    /// Returns `true` if the session is closed.
    pub fn is_closed(&self) -> bool {
        self.conn
            .as_ref()
            .map(|mux| mux.is_complete())
            .unwrap_or_default()
    }

    /// Closes the session.
    ///
    /// This will cause the session to begin closing. Session must continue to
    /// be polled until completion.
    pub fn close(&mut self) {
        if let Some(conn) = self.conn.as_mut() {
            conn.close()
        }
    }

    /// Attempts to take the IO, returning an error if it is not available.
    pub fn try_take(&mut self) -> Result<Io> {
        let conn = self.conn.take().ok_or_else(|| {
            Error::io().with_msg("failed to take the session io, it was already taken")
        })?;

        match conn.try_into_io() {
            Err(conn) => {
                self.conn = Some(conn);
                Err(Error::io()
                    .with_msg("failed to take the session io, session was not completed yet"))
            }
            Ok(conn) => Ok(conn),
        }
    }

    /// Polls the session.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        run_local(&self.executor.local_runner(), cx);
        self.conn
            .as_mut()
            .ok_or_else(|| {
                Error::io()
                    .with_msg("failed to poll the session connection because it has been taken")
            })?
            .poll(cx)
            .map_err(|e| {
                Error::io()
                    .with_msg("error occurred while polling the session connection")
                    .with_source(e)
            })
    }

    /// Splits the session into a driver and handle.
    ///
    /// The driver must be polled to make progress. The handle is used
    /// for creating provers/verifiers and closing the session.
    pub fn split(self) -> (SessionDriver<Io>, SessionHandle) {
        let should_close = Arc::new(AtomicBool::new(false));
        let waker = Arc::new(Mutex::new(None::<Waker>));

        (
            SessionDriver {
                local: self.executor.local_runner(),
                conn: self.conn,
                should_close: should_close.clone(),
                waker: waker.clone(),
            },
            SessionHandle {
                executor: self.executor,
                should_close,
                waker,
                handle: self.handle,
            },
        )
    }
}

impl<Io> Future for Session<Io>
where
    Io: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Session::poll(&mut (*self), cx)
    }
}

/// The polling half of a split session.
///
/// Must be polled continuously to drive the session. Returns the underlying
/// IO when the session closes.
#[must_use = "driver must be polled to make progress"]
pub struct SessionDriver<Io> {
    local: LocalRunner,
    conn: Option<Connection<Io>>,
    should_close: Arc<AtomicBool>,
    waker: Arc<Mutex<Option<Waker>>>,
}

impl<Io> SessionDriver<Io>
where
    Io: AsyncRead + AsyncWrite + Unpin,
{
    /// Polls the driver.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Io>> {
        // Store the waker so the handle can wake us when close() is called.
        {
            let mut waker_guard = self.waker.lock().unwrap();
            *waker_guard = Some(cx.waker().clone());
        }

        let conn = self
            .conn
            .as_mut()
            .ok_or_else(|| Error::io().with_msg("session driver already completed"))?;

        if self.should_close.load(Ordering::Acquire) {
            conn.close();
        }

        run_local(&self.local, cx);

        match conn.poll(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => {
                return Poll::Ready(Err(Error::io()
                    .with_msg("error polling session connection")
                    .with_source(e)));
            }
            Poll::Pending => return Poll::Pending,
        }

        let conn = self.conn.take().unwrap();
        Poll::Ready(
            conn.try_into_io()
                .map_err(|_| Error::io().with_msg("failed to take session io")),
        )
    }
}

impl<Io> Future for SessionDriver<Io>
where
    Io: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<Io>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        SessionDriver::poll(&mut *self, cx)
    }
}

/// The control half of a split session.
///
/// Used to create provers/verifiers and control the session lifecycle.
pub struct SessionHandle {
    executor: Executor,
    should_close: Arc<AtomicBool>,
    waker: Arc<Mutex<Option<Waker>>>,
    handle: Handle,
}

impl SessionHandle {
    /// Control a bounded noninteractive application proof flight.
    pub fn proof_batch_control(&self) -> tlsn_mux::Handle {
        self.handle.clone()
    }

    /// Opens an application stream within the running authenticated session.
    /// The driver must be polled while reading or writing this stream.
    pub fn application_stream(&self, id: &[u8]) -> Result<tlsn_mux::Stream> {
        self.handle
            .new_stream(id)
            .map_err(|e| Error::io().with_source(e))
    }

    /// Creates a new prover.
    pub fn new_prover(
        &mut self,
        config: ProverConfig,
    ) -> Result<Prover<prover_state::Initialized>> {
        let ctx = self.executor.new_context().map_err(|e| {
            Error::internal()
                .with_msg("failed to create new prover")
                .with_source(e)
        })?;

        Ok(Prover::new(ctx, self.handle.clone(), config))
    }

    /// Creates a new verifier.
    pub fn new_verifier(
        &mut self,
        config: VerifierConfig,
    ) -> Result<Verifier<verifier_state::Initialized>> {
        let ctx = self.executor.new_context().map_err(|e| {
            Error::internal()
                .with_msg("failed to create new verifier")
                .with_source(e)
        })?;

        Ok(Verifier::new(ctx, self.handle.clone(), config))
    }

    /// Signals the session to close.
    ///
    /// The driver must continue to be polled until it completes.
    pub fn close(&self) {
        self.should_close.store(true, Ordering::Release);
        if let Some(waker) = self.waker.lock().unwrap().take() {
            waker.wake();
        }
    }
}

/// Multiplexer controller providing streams.
struct MuxHandle {
    handle: Handle,
}

impl std::fmt::Debug for MuxHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MuxHandle").finish_non_exhaustive()
    }
}

impl Mux for MuxHandle {
    fn open(&self, id: &[u8]) -> Result<Io, std::io::Error> {
        let stream = self.handle.new_stream(id).map_err(std::io::Error::other)?;
        let io = Io::from_io(stream);

        Ok(io)
    }
}

/// Builds a work-stealing executor with the given muxer.
/// Tasks per poll before yielding to I/O on the single-threaded executor.
#[cfg(all(target_arch = "wasm32", not(feature = "web")))]
const LOCAL_BUDGET: usize = 64;

/// Runs MPC tasks on the polling thread when the platform has no threads
/// (wasm32 without `web`, e.g. a Cloudflare Worker). No-op elsewhere
/// (zkfetch patch).
#[allow(unused_variables)]
fn run_local(local: &LocalRunner, cx: &mut Context<'_>) {
    #[cfg(all(target_arch = "wasm32", not(feature = "web")))]
    let _ = local.poll_run(cx, LOCAL_BUDGET);
}

fn build_executor(mux: MuxHandle) -> Executor {
    #[cfg(all(feature = "web", target_arch = "wasm32"))]
    let cores = web_spawn::available_parallelism().map(|n| n.get());

    #[cfg(not(target_arch = "wasm32"))]
    let cores = std::thread::available_parallelism().map(|n| n.get());

    // No threads: tasks run on the driver's thread via `run_local`.
    #[cfg(all(target_arch = "wasm32", not(feature = "web")))]
    let cores: std::io::Result<usize> = Ok(0);

    let builder = Executor::builder().num_threads(cores.unwrap_or(8));

    #[cfg(all(feature = "web", target_arch = "wasm32"))]
    let builder = builder.spawn(|f| {
        let _ = web_spawn::spawn(f);
        Ok(())
    });

    builder.build(mux)
}
