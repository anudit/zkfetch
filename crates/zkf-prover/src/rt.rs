//! Runtime glue that lets the prover run natively (tokio) and in wasm
//! (browser pages, web workers, extension service workers).

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{AsyncRead, AsyncWrite, FutureExt, future::RemoteHandle};

/// Spawns `fut` and returns a handle to its output. Dropping the handle
/// cancels the task, like tokio-util's `AbortOnDropHandle`.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn spawn<F>(fut: F) -> RemoteHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send,
{
    let (task, handle) = fut.remote_handle();
    tokio::spawn(task);
    handle
}

/// Spawns `fut` on the browser event loop. wasm has a single thread, so the
/// future need not be `Send`.
#[cfg(target_arch = "wasm32")]
pub(crate) fn spawn<F>(fut: F) -> RemoteHandle<F::Output>
where
    F: Future + 'static,
{
    let (task, handle) = fut.remote_handle();
    wasm_bindgen_futures::spawn_local(task);
    handle
}

/// Adapts a `futures` byte stream to hyper's I/O traits without tokio.
pub(crate) struct HyperIo<T>(pub(crate) T);

impl<T: AsyncRead + Unpin> hyper::rt::Read for HyperIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        // SAFETY: the bytes are initialized below before they are advanced.
        let dst = unsafe { buf.as_mut() };
        let dst = unsafe { &mut *(dst as *mut [std::mem::MaybeUninit<u8>] as *mut [u8]) };
        dst.fill(0);
        let n = futures::ready!(Pin::new(&mut self.0).poll_read(cx, dst))?;
        unsafe { buf.advance(n) };
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncWrite + Unpin> hyper::rt::Write for HyperIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_close(cx)
    }
}

/// Marks a browser stream `Send` for tlsn's MPC client bound. Sound because
/// this wasm build has no threads: the value never leaves the one thread.
#[cfg(target_arch = "wasm32")]
pub(crate) struct AssertSend<T>(pub(crate) T);

#[cfg(target_arch = "wasm32")]
unsafe impl<T> Send for AssertSend<T> {}

#[cfg(target_arch = "wasm32")]
impl<T: AsyncRead + Unpin> AsyncRead for AssertSend<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

#[cfg(target_arch = "wasm32")]
impl<T: AsyncWrite + Unpin> AsyncWrite for AssertSend<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_close(cx)
    }
}
