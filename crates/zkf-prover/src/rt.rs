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
        for byte in dst.iter_mut() {
            byte.write(0);
        }
        // SAFETY: every MaybeUninit element was initialized before creating u8 references.
        let dst = unsafe { &mut *(dst as *mut [std::mem::MaybeUninit<u8>] as *mut [u8]) };
        let n = futures::ready!(Pin::new(&mut self.0).poll_read(cx, dst))?;
        if n > dst.len() {
            return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "reader returned an invalid byte count")));
        }
        // SAFETY: the returned count is within the initialized destination.
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

/// Keeps browser handles on their originating worker, including atomic wasm builds.
/// Moving the wrapper is allowed, but another thread cannot access or destroy T.
#[cfg(target_arch = "wasm32")]
pub(crate) struct AssertSend<T> {
    inner: std::mem::ManuallyDrop<T>,
    owner: std::thread::ThreadId,
}

#[cfg(target_arch = "wasm32")]
impl<T> AssertSend<T> {
    pub(crate) fn new(inner: T) -> Self {
        Self { inner: std::mem::ManuallyDrop::new(inner), owner: std::thread::current().id() }
    }
    fn local(&mut self) -> std::io::Result<&mut T> {
        if self.owner != std::thread::current().id() {
            return Err(std::io::Error::other("browser stream polled outside its originating worker"));
        }
        Ok(&mut self.inner)
    }
}

#[cfg(target_arch = "wasm32")]
impl<T> Drop for AssertSend<T> {
    fn drop(&mut self) {
        if self.owner == std::thread::current().id() {
            // SAFETY: T is destroyed only on the worker that created it.
            unsafe { std::mem::ManuallyDrop::drop(&mut self.inner); }
        }
        // Misuse on another worker leaks the handle instead of touching that
        // worker's unrelated JS handle table. Normal spawn_local teardown wipes it.
    }
}

#[cfg(target_arch = "wasm32")]
// SAFETY: all access and destruction of the !Send inner value is worker-bound.
unsafe impl<T> Send for AssertSend<T> {}

#[cfg(target_arch = "wasm32")]
impl<T: AsyncRead + Unpin> AsyncRead for AssertSend<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(self.local()?).poll_read(cx, buf)
    }
}

#[cfg(target_arch = "wasm32")]
impl<T: AsyncWrite + Unpin> AsyncWrite for AssertSend<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(self.local()?).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(self.local()?).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(self.local()?).poll_close(cx)
    }
}
