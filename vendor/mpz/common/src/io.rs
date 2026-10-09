//! I/O types.

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use futures::{AsyncRead, AsyncWrite};
use pin_project_lite::pin_project;
use serio::{Framed, Sink, Stream, channel::MemoryDuplex, codec::Bincode};
use tokio_util::{
    codec::{Framed as TokioFramed, LengthDelimitedCodec},
    compat::{Compat, FuturesAsyncReadCompatExt as _},
};

trait Duplex:
    futures::Stream<Item = Result<BytesMut, std::io::Error>>
    + futures::Sink<Bytes, Error = std::io::Error>
{
    /// Sets a new maximum frame length.
    ///
    /// # Arguments
    ///
    /// * `frame_limit` - The new maximum frame length in bytes.
    fn set_frame_limit(&mut self, frame_limit: usize);

    /// Returns the current frame limit.
    fn frame_limit(&self) -> usize;
}

impl<T> Duplex for TokioFramed<Compat<T>, LengthDelimitedCodec>
where
    T: AsyncRead + AsyncWrite,
{
    fn set_frame_limit(&mut self, frame_limit: usize) {
        self.codec_mut().set_max_frame_length(frame_limit);
    }

    fn frame_limit(&self) -> usize {
        self.codec().max_frame_length()
    }
}

pin_project! {
    /// Wrapper around [`Io`] to temporarily set a frame limit.
    pub struct WithLimit<'a> {
        old_limit: Option<usize>,
        #[pin]
        io: &'a mut Io,
    }

    impl<'a> PinnedDrop for WithLimit<'a> {
        fn drop(mut this: Pin<&mut Self>) {
            if let (Some(old_limit), Inner::Transport { framed }) = (this.old_limit, &mut this.io.inner)
            {
                framed.inner_mut().set_frame_limit(old_limit);
            }
        }
    }
}

impl WithLimit<'_> {
    #[cfg(test)]
    fn frame_limit(&self) -> Option<usize> {
        self.io.frame_limit()
    }
}

impl Stream for WithLimit<'_> {
    type Error = std::io::Error;

    fn poll_next<Item: serio::Deserialize>(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Item, Self::Error>>> {
        self.project().io.poll_next(cx)
    }
}

impl Sink for WithLimit<'_> {
    type Error = std::io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().io.poll_ready(cx)
    }

    fn start_send<Item: serio::Serialize>(
        self: Pin<&mut Self>,
        item: Item,
    ) -> Result<(), Self::Error> {
        self.project().io.start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().io.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().io.poll_close(cx)
    }
}

pin_project! {
    /// I/O channel.
    #[derive(Debug)]
    pub struct Io {
        #[pin]
        inner: Inner,
        stats: std::sync::Arc<IoCounters>,
    }
}

impl Io {
    #[doc(hidden)]
    pub fn from_io<Io: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static>(io: Io) -> Self {
        let stats = std::sync::Arc::new(IoCounters::default());
        let io = CountedIo {
            inner: io,
            stats: stats.clone(),
        };
        let framed = Box::new(LengthDelimitedCodec::builder().new_framed(io.compat()));

        Self {
            inner: Inner::Transport {
                framed: Framed::new(framed, Bincode),
            },
            stats,
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn from_io_with_limit<Io: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static>(
        io: Io,
        max_frame_length: usize,
    ) -> Self {
        let stats = std::sync::Arc::new(IoCounters::default());
        let io = CountedIo {
            inner: io,
            stats: stats.clone(),
        };
        let framed = Box::new(
            LengthDelimitedCodec::builder()
                .max_frame_length(max_frame_length)
                .new_framed(io.compat()),
        );

        Self {
            inner: Inner::Transport {
                framed: Framed::new(framed, Bincode),
            },
            stats,
        }
    }

    /// Returns the maximum message size that can be received.
    pub fn limit(&self) -> usize {
        match &self.inner {
            Inner::Transport { framed } => framed.inner().frame_limit(),
            Inner::Memory { channel: _ } => usize::MAX,
        }
    }

    /// Adjusts the frame limit temporarily and returns a [`WithLimit`].
    ///
    /// # Arguments
    ///
    /// * `frame_limit` - The new maximum frame length in bytes.
    pub fn with_limit(&mut self, frame_limit: usize) -> WithLimit<'_> {
        let old_limit = match &mut self.inner {
            Inner::Transport { framed } => {
                let old_limit = framed.inner().frame_limit();
                framed.inner_mut().set_frame_limit(frame_limit);
                Some(old_limit)
            }
            Inner::Memory { channel: _ } => None,
        };

        WithLimit {
            old_limit,
            io: self,
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn from_channel(duplex: MemoryDuplex) -> Self {
        Self {
            inner: Inner::Memory { channel: duplex },
            stats: Default::default(),
        }
    }

    #[cfg(test)]
    fn frame_limit(&self) -> Option<usize> {
        match &self.inner {
            Inner::Transport { framed } => Some(framed.inner().frame_limit()),
            Inner::Memory { channel: _ } => None,
        }
    }
}

pin_project! {
    #[project = InnerProj]
    enum Inner {
        /// I/O over a framed bytes transport.
        Transport { #[pin] framed: Framed<Box<dyn Duplex + Send + Sync + Unpin>, Bincode> },
        /// I/O over a memory channel.
        Memory { #[pin] channel: MemoryDuplex }
    }
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport { .. } => f.debug_struct("Transport").finish_non_exhaustive(),
            Self::Memory { .. } => f.debug_struct("Memory").finish_non_exhaustive(),
        }
    }
}

impl Sink for Io {
    type Error = std::io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.project().inner.project() {
            InnerProj::Transport { framed } => framed.poll_ready(cx),
            InnerProj::Memory { channel } => channel.poll_ready(cx),
        }
    }

    fn start_send<Item: serio::Serialize>(
        self: Pin<&mut Self>,
        item: Item,
    ) -> Result<(), Self::Error> {
        match self.project().inner.project() {
            InnerProj::Transport { framed } => framed.start_send(item),
            InnerProj::Memory { channel } => channel.start_send(item),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.project().inner.project() {
            InnerProj::Transport { framed } => framed.poll_flush(cx),
            InnerProj::Memory { channel } => channel.poll_flush(cx),
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.project().inner.project() {
            InnerProj::Transport { framed } => framed.poll_close(cx),
            InnerProj::Memory { channel } => channel.poll_close(cx),
        }
    }
}

impl Stream for Io {
    type Error = std::io::Error;

    fn poll_next<Item: serio::Deserialize>(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Item, Self::Error>>> {
        match self.project().inner.project() {
            InnerProj::Transport { framed } => framed.poll_next(cx),
            InnerProj::Memory { channel } => channel.poll_next(cx),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match &self.inner {
            Inner::Transport { framed } => framed.size_hint(),
            Inner::Memory { channel } => channel.size_hint(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Io;
    use tokio_util::compat::TokioAsyncReadCompatExt;

    #[test]
    fn test_frame_limit() {
        let (a, b) = tokio::io::duplex(1024);

        let mut a = Io::from_io(a.compat());
        let mut b = Io::from_io(b.compat());

        let old_limit = a.frame_limit().unwrap();
        let new_limit = 2 * old_limit;

        {
            let a = a.with_limit(new_limit);
            let b = b.with_limit(new_limit);

            assert_eq!(a.frame_limit().unwrap(), new_limit);
            assert_eq!(b.frame_limit().unwrap(), new_limit);
        }

        assert_eq!(a.frame_limit().unwrap(), old_limit);
        assert_eq!(b.frame_limit().unwrap(), old_limit);
    }
}

/// Counters for serialized protocol traffic, including length framing.
#[derive(Debug, Default)]
struct IoCounters {
    sent: std::sync::atomic::AtomicU64,
    received: std::sync::atomic::AtomicU64,
    changes: std::sync::atomic::AtomicU64,
    direction: std::sync::atomic::AtomicU8,
}
impl IoCounters {
    fn record(&self, sent: bool, n: usize) {
        use std::sync::atomic::Ordering::Relaxed;
        if n == 0 {
            return;
        }
        if sent { &self.sent } else { &self.received }.fetch_add(n as u64, Relaxed);
        let dir = if sent { 1 } else { 2 };
        let previous = self.direction.swap(dir, Relaxed);
        if previous != 0 && previous != dir {
            self.changes.fetch_add(1, Relaxed);
        }
    }
    fn snapshot(&self) -> [u64; 3] {
        use std::sync::atomic::Ordering::Relaxed;
        [
            self.sent.load(Relaxed),
            self.received.load(Relaxed),
            self.changes.load(Relaxed),
        ]
    }
}
struct CountedIo<S> {
    inner: S,
    stats: std::sync::Arc<IoCounters>,
}
impl<S: AsyncRead + Unpin> AsyncRead for CountedIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(n)) = result {
            self.stats.record(false, n);
        }
        result
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for CountedIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = result {
            self.stats.record(true, n);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}
/// Measures an OT setup sub-step. Nested spans include their children's bytes.
/// Direction changes describe this logical stream, not physical network RTTs.
pub struct SetupStep {
    stats: std::sync::Arc<IoCounters>,
    before: [u64; 3],
    started: web_time::Instant,
    step: &'static str,
}
impl SetupStep {
    /// Starts measuring a protocol sub-step without borrowing the I/O.
    pub fn new(io: &Io, step: &'static str) -> Self {
        Self {
            stats: io.stats.clone(),
            before: io.stats.snapshot(),
            started: web_time::Instant::now(),
            step,
        }
    }
}
impl Drop for SetupStep {
    fn drop(&mut self) {
        let after = self.stats.snapshot();
        tracing::info!(target: "zkfetch::setup", step = self.step,
            elapsed_ms = self.started.elapsed().as_secs_f64() * 1000.0,
            sent_bytes = after[0] - self.before[0], received_bytes = after[1] - self.before[1],
            direction_changes = after[2] - self.before[2], "setup sub-step");
    }
}
