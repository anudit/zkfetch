use crate::{
    Config, Result,
    error::ConnectionError,
    frame::{
        self, Frame,
        header::{self, CONNECTION_ID, Data, GoAway, Header, Ping, StreamId, Tag, WindowUpdate},
    },
    tagged_stream::TaggedStream,
};
use futures::{
    channel::{mpsc, oneshot},
    prelude::*,
    stream::{Fuse, SelectAll},
};
use nohash_hasher::IntMap;
use parking_lot::Mutex;
use std::{
    collections::VecDeque,
    fmt,
    sync::Arc,
    task::{Context, Poll, Waker},
};

type PendingFrames = VecDeque<Frame<()>>;

use super::{
    Id, UserId,
    cleanup::Cleanup,
    closing::Closing,
    rtt,
    stream::{self, State, Stream},
};

/// Shared state for stream management.
///
/// This struct holds state that can be accessed by both the Connection's
/// poll loop and Handle for concurrent stream creation.
pub(crate) struct StreamRegistry {
    id: Id,
    streams: IntMap<StreamId, Arc<Mutex<stream::Shared>>>,
    new_receiver_tx: mpsc::UnboundedSender<TaggedStream<StreamId, mpsc::Receiver<StreamCommand>>>,
    waker: Option<Waker>,
    batch_requested: bool,
    release: Option<oneshot::Sender<()>>,
    config: Arc<Config>,
    rtt: rtt::Rtt,
    accumulated_max_stream_windows: Arc<Mutex<usize>>,
}

impl StreamRegistry {
    fn new(
        id: Id,
        config: Arc<Config>,
        rtt: rtt::Rtt,
        accumulated_max_stream_windows: Arc<Mutex<usize>>,
        new_receiver_tx: mpsc::UnboundedSender<
            TaggedStream<StreamId, mpsc::Receiver<StreamCommand>>,
        >,
    ) -> Self {
        Self {
            id,
            streams: IntMap::default(),
            new_receiver_tx,
            waker: None,
            batch_requested: false,
            release: None,
            config,
            rtt,
            accumulated_max_stream_windows,
        }
    }

    fn new_stream(&mut self, user_id: &[u8]) -> Result<Stream> {
        let user_id = UserId::new(user_id)?;
        let stream_id = StreamId::new(user_id.as_bytes());

        if self.streams.len() >= self.config.max_num_streams {
            log::error!("{}: maximum number of streams reached", self.id);
            return Err(ConnectionError::TooManyStreams);
        }

        // Check if stream already exists (created implicitly by remote)
        if let Some(existing) = self.streams.get(&stream_id) {
            log::trace!("{}/{}: merging with existing stream", self.id, stream_id);
            let stream = self.make_stream_with_shared(stream_id, user_id, existing.clone());
            return Ok(stream);
        }

        let stream = self.make_stream(stream_id, user_id);
        self.streams.insert(stream_id, stream.clone_shared());

        log::debug!("{}: new stream {}", self.id, stream);

        if let Some(waker) = self.waker.take() {
            waker.wake();
        }

        Ok(stream)
    }

    /// Create a Stream using existing Shared state (for merging with implicit
    /// stream).
    fn make_stream_with_shared(
        &mut self,
        id: StreamId,
        user_id: UserId,
        shared: Arc<Mutex<stream::Shared>>,
    ) -> Stream {
        let (sender, receiver) = mpsc::channel(10);
        let _ = self
            .new_receiver_tx
            .unbounded_send(TaggedStream::new(id, receiver));

        if let Some(waker) = self.waker.take() {
            waker.wake();
        }

        Stream::with_shared(id, user_id, self.id, self.config.clone(), sender, shared)
    }

    fn make_stream(&mut self, id: StreamId, user_id: UserId) -> Stream {
        let (sender, receiver) = mpsc::channel(10);
        let _ = self
            .new_receiver_tx
            .unbounded_send(TaggedStream::new(id, receiver));

        Stream::new(
            id,
            user_id,
            self.id,
            self.config.clone(),
            sender,
            self.rtt.clone(),
            self.accumulated_max_stream_windows.clone(),
        )
    }

    fn make_implicit_stream_shared(&mut self) -> Arc<Mutex<stream::Shared>> {
        Arc::new(Mutex::new(stream::Shared::new(
            State::Open,
            self.config.initial_stream_credit,
            self.config.initial_stream_credit,
            self.accumulated_max_stream_windows.clone(),
            self.rtt.clone(),
            self.config.clone(),
        )))
    }
}

/// A handle for creating streams concurrently.
///
/// This type can be cloned and used from multiple tasks while the
/// Connection is being polled.
#[derive(Clone)]
pub struct Handle {
    registry: Arc<Mutex<StreamRegistry>>,
}

impl Handle {
    /// Begin collecting a bounded, noninteractive proof flight.
    pub fn begin_batch(&self) {
        let mut registry = self.registry.lock();
        assert!(!registry.batch_requested && registry.release.is_none());
        registry.batch_requested = true;
        if let Some(waker) = registry.waker.take() {
            waker.wake();
        }
    }
    /// Drain all queued streams and transmit the collected flight before returning.
    pub async fn end_batch(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        {
            let mut registry = self.registry.lock();
            assert!(registry.batch_requested && registry.release.is_none());
            registry.release = Some(tx);
            if let Some(waker) = registry.waker.take() {
                waker.wake();
            }
        }
        rx.await.map_err(|_| ConnectionError::Closed)
    }

    /// Create a new stream with the given user ID.
    ///
    /// The stream ID is computed from the user ID using BLAKE3.
    pub fn new_stream(&self, user_id: &[u8]) -> Result<Stream> {
        self.registry.lock().new_stream(user_id)
    }
}

/// `Stream` to `Connection` commands.
#[derive(Debug)]
pub(crate) enum StreamCommand {
    /// A new frame should be sent to the remote.
    SendFrame(Frame<()>),
    /// Close a stream.
    CloseStream { stream_id: StreamId },
}

/// Possible actions as a result of incoming frame handling.
#[derive(Debug)]
pub(crate) enum Action {
    /// Nothing to be done.
    None,
    /// A ping should be answered.
    Ping(Frame<Ping>),
    /// The connection should be terminated.
    Terminate(Frame<GoAway>),
}

/// The active state of [`super::Connection`].
pub(crate) struct Active<T> {
    id: Id,
    pub(super) config: Arc<Config>,
    socket: Fuse<frame::Io<T>>,

    registry: Arc<Mutex<StreamRegistry>>,
    stream_receivers: SelectAll<TaggedStream<StreamId, mpsc::Receiver<StreamCommand>>>,
    new_receiver_rx: mpsc::UnboundedReceiver<TaggedStream<StreamId, mpsc::Receiver<StreamCommand>>>,
    no_streams_waker: Option<Waker>,

    pending_read_frame: Option<Frame<()>>,
    pending_write_frame: Option<Frame<()>>,
    batching: bool,
    release_ack: Option<oneshot::Sender<()>>,
}

impl<T> fmt::Debug for Active<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Connection")
            .field("id", &self.id)
            .field("streams", &self.registry.lock().streams.len())
            .finish()
    }
}

impl<T> fmt::Display for Active<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "(Connection {} (streams {}))",
            self.id,
            self.registry.lock().streams.len()
        )
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> Active<T> {
    /// Create a new `Connection` from the given I/O resource.
    pub(super) fn new(socket: T, cfg: Config) -> Self {
        let id = Id::random();
        log::debug!("new connection: {id}");
        let socket = frame::Io::new(id, socket).fuse();
        let config = Arc::new(cfg);
        let rtt = rtt::Rtt::new();
        let accumulated_max_stream_windows = Arc::new(Mutex::new(0));
        let (new_receiver_tx, new_receiver_rx) = mpsc::unbounded();
        let registry = Arc::new(Mutex::new(StreamRegistry::new(
            id,
            config.clone(),
            rtt,
            accumulated_max_stream_windows,
            new_receiver_tx,
        )));
        Active {
            id,
            config,
            socket,
            registry,
            stream_receivers: SelectAll::default(),
            new_receiver_rx,
            no_streams_waker: None,
            pending_read_frame: None,
            pending_write_frame: None,
            batching: false,
            release_ack: None,
        }
    }

    /// Get a handle for creating streams concurrently.
    pub(super) fn handle(&self) -> Handle {
        Handle {
            registry: self.registry.clone(),
        }
    }

    /// Gracefully close the connection to the remote.
    pub(super) fn close(self) -> Closing<T> {
        let wait_for_reply = self.config.close_sync;
        let pending_frames = self
            .pending_read_frame
            .into_iter()
            .chain(self.pending_write_frame)
            .collect::<PendingFrames>();
        Closing::new(
            self.id,
            self.stream_receivers,
            pending_frames,
            self.socket,
            wait_for_reply,
            self.config.keep_alive,
        )
    }

    /// Close the connection without waiting for a reply.
    pub(super) fn close_no_wait(self) -> Closing<T> {
        let pending_frames = self
            .pending_read_frame
            .into_iter()
            .chain(self.pending_write_frame)
            .collect::<PendingFrames>();
        Closing::new(
            self.id,
            self.stream_receivers,
            pending_frames,
            self.socket,
            false,
            self.config.keep_alive,
        )
    }

    /// Cleanup all our resources.
    pub(super) fn cleanup(mut self, error: ConnectionError) -> Cleanup {
        self.drop_all_streams();
        Cleanup::new(self.stream_receivers, error)
    }

    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        loop {
            // Poll for new stream receivers from Handle
            while let Poll::Ready(Some(receiver)) = self.new_receiver_rx.poll_next_unpin(cx) {
                self.stream_receivers.push(receiver);
                if let Some(waker) = self.no_streams_waker.take() {
                    waker.wake();
                }
            }

            // Store waker in registry for Handle to wake us
            self.registry.lock().waker = Some(cx.waker().clone());

            if self.socket.poll_ready_unpin(cx).is_ready() {
                if self.registry.lock().batch_requested && !self.batching {
                    self.socket.get_mut().begin_batch();
                    self.batching = true;
                }
                if let Some(frame) = self.registry.lock().rtt.next_ping() {
                    self.socket.start_send_unpin(frame.into())?;
                    continue;
                }

                if let Some(frame) = self
                    .pending_read_frame
                    .take()
                    .or_else(|| self.pending_write_frame.take())
                {
                    self.socket.start_send_unpin(frame)?;
                    continue;
                }
            }

            match self.socket.poll_flush_unpin(cx)? {
                Poll::Ready(()) => {
                    if let Some(ack) = self.release_ack.take() {
                        let _ = ack.send(());
                    }
                }
                Poll::Pending => {}
            }

            if self.pending_write_frame.is_none() {
                match self.stream_receivers.poll_next_unpin(cx) {
                    Poll::Ready(Some((_, Some(StreamCommand::SendFrame(frame))))) => {
                        log::trace!(
                            "{}/{}: sending: {}",
                            self.id,
                            frame.header().stream_id(),
                            frame.header()
                        );
                        self.pending_write_frame.replace(frame);
                        continue;
                    }
                    Poll::Ready(Some((_, Some(StreamCommand::CloseStream { stream_id })))) => {
                        log::trace!("{}/{}: sending close", self.id, stream_id);
                        self.pending_write_frame
                            .replace(Frame::close_stream(stream_id).into());
                        continue;
                    }
                    Poll::Ready(Some((id, None))) => {
                        if let Some(frame) = self.on_drop_stream(id) {
                            log::trace!("{}/{}: sending: {}", self.id, id, frame.header());
                            self.pending_write_frame.replace(frame);
                        };
                        continue;
                    }
                    Poll::Ready(None) => {
                        self.no_streams_waker = Some(cx.waker().clone());
                    }
                    Poll::Pending => {}
                }
            }

            if self.pending_read_frame.is_none() {
                match self.socket.poll_next_unpin(cx) {
                    Poll::Ready(Some(frame)) => {
                        match self.on_frame(frame?)? {
                            Action::None => {}
                            Action::Ping(f) => {
                                log::trace!("{}/{}: pong", self.id, f.header().stream_id());
                                self.pending_read_frame.replace(f.into());
                            }
                            Action::Terminate(f) => {
                                log::trace!("{}: sending term", self.id);
                                self.pending_read_frame.replace(f.into());
                            }
                        }
                        continue;
                    }
                    Poll::Ready(None) => {
                        return Poll::Ready(Err(ConnectionError::Closed));
                    }
                    Poll::Pending => {}
                }
            }

            // Every stream queue was just polled to Pending. The caller has
            // queued the complete proof and request before asking for release.
            if self.batching
                && self.pending_write_frame.is_none()
                && self.pending_read_frame.is_none()
            {
                // The registry lock also serializes publication of release.
                // A caller can create/enqueue the attestation stream after the
                // top-of-loop polls but before requesting release. Recheck
                // BOTH queues under this lock before freezing the batch.
                let mut registry = self.registry.lock();
                if registry.release.is_some() {
                    if let Poll::Ready(Some(receiver)) = self.new_receiver_rx.poll_next_unpin(cx) {
                        self.stream_receivers.push(receiver);
                        drop(registry);
                        continue;
                    }
                    match self.stream_receivers.poll_next_unpin(cx) {
                        Poll::Ready(Some((_, Some(StreamCommand::SendFrame(frame))))) => {
                            self.pending_write_frame = Some(frame);
                            drop(registry);
                            continue;
                        }
                        Poll::Ready(Some((_, Some(StreamCommand::CloseStream { stream_id })))) => {
                            self.pending_write_frame = Some(Frame::close_stream(stream_id).into());
                            drop(registry);
                            continue;
                        }
                        Poll::Ready(Some((id, None))) => {
                            drop(registry);
                            self.pending_write_frame = self.on_drop_stream(id);
                            continue;
                        }
                        Poll::Ready(None) | Poll::Pending => {}
                    }
                }
                let release = registry.release.take();
                drop(registry);
                if let Some(ack) = release {
                    self.registry.lock().batch_requested = false;
                    self.socket.get_mut().end_batch();
                    self.batching = false;
                    self.release_ack = Some(ack);
                    continue;
                }
            }
            return Poll::Pending;
        }
    }

    /// Create a new stream.
    ///
    /// The stream ID is computed from the user ID using BLAKE3.
    pub(super) fn new_stream(&mut self, user_id: &[u8]) -> Result<Stream> {
        let stream = self.registry.lock().new_stream(user_id)?;
        // Drain new receivers immediately so they're available before poll
        while let Ok(receiver) = self.new_receiver_rx.try_recv() {
            self.stream_receivers.push(receiver);
        }
        Ok(stream)
    }

    fn on_drop_stream(&mut self, stream_id: StreamId) -> Option<Frame<()>> {
        let Some(s) = self.registry.lock().streams.remove(&stream_id) else {
            log::warn!("{}: stream {} not found on drop", self.id, stream_id);
            return None;
        };

        log::trace!("{}: removing dropped stream {}", self.id, stream_id);
        let frame = {
            let mut shared = s.lock();
            let frame = match shared.update_state(self.id, stream_id, State::Closed) {
                State::Open => {
                    let mut header = Header::data(stream_id, 0);
                    header.rst();
                    Some(Frame::new(header))
                }
                State::RecvClosed => {
                    let mut header = Header::data(stream_id, 0);
                    header.fin();
                    Some(Frame::new(header))
                }
                State::SendClosed => None,
                State::Closed => None,
            };
            if let Some(w) = shared.reader.take() {
                w.wake()
            }
            if let Some(w) = shared.writer.take() {
                w.wake()
            }
            frame
        };
        frame.map(Into::into)
    }

    fn on_frame(&mut self, frame: Frame<()>) -> Result<Action> {
        log::trace!("{}: received: {}", self.id, frame.header());

        let action = match frame.header().tag() {
            Tag::Data => self.on_data(frame.into_data()),
            Tag::WindowUpdate => self.on_window_update(&frame.into_window_update()),
            Tag::Ping => self.on_ping(&frame.into_ping()),
            Tag::GoAway => return Err(ConnectionError::Closed),
        };
        Ok(action)
    }

    fn on_data(&mut self, frame: Frame<Data>) -> Action {
        let stream_id = frame.header().stream_id();
        let mut registry = self.registry.lock();

        if frame.header().flags().contains(header::RST) {
            if let Some(s) = registry.streams.get_mut(&stream_id) {
                let mut shared = s.lock();
                shared.update_state(self.id, stream_id, State::Closed);
                if let Some(w) = shared.reader.take() {
                    w.wake()
                }
                if let Some(w) = shared.writer.take() {
                    w.wake()
                }
            }
            return Action::None;
        }

        let is_finish = frame.header().flags().contains(header::FIN);

        // SYN flag on Data frames is not allowed
        if frame.header().flags().contains(header::SYN) {
            log::error!("{}: SYN flag on Data frame is not allowed", self.id);
            return Action::Terminate(Frame::protocol_error());
        }

        // Implicit stream creation: if we receive data for an unknown stream,
        // create it automatically (the remote opened this stream)
        if !registry.streams.contains_key(&stream_id) {
            if stream_id.is_session() {
                log::error!("{}: data frame for session stream ID 0", self.id);
                return Action::Terminate(Frame::protocol_error());
            }

            if registry.streams.len() >= self.config.max_num_streams {
                log::error!("{}: maximum number of streams reached", self.id);
                return Action::Terminate(Frame::internal_error());
            }

            log::trace!(
                "{}/{}: creating implicit stream from remote",
                self.id,
                stream_id
            );
            let shared = registry.make_implicit_stream_shared();
            registry.streams.insert(stream_id, shared);
        }

        if let Some(s) = registry.streams.get_mut(&stream_id) {
            let mut shared = s.lock();
            if frame.body_len() > shared.receive_window() {
                log::error!(
                    "{}/{}: frame body larger than window of stream",
                    self.id,
                    stream_id
                );
                return Action::Terminate(Frame::protocol_error());
            }
            if is_finish {
                shared.update_state(self.id, stream_id, State::RecvClosed);
            }
            shared.consume_receive_window(frame.body_len());
            shared.buffer.push(frame.into_body());
            if let Some(w) = shared.reader.take() {
                w.wake()
            }
        }

        Action::None
    }

    fn on_window_update(&mut self, frame: &Frame<WindowUpdate>) -> Action {
        let stream_id = frame.header().stream_id();
        let mut registry = self.registry.lock();

        if frame.header().flags().contains(header::RST) {
            if let Some(s) = registry.streams.get_mut(&stream_id) {
                let mut shared = s.lock();
                shared.update_state(self.id, stream_id, State::Closed);
                if let Some(w) = shared.reader.take() {
                    w.wake()
                }
                if let Some(w) = shared.writer.take() {
                    w.wake()
                }
            }
            return Action::None;
        }

        let is_finish = frame.header().flags().contains(header::FIN);

        // SYN flag on WindowUpdate frames is not allowed
        if frame.header().flags().contains(header::SYN) {
            log::error!("{}: SYN flag on WindowUpdate frame is not allowed", self.id);
            return Action::Terminate(Frame::protocol_error());
        }

        // Implicit stream creation for window updates too
        if !registry.streams.contains_key(&stream_id) {
            if stream_id.is_session() {
                return Action::None; // Ignore window updates for session
            }

            if registry.streams.len() >= self.config.max_num_streams {
                log::error!("{}: maximum number of streams reached", self.id);
                return Action::Terminate(Frame::internal_error());
            }

            log::trace!(
                "{}/{}: creating implicit stream from remote window update",
                self.id,
                stream_id
            );
            let shared = registry.make_implicit_stream_shared();
            registry.streams.insert(stream_id, shared);
        }

        if let Some(s) = registry.streams.get_mut(&stream_id) {
            let mut shared = s.lock();
            shared.increase_send_window_by(frame.header().credit());
            if is_finish {
                shared.update_state(self.id, stream_id, State::RecvClosed);
                if let Some(w) = shared.reader.take() {
                    w.wake()
                }
            }
            if let Some(w) = shared.writer.take() {
                w.wake()
            }
        }

        Action::None
    }

    fn on_ping(&mut self, frame: &Frame<Ping>) -> Action {
        let stream_id = frame.header().stream_id();
        let mut registry = self.registry.lock();
        if frame.header().flags().contains(header::ACK) {
            return registry.rtt.handle_pong(frame.nonce());
        }
        if stream_id == CONNECTION_ID || registry.streams.contains_key(&stream_id) {
            let mut hdr = Header::ping(frame.header().nonce());
            hdr.ack();
            return Action::Ping(Frame::new(hdr));
        }
        log::debug!(
            "{}/{}: ping for unknown stream, possibly dropped earlier",
            self.id,
            stream_id,
        );
        Action::None
    }
}

impl<T> Active<T> {
    /// Close and drop all `Stream`s and wake any pending `Waker`s.
    pub(super) fn drop_all_streams(&mut self) {
        let mut registry = self.registry.lock();
        for (id, s) in registry.streams.drain() {
            let mut shared = s.lock();
            shared.update_state(self.id, id, State::Closed);
            if let Some(w) = shared.reader.take() {
                w.wake()
            }
            if let Some(w) = shared.writer.take() {
                w.wake()
            }
        }
    }
}

#[cfg(test)]
mod batch_tests {
    use super::*;
    use std::pin::Pin;
    #[derive(Clone, Default)]
    struct RecordingIo(Arc<Mutex<Vec<Vec<u8>>>>);
    impl AsyncRead for RecordingIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut [u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Pending
        }
    }
    impl AsyncWrite for RecordingIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.0.lock().push(bytes.to_vec());
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    #[test]
    fn release_includes_stream_created_between_queue_poll_and_barrier() {
        type Hook = Arc<Mutex<Option<Box<dyn FnOnce() + Send>>>>;
        struct HookIo {
            io: RecordingIo,
            hook: Hook,
        }
        impl AsyncRead for HookIo {
            fn poll_read(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                _: &mut [u8],
            ) -> Poll<std::io::Result<usize>> {
                if let Some(hook) = self.hook.lock().take() {
                    hook();
                }
                Poll::Pending
            }
        }
        impl AsyncWrite for HookIo {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                bytes: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                Pin::new(&mut self.io).poll_write(cx, bytes)
            }
            fn poll_flush(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.io).poll_flush(cx)
            }
            fn poll_close(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.io).poll_close(cx)
            }
        }
        futures::executor::block_on(async {
            let io = RecordingIo::default();
            let writes = io.0.clone();
            let hook: Hook = Default::default();
            let mut active = Active::new(
                HookIo {
                    io,
                    hook: hook.clone(),
                },
                Config::default(),
            );
            let handle = active.handle();
            let mut proof = handle.new_stream(b"proof").unwrap();
            handle.begin_batch();
            proof.write_all(b"committed proof").await.unwrap();
            proof.flush().await.unwrap();
            let kept_request = Arc::new(Mutex::new(None));
            let kept = kept_request.clone();
            let (ack, mut released) = oneshot::channel();
            *hook.lock() = Some(Box::new(move || {
                // Deterministically publish a new stream after the driver has
                // polled all queues, but before it considers releasing batch.
                let mut request = handle.new_stream(b"request").unwrap();
                {
                    let mut queued = Box::pin(async {
                        request.write_all(b"attestation request").await.unwrap();
                        request.flush().await.unwrap();
                    });
                    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
                    assert!(queued.as_mut().poll(&mut cx).is_ready());
                }
                *kept.lock() = Some(request);
                handle.registry.lock().release = Some(ack);
            }));
            futures::future::poll_fn(|cx| {
                assert!(active.poll(cx).is_pending());
                released.poll_unpin(cx)
            })
            .await
            .unwrap();
            let writes = writes.lock();
            assert_eq!(writes.len(), 1, "request escaped the proof batch");
            assert!(writes[0].windows(15).any(|x| x == b"committed proof"));
            assert!(writes[0].windows(19).any(|x| x == b"attestation request"));
        });
    }

    #[test]
    fn release_drains_all_streams_into_one_underlying_write() {
        futures::executor::block_on(async {
            let io = RecordingIo::default();
            let writes = io.0.clone();
            let mut connection = super::super::Connection::new(io, Config::default());
            let handle = connection.handle().unwrap();
            let mut proof = handle.new_stream(b"proof").unwrap();
            let mut request = handle.new_stream(b"request").unwrap();
            handle.begin_batch();
            proof.write_all(b"committed proof").await.unwrap();
            request.write_all(b"attestation request").await.unwrap();
            proof.flush().await.unwrap();
            request.flush().await.unwrap();
            assert!(writes.lock().is_empty());
            // Release is requested before the driver has even seen begin_batch.
            let mut release = Box::pin(handle.end_batch());
            futures::future::poll_fn(|cx| {
                if let Poll::Ready(result) = release.as_mut().poll(cx) {
                    return Poll::Ready(result);
                }
                assert!(connection.poll(cx).is_pending());
                Poll::Pending
            })
            .await
            .unwrap();
            let writes = writes.lock();
            assert_eq!(writes.len(), 1);
            assert!(writes[0].windows(15).any(|x| x == b"committed proof"));
            assert!(writes[0].windows(19).any(|x| x == b"attestation request"));
        });
    }
}
