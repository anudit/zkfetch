//! Prover <-> notary transport: a WebSocket carried as a byte stream, plus
//! length-prefixed framing for the post-MPC attestation exchange.

use anyhow::{Result, bail};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::MAX_FRAME_LEN;

/// Plain transport is limited to literal loopback addresses and localhost.
/// DNS names that happen to resolve locally do not qualify.
pub fn validate_endpoint(value: &str) -> Result<url::Url> {
    let endpoint = url::Url::parse(value)?;
    let local = match endpoint.host() {
        Some(url::Host::Domain("localhost")) => true,
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    if endpoint.scheme() != "wss" && !(endpoint.scheme() == "ws" && local) {
        bail!("remote notary and relay URLs must use wss://");
    }
    if !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.fragment().is_some()
    {
        bail!("notary URL must not contain userinfo or a fragment");
    }
    Ok(endpoint)
}

#[cfg(not(target_arch = "wasm32"))]
pub use socket::*;

#[cfg(target_arch = "wasm32")]
pub use browser::*;

/// A WebSocket byte stream that fails writes once the peer has gone.
///
/// The WebSocket adapters can leave a write pending forever after the
/// connection closed. The multiplexer flushes a final frame before it shuts
/// down, so one such write hangs the whole session (for example when the
/// notary rejects the target server and disconnects). After a read sees EOF or
/// any operation fails, writes return `BrokenPipe` and close completes at once.
pub struct Guarded<S> {
    inner: S,
    closed: bool,
}

impl<S> Guarded<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            closed: false,
        }
    }

    fn broken() -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "the notary connection is closed",
        )
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Guarded<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let poll = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(
            &poll,
            std::task::Poll::Ready(Ok(0)) | std::task::Poll::Ready(Err(_))
        ) && !buf.is_empty()
        {
            self.closed = true;
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Guarded<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.closed {
            return std::task::Poll::Ready(Err(Self::broken()));
        }
        let poll = std::pin::Pin::new(&mut self.inner).poll_write(cx, buf);
        if matches!(poll, std::task::Poll::Ready(Err(_))) {
            self.closed = true;
        }
        poll
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.closed {
            return std::task::Poll::Ready(Err(Self::broken()));
        }
        let poll = std::pin::Pin::new(&mut self.inner).poll_flush(cx);
        if matches!(poll, std::task::Poll::Ready(Err(_))) {
            self.closed = true;
        }
        poll
    }

    fn poll_close(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.closed {
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_close(cx)
    }
}

#[cfg(target_arch = "wasm32")]
mod browser {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use anyhow::{Result, anyhow};
    use async_io_stream::IoStream;
    use futures::{AsyncRead, AsyncWrite};
    use ws_stream_wasm::{WsMeta, WsStreamIo};

    /// Byte stream over a browser WebSocket.
    pub type ClientStream = super::Guarded<BrowserStream>;

    /// Keeps the socket's metadata handle alive for the stream's lifetime.
    pub struct BrowserStream {
        _meta: WsMeta,
        io: IoStream<WsStreamIo, Vec<u8>>,
    }

    /// Connects to a notary (or relay) at `ws://` or `wss://` `url`.
    pub async fn connect(url: &str) -> Result<ClientStream> {
        super::validate_endpoint(url)?;
        let (meta, ws) = WsMeta::connect(url, None)
            .await
            .map_err(|_| anyhow!("failed to connect to notary"))?;
        Ok(super::Guarded::new(BrowserStream {
            _meta: meta,
            io: ws.into_io(),
        }))
    }

    impl AsyncRead for BrowserStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.io).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for BrowserStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.io).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.io).poll_flush(cx)
        }

        fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.io).poll_close(cx)
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod socket {
    use anyhow::{Context, Result};
    use async_tungstenite::tokio::{
        TokioAdapter, accept_async_with_config, client_async_tls_with_connector_and_config,
    };
    use tokio::net::TcpStream;
    use ws_stream_tungstenite::WsStream;

    /// Byte stream over a client-side WebSocket.
    pub type ClientStream = super::Guarded<WsStream<async_tungstenite::tokio::ConnectStream>>;

    /// Byte stream over a server-side WebSocket.
    pub type ServerStream = super::Guarded<WsStream<TokioAdapter<TcpStream>>>;

    /// Connects to a notary at `ws://` or `wss://` `url`.
    pub async fn connect(url: &str) -> Result<ClientStream> {
        let endpoint = super::validate_endpoint(url)?;
        let host = endpoint.host_str().context("notary URL has no host")?;
        let port = endpoint
            .port_or_known_default()
            .context("notary URL has no port")?;
        let tcp = TcpStream::connect((host, port)).await?;
        // MPC makes many small, dependent exchanges. Avoid Nagle/delayed-ACK stalls.
        tcp.set_nodelay(true)?;
        let (ws, _) = client_async_tls_with_connector_and_config(
            url,
            tcp,
            None,
            Some(
                async_tungstenite::tungstenite::protocol::WebSocketConfig::default()
                    .max_frame_size(Some(1 << 20))
                    .max_message_size(Some(1 << 20)),
            ),
        )
        .await
        .context("failed to connect to notary")?;
        Ok(super::Guarded::new(WsStream::new(ws)))
    }

    /// Accepts a WebSocket upgrade on an incoming TCP connection.
    pub async fn accept(tcp: TcpStream) -> Result<ServerStream> {
        tcp.set_nodelay(true)?;
        let ws = accept_async_with_config(
            tcp,
            Some(
                async_tungstenite::tungstenite::protocol::WebSocketConfig::default()
                    .max_frame_size(Some(1 << 20))
                    .max_message_size(Some(1 << 20)),
            ),
        )
        .await
        .context("websocket handshake failed")?;
        Ok(super::Guarded::new(WsStream::new(ws)))
    }
}

/// Writes a u32 big-endian length-prefixed frame.
pub async fn write_frame<W: AsyncWrite + Unpin>(io: &mut W, data: &[u8]) -> Result<()> {
    if data.len() > MAX_FRAME_LEN {
        bail!("frame too large: {} bytes", data.len());
    }
    io.write_all(&(data.len() as u32).to_be_bytes()).await?;
    io.write_all(data).await?;
    io.flush().await?;
    Ok(())
}

/// Reads a u32 big-endian length-prefixed frame.
pub async fn read_frame<R: AsyncRead + Unpin>(io: &mut R) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    io.read_exact(&mut len)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read frame length: {e}"))?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME_LEN {
        bail!("frame too large: {len} bytes");
    }
    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read frame body: {e}"))?;
    Ok(buf)
}

#[cfg(test)]
mod security_tests {
    use super::*;
    #[test]
    fn remote_plaintext_transport_is_rejected() {
        for url in [
            "ws://example.com",
            "ws://localhost.example",
            "ws://127.0.0.1.example",
            "https://example.com",
        ] {
            assert!(validate_endpoint(url).is_err(), "{url}");
        }
        for url in [
            "wss://example.com",
            "ws://127.0.0.1",
            "ws://[::1]",
            "ws://localhost",
        ] {
            assert!(validate_endpoint(url).is_ok(), "{url}");
        }
    }
    #[test]
    fn oversized_frames_are_rejected_before_reading_the_body() {
        let mut stream = futures::io::Cursor::new(((MAX_FRAME_LEN + 1) as u32).to_be_bytes());
        assert!(futures::executor::block_on(read_frame(&mut stream)).is_err());
    }
}
