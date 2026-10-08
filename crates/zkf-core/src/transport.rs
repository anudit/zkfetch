//! Prover <-> notary transport: a WebSocket carried as a byte stream, plus
//! length-prefixed framing for the post-MPC attestation exchange.

use anyhow::{Result, bail};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::MAX_FRAME_LEN;

#[cfg(not(target_arch = "wasm32"))]
pub use socket::*;

#[cfg(target_arch = "wasm32")]
pub use browser::*;

#[cfg(target_arch = "wasm32")]
mod browser {
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    use anyhow::{Result, anyhow, bail};
    use futures::{AsyncRead, AsyncWrite};
    use async_io_stream::IoStream;
    use ws_stream_wasm::{WsMeta, WsStreamIo};

    /// Byte stream over a browser WebSocket. Keeps the socket's metadata
    /// handle alive for the stream's lifetime.
    pub struct ClientStream {
        _meta: WsMeta,
        io: IoStream<WsStreamIo, Vec<u8>>,
    }

    /// Connects to a notary (or relay) at `ws://` or `wss://` `url`.
    pub async fn connect(url: &str) -> Result<ClientStream> {
        if !(url.starts_with("ws://") || url.starts_with("wss://")) {
            bail!("notary URL must use ws:// or wss://");
        }
        let (meta, ws) = WsMeta::connect(url, None)
            .await
            .map_err(|e| anyhow!("failed to connect to {url}: {e}"))?;
        Ok(ClientStream {
            _meta: meta,
            io: ws.into_io(),
        })
    }

    impl AsyncRead for ClientStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.io).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for ClientStream {
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
    use anyhow::{Context, Result, bail};
    use async_tungstenite::tokio::{
        TokioAdapter, accept_async, client_async_tls_with_connector_and_config,
    };
    use tokio::net::TcpStream;
    use ws_stream_tungstenite::WsStream;

    /// Byte stream over a client-side WebSocket.
    pub type ClientStream = WsStream<async_tungstenite::tokio::ConnectStream>;

    /// Byte stream over a server-side WebSocket.
    pub type ServerStream = WsStream<TokioAdapter<TcpStream>>;

    /// Connects to a notary at `ws://` or `wss://` `url`.
    pub async fn connect(url: &str) -> Result<ClientStream> {
        let endpoint = url::Url::parse(url).context("invalid notary URL")?;
        if !matches!(endpoint.scheme(), "ws" | "wss") {
            bail!("notary URL must use ws:// or wss://");
        }
        let host = endpoint.host_str().context("notary URL has no host")?;
        let port = endpoint
            .port_or_known_default()
            .context("notary URL has no port")?;
        let tcp = TcpStream::connect((host, port)).await?;
        // MPC makes many small, dependent exchanges. Avoid Nagle/delayed-ACK stalls.
        tcp.set_nodelay(true)?;
        let (ws, _) = client_async_tls_with_connector_and_config(url, tcp, None, None)
            .await
            .with_context(|| format!("failed to connect to notary at {url}"))?;
        Ok(WsStream::new(ws))
    }

    /// Accepts a WebSocket upgrade on an incoming TCP connection.
    pub async fn accept(tcp: TcpStream) -> Result<ServerStream> {
        tcp.set_nodelay(true)?;
        let ws = accept_async(tcp)
            .await
            .context("websocket handshake failed")?;
        Ok(WsStream::new(ws))
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
