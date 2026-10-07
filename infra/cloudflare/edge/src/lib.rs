//! zkfetch notary inside a Cloudflare Worker.
//!
//! The MPC-TLS verifier runs in the Worker isolate that accepts the prover's
//! WebSocket, at the edge location nearest the prover. Each MPC round trip is
//! prover <-> edge only, with no Durable Object or container hop. The Worker
//! has no threads; the patched tlsn session runs MPC tasks on this thread.

use std::{
    pin::Pin,
    task::Poll,
    time::Duration,
};

use futures::{
    AsyncRead, AsyncWrite, FutureExt, StreamExt,
    channel::mpsc::{UnboundedReceiver, unbounded},
};
use worker::{js_sys, *};
use zkf_notary::{NotaryConfig, ServerConnector, notarize};

const SESSION_TIMEOUT: Duration = Duration::from_secs(120);

#[event(start)]
fn start() {
    console_error_panic_hook::set_once();
    // DEBUG(mem)
    let _ = zkf_notary::PHASE_HOOK.set(|name| {
        console_log!("phase {name}: {} MiB", core::arch::wasm32::memory_size(0) * 64 / 1024)
    });
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: worker::Context) -> Result<Response> {
    if req.method() != Method::Get {
        return Response::error("Method not allowed", 405);
    }
    let config = match signing_key(&env) {
        Ok(signing_key) => NotaryConfig { signing_key, extra_roots: Vec::new() },
        Err(err) => {
            console_error!("{err:#}");
            return Response::error("Notary signing key is not configured", 503);
        }
    };
    match req.path().as_str() {
        "/health" => Response::from_json(&serde_json::json!({
            "publicKey": config.public_key_hex().map_err(|e| Error::RustError(e.to_string()))?,
            "tlsVersions": ["1.2", "1.3"],
            "cipher": "AES-128-GCM",
            "runtime": "worker",
            "location": req.cf().map(|cf| cf.colo()),
        })),
        "/notarize" => {
            let upgrade = req.headers().get("Upgrade")?.map(|v| v.to_ascii_lowercase());
            if upgrade.as_deref() != Some("websocket") {
                return Response::error("WebSocket upgrade required", 426);
            }
            let pair = WebSocketPair::new()?;
            let server = pair.server;
            server.accept()?;
            // Newer compatibility dates default to Blob, which `bytes()` reads
            // as empty. MPC frames are binary; receive them as ArrayBuffers.
            js_sys::Reflect::set(server.as_ref(), &"binaryType".into(), &"arraybuffer".into())?;
            wasm_bindgen_futures::spawn_local(async move {
                let session = run_session(server.clone(), config).fuse();
                let timeout = Delay::from(SESSION_TIMEOUT).fuse();
                futures::pin_mut!(session, timeout);
                let result = futures::select! {
                    result = session => result,
                    () = timeout => Err(anyhow::anyhow!("session timed out after {SESSION_TIMEOUT:?}")),
                };
                // Linear memory only grows, so this is the session's peak.
                console_log!("wasm memory {} MiB", core::arch::wasm32::memory_size(0) * 64 / 1024);
                match result {
                    Ok(()) => console_log!("session notarized"),
                    Err(err) => {
                        console_error!("session failed: {err:#}");
                        let _ = server.close(Some(1011), Some("notarization failed"));
                    }
                }
            });
            Response::from_websocket(pair.client)
        }
        _ => Response::error("Not found", 404),
    }
}

fn signing_key(env: &Env) -> anyhow::Result<[u8; 32]> {
    let hex_key = env
        .secret("ZKF_NOTARY_KEY")
        .map_err(|_| anyhow::anyhow!("ZKF_NOTARY_KEY secret is missing"))?
        .to_string();
    hex::decode(hex_key.trim())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("notary key must be 32 bytes"))
}

async fn run_session(ws: WebSocket, config: NotaryConfig) -> anyhow::Result<()> {
    let (tx, rx) = unbounded();
    let events_ws = ws.clone();
    // Forward incoming frames until the socket closes; dropping `tx` is EOF.
    wasm_bindgen_futures::spawn_local(async move {
        let mut events = match events_ws.events() {
            Ok(events) => events,
            Err(err) => {
                console_error!("events() failed: {err:?}");
                return;
            }
        };
        while let Some(event) = events.next().await {
            match event {
                Ok(WebsocketEvent::Message(msg)) => {
                    if let Some(bytes) = msg.bytes() {
                        if tx.unbounded_send(bytes).is_err() {
                            break;
                        }
                    }
                }
                Ok(WebsocketEvent::Close(_)) | Err(_) => break,
            }
        }
    });
    notarize(WsIo { ws, rx, buf: Vec::new(), pos: 0 }, &config, &WorkerConnector).await
}

/// Proxy mode: the notary's TCP connection to the server, via `connect()`.
struct WorkerConnector;

impl ServerConnector for WorkerConnector {
    type Stream = ServerSocket;

    async fn connect(&self, host: &str, port: u16) -> anyhow::Result<Self::Stream> {
        use tokio_util::compat::TokioAsyncReadCompatExt;
        let socket = ConnectionBuilder::new()
            .connect(host, port)
            .map_err(|e| anyhow::anyhow!("connect to {host}:{port} failed: {e}"))?;
        socket
            .opened()
            .await
            .map_err(|e| anyhow::anyhow!("connect to {host}:{port} failed: {e}"))?;
        Ok(ServerSocket { inner: socket.compat(), read_eof: false })
    }
}

/// Workers TCP socket that, like a native socket, accepts writes after the
/// server has closed. The prover's TLS client sends `close_notify` after a
/// `Connection: close` response; a Workers socket would throw on it.
struct ServerSocket {
    inner: tokio_util::compat::Compat<Socket>,
    read_eof: bool,
}

impl AsyncRead for ServerSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_read(cx, out);
        if let Poll::Ready(Ok(0)) = poll {
            self.read_eof = true;
        }
        poll
    }
}

impl AsyncWrite for ServerSocket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.read_eof {
            return Poll::Ready(Ok(data.len()));
        }
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<std::io::Result<()>> {
        if self.read_eof {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<std::io::Result<()>> {
        if self.read_eof {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

/// WebSocket as a byte stream: each write is one binary message.
struct WsIo {
    ws: WebSocket,
    rx: UnboundedReceiver<Vec<u8>>,
    buf: Vec<u8>,
    pos: usize,
}

impl AsyncRead for WsIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        while self.pos == self.buf.len() {
            match self.rx.poll_next_unpin(cx) {
                Poll::Ready(Some(bytes)) => {
                    self.buf = bytes;
                    self.pos = 0;
                }
                Poll::Ready(None) => return Poll::Ready(Ok(0)),
                Poll::Pending => return Poll::Pending,
            }
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Poll::Ready(Ok(n))
    }
}

impl AsyncWrite for WsIo {
    fn poll_write(self: Pin<&mut Self>, _: &mut std::task::Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        Poll::Ready(
            self.ws
                .send_with_bytes(data)
                .map(|()| data.len())
                .map_err(|e| std::io::Error::other(e.to_string())),
        )
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut std::task::Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut std::task::Context<'_>) -> Poll<std::io::Result<()>> {
        let _ = self.ws.close(Some(1000), Some("done"));
        Poll::Ready(Ok(()))
    }
}
