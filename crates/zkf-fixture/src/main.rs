//! Local HTTPS fixture serving `test-server.io` with a test CA.
//!
//! Env: `ZKF_FIXTURE_ADDR` (default `127.0.0.1:4443`).
//! Prints `ZKF_FIXTURE_READY <addr> <server-name> <ca-der-base64>` once bound.

use tlsn_server_fixture::{bind, bind_tls12, bind_tls13};
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};
use tokio::net::TcpListener;
use tokio_util::compat::TokioAsyncWriteCompatExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr = std::env::var("ZKF_FIXTURE_ADDR").unwrap_or_else(|_| "127.0.0.1:4443".into());
    let listener = TcpListener::bind(&addr).await?;
    let version = std::env::var("ZKF_FIXTURE_TLS_VERSION").unwrap_or_else(|_| "auto".into());
    anyhow::ensure!(
        ["auto", "1.2", "1.3"].contains(&version.as_str()),
        "invalid fixture TLS version"
    );
    println!(
        "ZKF_FIXTURE_READY {} {} {}",
        listener.local_addr()?,
        SERVER_DOMAIN,
        zkf_core::b64::encode(CA_CERT_DER)
    );
    loop {
        let (socket, _) = listener.accept().await?;
        let version = version.clone();
        tokio::spawn(async move {
            match version.as_str() {
                "1.2" => bind_tls12(socket.compat_write()).await,
                "1.3" => bind_tls13(socket.compat_write()).await,
                _ => bind(socket.compat_write()).await,
            }
        });
    }
}
