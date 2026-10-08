//! KeyLog implementation that captures the TLS 1.2 master secret, or the
//! TLS 1.3 traffic secrets (zkfetch patch P4).

use rustls::KeyLog;
use std::sync::Mutex;

const MS: &str = "CLIENT_RANDOM";
const CLIENT_APP: &str = "CLIENT_TRAFFIC_SECRET_0";
const SERVER_APP: &str = "SERVER_TRAFFIC_SECRET_0";
const CLIENT_HS: &str = "CLIENT_HANDSHAKE_TRAFFIC_SECRET";
const SERVER_HS: &str = "SERVER_HANDSHAKE_TRAFFIC_SECRET";

#[derive(Debug, Default)]
pub(crate) struct MasterSecretLog {
    ms: Mutex<Vec<u8>>,
    client_app: Mutex<Vec<u8>>,
    server_app: Mutex<Vec<u8>>,
    client_hs: Mutex<Vec<u8>>,
    server_hs: Mutex<Vec<u8>>,
}

impl MasterSecretLog {
    pub(crate) fn take(&self) -> Vec<u8> {
        std::mem::take(&mut *self.ms.lock().expect("key log lock"))
    }

    /// TLS 1.3 client and server handshake traffic secrets.
    pub(crate) fn take_hs_secrets(&self) -> (Vec<u8>, Vec<u8>) {
        (
            std::mem::take(&mut *self.client_hs.lock().expect("key log lock")),
            std::mem::take(&mut *self.server_hs.lock().expect("key log lock")),
        )
    }

    /// TLS 1.3 client and server application traffic secrets.
    pub(crate) fn take_app_secrets(&self) -> (Vec<u8>, Vec<u8>) {
        (
            std::mem::take(&mut *self.client_app.lock().expect("key log lock")),
            std::mem::take(&mut *self.server_app.lock().expect("key log lock")),
        )
    }
}

impl KeyLog for MasterSecretLog {
    fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
        let slot = match label {
            MS => &self.ms,
            CLIENT_APP => &self.client_app,
            SERVER_APP => &self.server_app,
            CLIENT_HS => &self.client_hs,
            SERVER_HS => &self.server_hs,
            _ => return,
        };
        *slot.lock().expect("key log lock") = secret.to_vec();
    }

    fn will_log(&self, label: &str) -> bool {
        matches!(label, MS | CLIENT_APP | SERVER_APP | CLIENT_HS | SERVER_HS)
    }
}
