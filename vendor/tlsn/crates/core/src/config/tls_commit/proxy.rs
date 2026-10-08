//! Proxy-TLS commitment protocol configuration.

use crate::connection::{DnsName, TlsVersion};
use serde::{Deserialize, Serialize};

/// Proxy-TLS commitment protocol configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProxyTlsConfig {
    /// The server name.
    server_name: DnsName,
    /// TLS protocol version to negotiate (zkfetch patch P4).
    #[serde(default = "tls12")]
    tls_version: TlsVersion,
}

fn tls12() -> TlsVersion {
    TlsVersion::V1_2
}

impl ProxyTlsConfig {
    /// Creates a new builder.
    pub fn builder() -> ProxyTlsConfigBuilder {
        ProxyTlsConfigBuilder::default()
    }

    /// Returns the server name.
    pub fn server_name(&self) -> &DnsName {
        &self.server_name
    }

    /// Returns the TLS protocol version to negotiate.
    pub fn tls_version(&self) -> TlsVersion {
        self.tls_version
    }
}

/// Builder for [`ProxyTlsConfig`].
#[derive(Debug, Default)]
pub struct ProxyTlsConfigBuilder {
    server_name: Option<DnsName>,
    tls_version: Option<TlsVersion>,
}

impl ProxyTlsConfigBuilder {
    /// Sets the server name.
    pub fn server_name(mut self, server_name: DnsName) -> Self {
        self.server_name = Some(server_name);
        self
    }

    /// Sets the TLS protocol version (default TLS 1.2).
    pub fn tls_version(mut self, tls_version: TlsVersion) -> Self {
        self.tls_version = Some(tls_version);
        self
    }

    /// Builds the configuration.
    pub fn build(self) -> Result<ProxyTlsConfig, ProxyTlsConfigError> {
        let server_name = self
            .server_name
            .ok_or(ProxyTlsConfigError(ErrorRepr::MissingField {
                name: "server_name",
            }))?;

        let config = ProxyTlsConfig {
            server_name,
            tls_version: self.tls_version.unwrap_or(TlsVersion::V1_2),
        };
        Ok(config)
    }
}

/// Error for [`ProxyTlsConfig`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ProxyTlsConfigError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("missing field: {name}")]
    MissingField { name: &'static str },
}
