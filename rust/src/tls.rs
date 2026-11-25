//! TLS plumbing (tokio-rustls, ring provider): server configuration for the
//! inbound STARTTLS listener and client configuration for upstream STARTTLS,
//! plus the boxed duplex stream type the SMTP code upgrades in place.

use std::sync::{Arc, OnceLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite};

/// A duplex byte stream (plain TCP or TLS).
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// Boxed stream so a connection can be swapped from TCP to TLS mid-session.
pub type BoxIo = Box<dyn Io>;

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Loads a PEM certificate chain and private key into a server config.
pub fn server_config_from_pem(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<Arc<ServerConfig>, String> {
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<_, _>>()
        .map_err(|e| format!("tls: parse certificate: {e}"))?;
    if certs.is_empty() {
        return Err("tls: no certificate found".into());
    }
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut &key_pem[..])
        .map_err(|e| format!("tls: parse key: {e}"))?
        .ok_or("tls: no private key found")?;
    let cfg = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("tls: {e}"))?;
    Ok(Arc::new(cfg))
}

/// Loads cert/key files into a server config.
pub fn server_config(cert_file: &str, key_file: &str) -> Result<Arc<ServerConfig>, String> {
    let c = std::fs::read(cert_file).map_err(|e| format!("tls: {cert_file}: {e}"))?;
    let k = std::fs::read(key_file).map_err(|e| format!("tls: {key_file}: {e}"))?;
    server_config_from_pem(&c, &k)
}

/// Client config verifying against the Mozilla root set, or (when `insecure`)
/// accepting any certificate — for internal upstreams with private CAs.
pub fn client_config(insecure: bool) -> Arc<ClientConfig> {
    static VERIFIED: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    static INSECURE: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    if insecure {
        INSECURE
            .get_or_init(|| {
                let p = provider();
                let cfg = ClientConfig::builder_with_provider(p.clone())
                    .with_safe_default_protocol_versions()
                    .expect("tls versions")
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoVerify(p)))
                    .with_no_client_auth();
                Arc::new(cfg)
            })
            .clone()
    } else {
        VERIFIED
            .get_or_init(|| {
                let mut roots = rustls::RootCertStore::empty();
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                let cfg = ClientConfig::builder_with_provider(provider())
                    .with_safe_default_protocol_versions()
                    .expect("tls versions")
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                Arc::new(cfg)
            })
            .clone()
    }
}

/// Upgrades `io` to TLS as a client for `host`.
pub async fn connect(io: BoxIo, host: &str, insecure: bool) -> Result<BoxIo, String> {
    let name = ServerName::try_from(host.to_string())
        .map_err(|e| format!("tls: server name {host:?}: {e}"))?;
    let tls = tokio_rustls::TlsConnector::from(client_config(insecure))
        .connect(name, io)
        .await
        .map_err(|e| format!("tls handshake: {e}"))?;
    Ok(Box::new(tls))
}

/// Upgrades `io` to TLS as a server.
pub async fn accept(io: BoxIo, cfg: Arc<ServerConfig>) -> std::io::Result<BoxIo> {
    let tls = tokio_rustls::TlsAcceptor::from(cfg).accept(io).await?;
    Ok(Box::new(tls))
}

#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
