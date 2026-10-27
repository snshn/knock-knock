//! Obtains TLS certificate expiration info by connecting to a server.

use chrono::{DateTime, Utc};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, SignatureScheme};
use rustls_platform_verifier::Verifier;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::x509::{CertificateValidity, certificate_validity};
use crate::{KnockKnockError, MAX_ATTEMPTS, RETRY_DELAY, TIMEOUT_SECS, error_chain};

/// Certificate presented by a server
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Certificate {
    pub host: String,
    pub port: u16,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub self_signed: bool,
    /// Why the certificate is not trusted by the operating system (if it isn't)
    pub verification_error: Option<VerificationError>,
}

/// Reasons why a certificate may not be trusted
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerificationError {
    Expired,
    NotValidForName(String),
    NotValidYet,
    Revoked,
    /// Includes self-signed certificates
    UnknownIssuer,
    Other(String),
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerificationError::Expired => write!(f, "expired"),
            VerificationError::NotValidForName(host) => write!(f, "not valid for {}", host),
            VerificationError::NotValidYet => write!(f, "not valid yet"),
            VerificationError::Revoked => write!(f, "revoked"),
            VerificationError::UnknownIssuer => {
                write!(f, "issued by an unknown certificate authority")
            }
            VerificationError::Other(details) => write!(f, "{}", details),
        }
    }
}

/// Wraps the platform verifier, recording its verdict instead of aborting the handshake,
/// so that information about invalid (e.g. expired or self-signed) certificates can be obtained
struct RecordingVerifier {
    inner: Arc<Verifier>,
    verdict: Mutex<Option<Result<(), rustls::Error>>>,
}

impl fmt::Debug for RecordingVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordingVerifier").finish_non_exhaustive()
    }
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let verdict = self
            .inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
            .map(|_| ());

        if let Ok(mut recorded_verdict) = self.verdict.lock() {
            *recorded_verdict = Some(verdict);
        }

        Ok(ServerCertVerified::assertion())
    }

    // Handshake signatures are still verified for real
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Turns rustls' certificate verification error into something simpler
fn to_verification_error(error: &rustls::Error, host: &str) -> VerificationError {
    match error {
        rustls::Error::InvalidCertificate(certificate_error) => match certificate_error {
            CertificateError::UnknownIssuer => VerificationError::UnknownIssuer,
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                VerificationError::NotValidForName(host.to_string())
            }
            CertificateError::Expired | CertificateError::ExpiredContext { .. } => {
                VerificationError::Expired
            }
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
                VerificationError::NotValidYet
            }
            CertificateError::Revoked => VerificationError::Revoked,
            other => VerificationError::Other(format!("{:?}", other)),
        },
        other => VerificationError::Other(other.to_string()),
    }
}

fn timestamp_to_datetime(timestamp: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(timestamp, 0).unwrap_or(DateTime::<Utc>::MAX_UTC)
}

/// Looks up TLS certificates presented by servers
pub struct TlsChecker {
    provider: Arc<CryptoProvider>,
    verifier: Arc<Verifier>,
}

impl TlsChecker {
    pub fn new() -> Result<TlsChecker, KnockKnockError> {
        let provider: Arc<CryptoProvider> = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let verifier: Verifier = Verifier::new(provider.clone())
            .map_err(|error| KnockKnockError::TlsSetupProblem(error_chain(&error)))?;

        Ok(TlsChecker {
            provider,
            verifier: Arc::new(verifier),
        })
    }

    /// Connects to given host and port, and obtains its certificate's validity info
    async fn fetch_certificate(
        &self,
        host: &str,
        port: u16,
    ) -> Result<Certificate, KnockKnockError> {
        let recording_verifier = Arc::new(RecordingVerifier {
            inner: self.verifier.clone(),
            verdict: Mutex::new(None),
        });

        let config: ClientConfig = ClientConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|error| KnockKnockError::TlsSetupProblem(error_chain(&error)))?
            .dangerous()
            .with_custom_certificate_verifier(recording_verifier.clone())
            .with_no_client_auth();

        let server_name: ServerName<'static> = ServerName::try_from(host.to_string())
            .map_err(|_| KnockKnockError::InvalidDomainName)?;
        let connector: TlsConnector = TlsConnector::from(Arc::new(config));

        let connection = async {
            let tcp_stream: TcpStream = TcpStream::connect((host, port)).await?;
            connector.connect(server_name, tcp_stream).await
        };

        let tls_stream = timeout(Duration::from_secs(TIMEOUT_SECS), connection)
            .await
            .map_err(|_| KnockKnockError::TlsConnectionFailed("timed out".to_string()))?
            .map_err(|error| KnockKnockError::TlsConnectionFailed(error_chain(&error)))?;

        let leaf_certificate: &CertificateDer<'static> = tls_stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certificates| certificates.first())
            .ok_or(KnockKnockError::NoCertificatePresented)?;

        let validity: CertificateValidity = certificate_validity(leaf_certificate.as_ref())
            .ok_or(KnockKnockError::CouldntParseCertificate)?;

        let not_verified = || VerificationError::Other("certificate was not verified".to_string());
        let verification_error: Option<VerificationError> = match recording_verifier.verdict.lock()
        {
            Ok(verdict) => match verdict.as_ref() {
                Some(Ok(())) => None,
                Some(Err(error)) => Some(to_verification_error(error, host)),
                None => Some(not_verified()),
            },
            Err(_) => Some(not_verified()),
        };

        Ok(Certificate {
            host: host.to_string(),
            port,
            not_before: timestamp_to_datetime(validity.not_before),
            not_after: timestamp_to_datetime(validity.not_after),
            self_signed: validity.self_signed,
            verification_error,
        })
    }

    /// Obtains certificate info for given host and port, retrying on connection failures
    pub async fn check(&self, host: &str, port: u16) -> Result<Certificate, KnockKnockError> {
        let mut attempt: u32 = 1;

        loop {
            match self.fetch_certificate(host, port).await {
                Err(error) if error.is_transient() && attempt < MAX_ATTEMPTS => {
                    tokio::time::sleep(RETRY_DELAY * attempt).await;
                    attempt += 1;
                }
                result => return result,
            }
        }
    }
}
