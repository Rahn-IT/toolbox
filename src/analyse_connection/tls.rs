use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
};

use hickory_client::proto::rr::Name;
use iced::{Alignment, Element, widget::row};
use tokio::{net::TcpStream, time::Instant};
use tokio_rustls::{
    TlsConnector,
    client::TlsStream,
    rustls,
    rustls::{
        CertificateError, DigitallySignedStruct, SignatureScheme,
        client::{
            WebPkiServerVerifier,
            danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        },
        pki_types::{CertificateDer, ServerName, UnixTime},
    },
};
use x509_parser::certificate::X509Certificate;

use super::{
    check_view::{badge, checking},
    port_connectivity::Message,
};

pub(super) fn server_name(host: &str) -> Result<ServerName<'static>, String> {
    if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
        return Ok(ip.into());
    }
    let name = Name::from_utf8(host).map_err(|error| error.to_string())?;
    let ascii = name.to_ascii();
    let ascii = ascii.trim_end_matches('.');
    if !ascii
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
    {
        return Err("Invalid hostname".into());
    }
    ServerName::try_from(ascii.to_owned()).map_err(|error| error.to_string())
}

#[derive(Clone, Default)]
pub struct PresentedCertificate {
    pub certificates: Vec<CertificateDer<'static>>,
    pub verification: Option<Result<(), rustls::Error>>,
}

#[derive(Clone)]
pub struct Report {
    pub presented: PresentedCertificate,
    handshake: Result<(), String>,
    pub peer_alert: bool,
}

#[derive(Default)]
pub(super) enum State {
    #[default]
    Disabled,
    Checking,
    Complete(Report),
}

impl State {
    pub fn start(&mut self) {
        if matches!(self, Self::Disabled) {
            *self = Self::Checking;
        }
    }

    pub fn finish(&mut self, report: Report) {
        if matches!(self, Self::Checking) {
            *self = Self::Complete(report);
        }
    }

    pub fn certificates(&self) -> Option<&[CertificateDer<'static>]> {
        match self {
            Self::Complete(report) if !report.presented.certificates.is_empty() => {
                Some(&report.presented.certificates)
            }
            _ => None,
        }
    }

    pub fn view(&self) -> Option<Element<'_, Message>> {
        Some(match self {
            Self::Checking => checking(),
            Self::Complete(report) => {
                let status = match (&report.handshake, &report.presented.verification) {
                    (_, Some(Err(error))) => badge(verification_failure(error), false),
                    (Ok(()), Some(Ok(()))) => badge("Verified", true),
                    _ => badge("TLS failed", false),
                };
                let self_signed = report.presented.certificates.first().is_some_and(|der| {
                    x509_parser::parse_x509_certificate(der.as_ref())
                        .is_ok_and(|(_, certificate)| is_self_signed(&certificate))
                });
                row![status, self_signed.then(|| badge("Self-signed", false))]
                    .align_y(Alignment::Center)
                    .spacing(8)
                    .into()
            }
            _ => return None,
        })
    }
}

pub(super) fn is_self_signed(certificate: &X509Certificate<'_>) -> bool {
    certificate.subject() == certificate.issuer() && certificate.verify_signature(None).is_ok()
}

fn verification_failure(error: &rustls::Error) -> &'static str {
    match error {
        rustls::Error::InvalidCertificate(error) => match error {
            CertificateError::Expired | CertificateError::ExpiredContext { .. } => {
                "Certificate expired"
            }
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
                "Certificate not yet valid"
            }
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                "Certificate name mismatch"
            }
            CertificateError::UnknownIssuer => "Untrusted certificate issuer",
            _ => "Certificate rejected",
        },
        _ => "Certificate rejected",
    }
}

pub(super) async fn inspect(
    stream: TcpStream,
    name: ServerName<'static>,
    deadline: Instant,
) -> (Report, Option<TlsStream<TcpStream>>) {
    let presented = Arc::new(Mutex::new(PresentedCertificate::default()));
    let result = handshake(stream, name, Arc::clone(&presented), deadline).await;
    let presented =
        std::mem::take(&mut *presented.lock().unwrap_or_else(|error| error.into_inner()));
    let peer_alert = result.as_ref().err().is_some_and(|error| {
        matches!(
            error
                .get_ref()
                .and_then(|source| source.downcast_ref::<rustls::Error>()),
            Some(rustls::Error::AlertReceived(_))
        )
    });
    let report = Report {
        presented,
        handshake: result.as_ref().map(|_| ()).map_err(ToString::to_string),
        peer_alert,
    };
    (report, result.ok())
}

async fn handshake(
    stream: TcpStream,
    server_name: ServerName<'static>,
    presented: Arc<Mutex<PresentedCertificate>>,
    deadline: Instant,
) -> std::io::Result<TlsStream<TcpStream>> {
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let verifier = WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .map_err(std::io::Error::other)?;
    let verifier = Arc::new(CaptureVerifier {
        verifier,
        presented,
    });
    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));
    tokio::time::timeout_at(deadline, connector.connect(server_name, stream))
        .await
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))?
}

struct CaptureVerifier {
    verifier: Arc<WebPkiServerVerifier>,
    presented: Arc<Mutex<PresentedCertificate>>,
}

impl std::fmt::Debug for CaptureVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CaptureVerifier")
            .finish_non_exhaustive()
    }
}

impl ServerCertVerifier for CaptureVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let result = self
            .verifier
            .verify_server_cert(end_entity, intermediates, name, ocsp, now);
        let mut presented = self
            .presented
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        presented.certificates = std::iter::once(end_entity)
            .chain(intermediates)
            .map(|cert| cert.clone().into_owned())
            .collect();
        presented.verification = Some(result.as_ref().map(|_| ()).map_err(Clone::clone));
        // This connector only detects the protocol at the selected endpoint.
        // Keep WebPKI's trust result for the UI and verify handshake signatures normally.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verifier
            .verify_tls12_signature(message, certificate, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verifier
            .verify_tls13_signature(message, certificate, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.verifier.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn permits_detection_and_records_the_chain_when_webpki_rejects_it() {
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let presented = Arc::new(Mutex::new(PresentedCertificate::default()));
        let verifier = CaptureVerifier {
            verifier: WebPkiServerVerifier::builder(Arc::new(roots))
                .build()
                .unwrap(),
            presented: Arc::clone(&presented),
        };
        let leaf = CertificateDer::from(vec![1, 2, 3]);
        let intermediate = CertificateDer::from(vec![4, 5, 6]);
        let name = ServerName::try_from("example.com").unwrap();
        assert!(
            verifier
                .verify_server_cert(&leaf, &[intermediate.clone()], &name, &[], UnixTime::now())
                .is_ok()
        );
        let presented = presented.lock().unwrap();
        assert_eq!(presented.certificates, [leaf, intermediate]);
        assert!(matches!(
            presented.verification,
            Some(Err(rustls::Error::InvalidCertificate(_)))
        ));
    }

    #[tokio::test]
    #[ignore = "requires network access to example.com on TCP port 443"]
    async fn retrieves_a_verified_chain_over_tls() {
        let stream = tokio::time::timeout(
            Duration::from_secs(5),
            TcpStream::connect(("example.com", 443)),
        )
        .await
        .unwrap()
        .unwrap();
        let name = server_name("example.com").unwrap();
        let (report, _) = inspect(stream, name, Instant::now() + Duration::from_secs(5)).await;
        assert_eq!(report.handshake, Ok(()));
        assert_eq!(report.presented.verification, Some(Ok(())));
        assert!(!report.presented.certificates.is_empty());
        assert!(
            x509_parser::parse_x509_certificate(report.presented.certificates[0].as_ref()).is_ok()
        );
    }
}
