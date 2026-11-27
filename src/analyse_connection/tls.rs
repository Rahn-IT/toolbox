use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use hickory_client::proto::rr::Name;
use iced::{Alignment, Element, widget::row};
use tokio::net::TcpStream;
use tokio_rustls::{
    TlsConnector, rustls,
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
    Protocol,
    check_view::{badge, checking},
    port_connectivity::Message,
};

#[derive(Clone)]
pub(super) struct Request {
    host: String,
    https: bool,
}

impl Request {
    fn server_name(&self) -> Result<ServerName<'static>, String> {
        if let Ok(ip) = self.host.trim_matches(['[', ']']).parse::<IpAddr>() {
            return Ok(ip.into());
        }
        let name = Name::from_utf8(&self.host).map_err(|error| error.to_string())?;
        ServerName::try_from(name.to_ascii().trim_end_matches('.').to_owned())
            .map_err(|error| error.to_string())
    }
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
}

#[derive(Default)]
pub(super) enum State {
    #[default]
    Disabled,
    Waiting(Request),
    Checking,
    Complete(Report),
}

impl State {
    pub fn new(host: &str, protocol: Option<Protocol>) -> Self {
        match protocol {
            Some(Protocol::Tls | Protocol::Https) => Self::Waiting(Request {
                host: host.into(),
                https: protocol == Some(Protocol::Https),
            }),
            _ => Self::Disabled,
        }
    }

    pub fn request(&self) -> Option<Request> {
        match self {
            Self::Waiting(request) => Some(request.clone()),
            _ => None,
        }
    }

    pub fn start(&mut self) {
        if matches!(self, Self::Waiting(_)) {
            *self = Self::Checking;
        }
    }

    pub fn finish(&mut self, report: Report) {
        if matches!(self, Self::Checking) {
            *self = Self::Complete(report);
        }
    }

    pub fn is_running(&self) -> bool {
        matches!(self, Self::Checking)
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
                    (Ok(()), _) => badge("Verified", true),
                    (_, Some(Err(error))) => badge(verification_failure(error), false),
                    (Err(_), _) => badge("TLS failed", false),
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

pub(super) async fn inspect(stream: TcpStream, request: Request) -> Report {
    let presented = Arc::new(Mutex::new(PresentedCertificate::default()));
    let handshake = handshake(stream, request, Arc::clone(&presented)).await;
    let presented =
        std::mem::take(&mut *presented.lock().unwrap_or_else(|error| error.into_inner()));
    Report {
        presented,
        handshake,
    }
}

async fn handshake(
    stream: TcpStream,
    request: Request,
    presented: Arc<Mutex<PresentedCertificate>>,
) -> Result<(), String> {
    let server_name = request.server_name()?;
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let verifier = WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|error| error.to_string())?;
    let verifier = Arc::new(CaptureVerifier {
        verifier,
        presented,
    });
    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    if request.https {
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    }
    let connector = TlsConnector::from(Arc::new(config));
    tokio::time::timeout(
        Duration::from_secs(5),
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| "TLS handshake timed out".to_owned())?
    .map(|_| ())
    .map_err(|error| error.to_string())
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
        result
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
    use super::*;

    #[test]
    fn keeps_the_chain_when_webpki_rejects_it() {
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
        let error = verifier
            .verify_server_cert(&leaf, &[intermediate.clone()], &name, &[], UnixTime::now())
            .unwrap_err();
        let presented = presented.lock().unwrap();
        assert_eq!(presented.certificates, [leaf, intermediate]);
        assert_eq!(presented.verification, Some(Err(error)));
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
        let request = State::new("example.com", Some(Protocol::Https))
            .request()
            .unwrap();
        let report = inspect(stream, request).await;
        assert_eq!(report.handshake, Ok(()));
        assert_eq!(report.presented.verification, Some(Ok(())));
        assert!(!report.presented.certificates.is_empty());
        assert!(
            x509_parser::parse_x509_certificate(report.presented.certificates[0].as_ref()).is_ok()
        );
    }
}
