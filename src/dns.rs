use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use futures_util::StreamExt;
use hickory_client::{
    client::Client,
    proto::{
        h2::HttpsClientStreamBuilder,
        op::{Message, Query},
        rr::{Name, RecordType},
        runtime::TokioRuntimeProvider,
        tcp::TcpClientStream,
        udp::UdpClientStream,
        xfer::{DnsHandle, DnsResponse},
    },
};
use tokio_rustls::rustls;

const TIMEOUT: Duration = Duration::from_secs(3);
pub(crate) mod dnssec;

pub(crate) async fn system_lookup(host: String) -> Result<Vec<IpAddr>, String> {
    let lookup = tokio::time::timeout(TIMEOUT, tokio::net::lookup_host((host.as_str(), 0))).await;
    match lookup {
        Ok(Ok(addresses)) => {
            let mut seen = BTreeSet::new();
            Ok(addresses
                .map(|address| address.ip())
                .filter(|ip| seen.insert(*ip))
                .collect())
        }
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err("Timed out".into()),
    }
}

#[cfg(unix)]
pub(crate) async fn configured_server() -> Result<Option<SocketAddr>, String> {
    let (config, _) =
        hickory_resolver::system_conf::read_system_conf().map_err(|error| error.to_string())?;
    Ok(config.name_servers().first().and_then(|server| {
        server
            .connections
            .first()
            .map(|connection| SocketAddr::new(server.ip, connection.port))
    }))
}

#[cfg(windows)]
pub(crate) async fn configured_server() -> Result<Option<SocketAddr>, String> {
    use std::net::{IpAddr, SocketAddrV6};

    let adapter = crate::windows_network::default_adapter()
        .await?
        .ok_or_else(|| "No active adapter with a default route found.".to_owned())?;
    Ok(adapter.dns_servers().first().map(|&ip| match ip {
        IpAddr::V6(ip) if ip.is_unicast_link_local() => {
            SocketAddrV6::new(ip, 53, 0, adapter.ipv6_if_index()).into()
        }
        _ => SocketAddr::new(ip, 53),
    }))
}

#[cfg(not(any(unix, windows)))]
pub(crate) async fn configured_server() -> Result<Option<SocketAddr>, String> {
    Err("Reading the configured DNS server is unavailable on this platform.".into())
}

#[derive(Clone, Copy)]
pub(crate) enum Server {
    Plain(SocketAddr),
    Https(SocketAddr, &'static str),
}

impl Server {
    pub(crate) async fn signed_material(
        self,
        name: Name,
        record_type: RecordType,
    ) -> Result<DnsResponse, String> {
        let mut request = Message::new();
        let mut edns = hickory_client::proto::op::Edns::new();
        edns.set_dnssec_ok(true);
        request
            .add_query(Query::query(name, record_type))
            .set_recursion_desired(true)
            .set_edns(edns);
        tokio::time::timeout(TIMEOUT, self.exchange(request))
            .await
            .map_err(|_| "Timed out".to_owned())?
    }

    pub(crate) async fn query(
        self,
        name: Name,
        record_type: RecordType,
        recursive: bool,
    ) -> Result<DnsResponse, String> {
        let mut request = Message::new();
        request
            .add_query(Query::query(name, record_type))
            .set_recursion_desired(recursive);

        tokio::time::timeout(TIMEOUT, self.exchange(request))
            .await
            .map_err(|_| "Timed out".to_owned())?
    }

    async fn exchange(self, request: Message) -> Result<DnsResponse, String> {
        let provider = TokioRuntimeProvider::default();
        match self {
            Self::Plain(address) => {
                let stream = UdpClientStream::builder(address, provider.clone()).build();
                let (client, background) = Client::connect(stream).await.map_err(error_text)?;
                tokio::spawn(background);
                let response = answer(&client, request.clone()).await?;
                if !response.truncated() {
                    return Ok(response);
                }

                let (stream, handle) = TcpClientStream::new(address, None, Some(TIMEOUT), provider);
                let (client, background) = Client::new(stream, handle, None)
                    .await
                    .map_err(error_text)?;
                tokio::spawn(background);
                answer(&client, request).await
            }
            Self::Https(address, hostname) => {
                // Trust bundled public roots so a locally installed interception CA
                // cannot authenticate a replacement resolver certificate.
                let roots = rustls::RootCertStore::from_iter(
                    webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
                );
                let tls = rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                let stream = HttpsClientStreamBuilder::with_client_config(Arc::new(tls), provider)
                    .build(address, hostname.into(), "/dns-query".into());
                let (client, background) = Client::connect(stream).await.map_err(error_text)?;
                tokio::spawn(background);
                answer(&client, request).await
            }
        }
    }
}

async fn answer(client: &Client, request: Message) -> Result<DnsResponse, String> {
    client
        .send(request)
        .next()
        .await
        .ok_or_else(|| "DNS server returned no response".to_owned())?
        .map_err(error_text)
}

fn error_text(error: hickory_client::proto::ProtoError) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_client::proto::op::{MessageType, ResponseCode};
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn direct_lookup_uses_the_selected_server_without_recursion() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let mut buffer = [0; 512];
            let (size, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let mut message = Message::from_vec(&buffer[..size]).unwrap();
            assert!(!message.recursion_desired());
            assert_eq!(message.queries()[0].query_type(), RecordType::AAAA);
            message
                .set_message_type(MessageType::Response)
                .set_authoritative(true)
                .set_response_code(ResponseCode::NXDomain);
            socket
                .send_to(&message.to_vec().unwrap(), peer)
                .await
                .unwrap();
        });
        let response = Server::Plain(address)
            .query(
                Name::from_ascii("example.test.").unwrap(),
                RecordType::AAAA,
                false,
            )
            .await
            .unwrap();
        assert!(response.authoritative());
        assert_eq!(response.response_code(), ResponseCode::NXDomain);
        responder.await.unwrap();
    }
}
