use std::{
    task::{Context, Poll},
    time::{SystemTime, UNIX_EPOCH},
};

use hickory_resolver::{
    net::xfer::{DnsRequestSender, DnsResponseStream},
    proto::{
        dnssec::{
            Algorithm, DigestType, SigningKey, TBS, TrustAnchors, crypto::Ed25519SigningKey,
            rdata::SigInput,
        },
        rr::rdata::{A, NS},
    },
};

use super::*;

struct Authority {
    records: HashMap<(Name, RecordType), Vec<Record>>,
    denials: HashMap<Name, Vec<Record>>,
}

impl Stream for Authority {
    type Item = Result<(), NetError>;

    fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Pending
    }
}

impl DnsRequestSender for Authority {
    fn send_message(&mut self, request: DnsRequest) -> DnsResponseStream {
        let response = self.reply(&request);
        Box::pin(async move { DnsResponse::from_message(response).map_err(NetError::from) }).into()
    }

    fn shutdown(&mut self) {}

    fn is_shutdown(&self) -> bool {
        false
    }
}

impl Authority {
    fn reply(&self, request: &Message) -> Message {
        assert!(request.metadata.checking_disabled);
        assert!(request.edns.as_ref().unwrap().flags().dnssec_ok);
        let question = request.queries[0].clone();
        let mut response = Message::response(request.id, request.op_code);
        response.add_query(question.clone());
        response.metadata.authentic_data = true;
        if let Some(records) = self
            .records
            .get(&(question.name().clone(), question.query_type()))
        {
            response.add_answers(records.clone());
        }
        if question.query_type() == RecordType::DS
            && let Some(denial) = self.denials.get(question.name())
        {
            response.authorities = denial.clone();
        }
        response
    }
}

fn key() -> Ed25519SigningKey {
    Ed25519SigningKey::from_pkcs8(&Ed25519SigningKey::generate_pkcs8().unwrap()).unwrap()
}

fn sign(record: &Record, zone: &Name, key: &Ed25519SigningKey, public: &DNSKEY) -> Record {
    sign_set(std::slice::from_ref(record), zone, key, public)
}

fn sign_set(records: &[Record], zone: &Name, key: &Ed25519SigningKey, public: &DNSKEY) -> Record {
    let record = &records[0];
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let input = SigInput {
        type_covered: record.record_type(),
        algorithm: Algorithm::ED25519,
        num_labels: record.name.num_labels(),
        original_ttl: record.ttl,
        sig_inception: (now - 600).into(),
        sig_expiration: (now + 600).into(),
        key_tag: public.calculate_key_tag().unwrap(),
        signer_name: zone.clone(),
    };
    let tbs = TBS::from_input(&record.name, record.dns_class, &input, records.iter()).unwrap();
    let rrsig = RRSIG::from_sig(input, key.sign(&tbs).unwrap());
    Record::from_rdata(record.name.clone(), record.ttl, rrsig).into_record_of_rdata()
}

enum Answer {
    Signed,
    MissingSignature,
    Unsigned,
}

fn authority(zone: &Name, answer: Answer) -> (Authority, Arc<TrustAnchors>) {
    let root = Name::root();
    let root_key = key();
    let child_key = key();
    let record_key = key();
    let root_public = root_key.to_public_key().unwrap();
    let child_public = child_key.to_public_key().unwrap();
    let root_dnskey = DNSKEY::from_key(&root_public);
    let child_dnskey = DNSKEY::from_key(&child_public);
    let record_dnskey = DNSKEY::from_key(&record_key.to_public_key().unwrap());
    let child_ds = DS::from_key(&child_public, zone, DigestType::SHA256).unwrap();
    let root_record: Record =
        Record::from_rdata(root.clone(), 300, root_dnskey.clone()).into_record_of_rdata();
    let child_record: Record =
        Record::from_rdata(zone.clone(), 300, child_dnskey.clone()).into_record_of_rdata();
    let record_key_record =
        Record::from_rdata(zone.clone(), 300, record_dnskey.clone()).into_record_of_rdata();
    let ds_record: Record = Record::from_rdata(zone.clone(), 300, child_ds).into_record_of_rdata();
    let address: Record =
        Record::from_rdata(zone.clone(), 300, A::new(192, 0, 2, 1)).into_record_of_rdata();
    let mut addresses = vec![address.clone()];
    if matches!(answer, Answer::Signed) {
        addresses.push(sign(&address, zone, &record_key, &record_dnskey));
    }
    let mut child_keys = vec![child_record, record_key_record];
    child_keys.push(sign_set(&child_keys, zone, &child_key, &child_dnskey));
    let mut records = HashMap::from([
        ((root.clone(), RecordType::DNSKEY), vec![root_record]),
        ((zone.clone(), RecordType::DNSKEY), child_keys),
        (
            (zone.clone(), RecordType::DS),
            vec![sign(&ds_record, &root, &root_key, &root_dnskey), ds_record],
        ),
        (
            (zone.clone(), RecordType::NS),
            vec![
                Record::from_rdata(
                    zone.clone(),
                    300,
                    NS(Name::from_ascii("ns.example.").unwrap()),
                )
                .into_record_of_rdata(),
            ],
        ),
        ((zone.clone(), RecordType::A), addresses),
    ]);
    let mut denials = HashMap::new();
    if matches!(answer, Answer::Unsigned) {
        records.remove(&(zone.clone(), RecordType::DS));
        records.remove(&(zone.clone(), RecordType::DNSKEY));
        let nsec = Record::from_rdata(
            zone.clone(),
            300,
            NSEC::new(
                Name::from_ascii("next.").unwrap(),
                [RecordType::NS, RecordType::NSEC, RecordType::RRSIG],
            ),
        )
        .into_record_of_rdata();
        denials.insert(
            zone.clone(),
            vec![sign(&nsec, &root, &root_key, &root_dnskey), nsec],
        );
    }
    let mut anchors = TrustAnchors::empty();
    anchors.insert(&root_public);
    (Authority { records, denials }, Arc::new(anchors))
}

fn session(zone: &Name, answer: Answer) -> Session {
    let (authority, anchors) = authority(zone, answer);
    let (client, driver) = Client::from_sender(authority);
    test_session(client, tokio::spawn(driver), anchors, None)
}

fn test_session(
    client: Client<TokioRuntimeProvider>,
    driver: tokio::task::JoinHandle<()>,
    anchors: Arc<TrustAnchors>,
    tcp_fallback: Option<SocketAddr>,
) -> Session {
    let deadline = Instant::now() + Duration::from_secs(2);
    Session {
        validator: DnssecDnsHandle::with_trust_anchor(
            Bounded {
                client,
                tcp_fallback,
                deadline,
                queries: Arc::new(AtomicUsize::new(0)),
            },
            anchors,
        ),
        deadline,
        replies: HashMap::new(),
        zones: HashMap::new(),
        _driver: AbortOnDropHandle::new(driver),
    }
}

#[tokio::test]
async fn verifies_the_signer_and_detects_a_stripped_signature_under_secure_ds() {
    let zone = Name::from_ascii("example.").unwrap();
    let mut details = Vec::new();
    let signed = session(&zone, Answer::Signed)
        .family(zone.clone(), RecordType::A, &mut details)
        .await;
    assert_eq!(signed, Verdict::Validated, "{details:?}");
    assert!(
        details
            .iter()
            .any(|finding| finding.kind == FindingKind::DelegationVerified),
        "{details:?}"
    );
    assert!(
        details
            .iter()
            .any(|finding| finding.kind == FindingKind::RecordVerified),
        "{details:?}"
    );

    details.clear();
    let stripped = session(&zone, Answer::MissingSignature)
        .family(zone, RecordType::A, &mut details)
        .await;
    assert_eq!(stripped, Verdict::MissingSignature, "{details:?}");
}

#[tokio::test]
async fn authenticated_parent_denial_distinguishes_an_unsigned_child() {
    let zone = Name::from_ascii("example.").unwrap();
    let mut details = Vec::new();
    let unsigned = session(&zone, Answer::Unsigned)
        .family(zone, RecordType::A, &mut details)
        .await;
    assert_eq!(unsigned, Verdict::Unsigned, "{details:?}");
}

#[tokio::test]
async fn configured_dns_reports_signatures_from_tcp_after_a_truncated_udp_reply() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let udp = UdpSocket::bind(endpoint).await.unwrap();
    let zone = Name::from_ascii("example.").unwrap();
    let address =
        Record::from_rdata(zone.clone(), 300, A::new(192, 0, 2, 1)).into_record_of_rdata();
    let signer = key();
    let dnskey = DNSKEY::from_key(&signer.to_public_key().unwrap());
    let rrsig = sign(&address, &zone, &signer, &dnskey);
    let response = |bytes: &[u8]| {
        let message = Message::from_vec(bytes).unwrap();
        assert!(!message.metadata.checking_disabled);
        assert!(message.edns.as_ref().unwrap().flags().dnssec_ok);
        let mut response = Message::response(message.id, message.op_code);
        response.add_queries(message.queries);
        response
    };
    let server = async move {
        let mut packet = [0; 512];
        let (length, peer) = udp.recv_from(&mut packet).await.unwrap();
        let mut truncated = response(&packet[..length]);
        truncated.metadata.truncation = true;
        udp.send_to(&truncated.to_vec().unwrap(), peer)
            .await
            .unwrap();

        let (mut tcp, _) = listener.accept().await.unwrap();
        let mut packet = vec![0; usize::from(tcp.read_u16().await.unwrap())];
        tcp.read_exact(&mut packet).await.unwrap();
        let mut full = response(&packet);
        full.add_answers([address, rrsig]);
        let bytes = full.to_vec().unwrap();
        tcp.write_u16(bytes.len() as u16).await.unwrap();
        tcp.write_all(&bytes).await.unwrap();
    };
    let (details, ()) = tokio::time::timeout(Duration::from_secs(4), async {
        tokio::join!(observe_family(endpoint, zone, RecordType::A), server)
    })
    .await
    .unwrap();
    assert_eq!(
        details,
        [Finding {
            answer: None,
            kind: FindingKind::SignaturesReturned,
            subject: "example. A".into(),
        }]
    );
}

#[tokio::test]
async fn validates_configured_dns_signatures_after_tcp_fallback() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let udp = UdpSocket::bind(endpoint).await.unwrap();
    let zone = Name::from_ascii("example.").unwrap();
    let (authority, anchors) = authority(&zone, Answer::Signed);
    let datagrams = async {
        let mut packet = [0; 4096];
        loop {
            let (length, peer) = udp.recv_from(&mut packet).await.unwrap();
            let request = Message::from_vec(&packet[..length]).unwrap();
            let mut reply = authority.reply(&request);
            if request.queries[0].query_type() == RecordType::A {
                reply.answers.clear();
                reply.metadata.truncation = true;
            }
            udp.send_to(&reply.to_vec().unwrap(), peer).await.unwrap();
        }
    };
    let stream = async {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut packet = vec![0; usize::from(socket.read_u16().await.unwrap())];
        socket.read_exact(&mut packet).await.unwrap();
        let request = Message::from_vec(&packet).unwrap();
        assert_eq!(request.queries[0].query_type(), RecordType::A);
        let reply = authority.reply(&request).to_vec().unwrap();
        socket.write_u16(reply.len() as u16).await.unwrap();
        socket.write_all(&reply).await.unwrap();
    };
    let transport = UdpClientStream::builder(endpoint, TokioRuntimeProvider::default()).build();
    let (client, driver) = Client::from_sender(transport);
    let mut session = test_session(client, tokio::spawn(driver), anchors, Some(endpoint));
    let mut details = Vec::new();
    let (result, ()) = tokio::select! {
        result = async { tokio::join!(session.family(zone, RecordType::A, &mut details), stream) } => result,
        _ = datagrams => unreachable!("loopback responder runs until the diagnostic completes"),
    };
    assert_eq!(result, Verdict::Validated, "{details:?}");
}
