//! Public authentication input/output metadata, independently recorded from Go.
#[path = "support/auth_dns.rs"]
mod auth_dns;
use base64::Engine;
use std::sync::Arc;
/// Recorded Go verdicts that remain valid under the secure verifier. Cases whose
/// Go result was a fixed bug are listed in `oracle/divergences.json` (their secure
/// behaviour is asserted in `secfix_inbound.rs`).
#[tokio::test]
async fn dkim_verdicts_unchanged_by_the_security_fixes_match_go() {
    let diverged: serde_json::Value =
        serde_json::from_str(include_str!("../oracle/divergences.json")).unwrap();
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("../oracle/dkim-vectors-go.json")).unwrap();
    let mut compared = 0;
    for case in cases.as_array().unwrap() {
        if diverged.as_array().unwrap().iter().any(|r| {
            r["case"] == case["name"]
                && r["corpus"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|c| c == "dkim-vectors-go.json")
        }) {
            continue;
        }
        let auth = setjoin_smtp::mail_auth::MailAuth::new(
            Default::default(),
            Arc::new(auth_dns::FixtureDns(case["dns"].clone())),
        );
        let raw = base64::engine::general_purpose::STANDARD
            .decode(case["raw_base64"].as_str().unwrap())
            .unwrap();
        let got = auth.verify_dkim(&raw).await;
        assert_eq!(
            got.result,
            case["result"].as_str().unwrap(),
            "{}",
            case["name"]
        );
        compared += 1;
    }
    assert!(
        compared >= 6,
        "too few unchanged vectors compared: {compared}"
    );
}

#[tokio::test]
async fn network_dns_preserves_txt_records_and_go_mx_priority() {
    use hickory_resolver::{
        config::{NameServerConfig, ResolverConfig},
        net::runtime::TokioRuntimeProvider,
        proto::{
            op::{Message, ResponseCode},
            rr::{
                rdata::{MX, TXT},
                Name, RData, Record, RecordType,
            },
        },
    };
    use setjoin_smtp::mail_auth::{Dns, DnsError, DnsType, SystemDns};
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    struct Peer(tokio::task::JoinHandle<()>);
    impl Drop for Peer {
        fn drop(&mut self) {
            self.0.abort()
        }
    }
    let _peer = Peer(tokio::spawn(async move {
        let mut buffer = [0; 4096];
        loop {
            let (n, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let query = Message::from_vec(&buffer[..n]).unwrap();
            let question = &query.queries[0];
            let mut reply = Message::response(query.metadata.id, query.metadata.op_code);
            reply.metadata.recursion_available = true;
            reply.add_query(question.clone());
            let name = question.name.to_utf8();
            let records = match (name.as_str(), question.query_type) {
                ("txt.smtp2.test.", RecordType::TXT) => vec![
                    RData::TXT(TXT::new(vec![
                        "v=spf1 ".into(),
                        "ip4:127.0.0.1 -all".into(),
                    ])),
                    RData::TXT(TXT::new(vec!["unrelated".into()])),
                ],
                ("mx.smtp2.test.", RecordType::MX) => vec![
                    RData::MX(MX::new(100, Name::from_ascii("late.test.").unwrap())),
                    RData::MX(MX::new(10, Name::from_ascii("early.test.").unwrap())),
                ],
                ("nodata.smtp2.test.", _) => vec![],
                ("temporary.smtp2.test.", _) => {
                    reply.metadata.response_code = ResponseCode::ServFail;
                    vec![]
                }
                _ => {
                    reply.metadata.response_code = ResponseCode::NXDomain;
                    vec![]
                }
            };
            for data in records {
                reply.add_answer(Record::from_rdata(question.name.clone(), 30, data));
            }
            socket
                .send_to(&reply.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    }));
    let mut server = NameServerConfig::udp(addr.ip());
    for connection in &mut server.connections {
        connection.port = addr.port()
    }
    let resolver = hickory_resolver::Resolver::builder_with_config(
        ResolverConfig::from_name_servers(vec![server]),
        TokioRuntimeProvider::default(),
    )
    .build()
    .unwrap();
    let dns = SystemDns::from_resolver(resolver);
    assert_eq!(
        dns.lookup(DnsType::Txt, "txt.smtp2.test").await.unwrap(),
        vec!["v=spf1 ip4:127.0.0.1 -all", "unrelated"]
    );
    assert_eq!(
        dns.lookup(DnsType::Txt, "missing.smtp2.test").await,
        Err(DnsError::NotFound)
    );
    assert_eq!(
        dns.lookup(DnsType::Txt, "nodata.smtp2.test").await,
        Err(DnsError::NotFound)
    );
    assert_eq!(
        dns.lookup(DnsType::Txt, "temporary.smtp2.test").await,
        Err(DnsError::Temporary)
    );
    assert_eq!(
        dns.lookup(DnsType::Mx, "mx.smtp2.test").await.unwrap(),
        vec!["early.test.", "late.test."]
    );
}
