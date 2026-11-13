//! Exercise the production TLSA adapter against a real UDP DNS peer.
use hickory_resolver::proto::{
    op::{Message, OpCode},
    rr::{rdata::TLSA, Name, RData, Record},
};
use setjoin_smtp::outbound::transport::{SystemTlsa, TlsaLookup};

#[tokio::test]
async fn tlsa_wire_requests_dnssec_and_preserves_authenticated_absence_and_failures() {
    for (ad, rcode, records) in [
        (true, 0, true),
        (false, 2, false),
        (false, 3, false),
        (true, 3, false),
        (true, 2, true),
    ] {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver = SystemTlsa::from_nameserver(socket.local_addr().unwrap());
        let peer = tokio::spawn(async move {
            let mut buffer = [0; 4096];
            let (n, from) = socket.recv_from(&mut buffer).await.unwrap();
            let request = Message::from_vec(&buffer[..n]).unwrap();
            assert!(request.metadata.recursion_desired);
            assert!(request.edns.as_ref().unwrap().flags().dnssec_ok);
            assert_eq!(request.edns.as_ref().unwrap().max_payload(), 1232);
            assert_eq!(
                request.queries[0].name.to_utf8(),
                "_25._tcp.mx.example.test."
            );
            let mut response = Message::response(request.metadata.id, OpCode::Query);
            response.metadata.authentic_data = ad;
            response.metadata.response_code = rcode.into();
            response.add_query(request.queries[0].clone());
            if records {
                for (usage, data) in [(3, vec![1, 2, 3]), (255, vec![])] {
                    response.add_answer(Record::from_rdata(
                        Name::from_ascii("_25._tcp.mx.example.test.").unwrap(),
                        60,
                        RData::TLSA(TLSA::new(usage.into(), 1.into(), 2.into(), data)),
                    ));
                }
            }
            socket
                .send_to(&response.to_vec().unwrap(), from)
                .await
                .unwrap();
        });
        let answer = tokio::time::timeout(
            std::time::Duration::from_secs(6),
            resolver.lookup("mx.example.test."),
        )
        .await
        .unwrap()
        .unwrap();
        peer.await.unwrap();
        assert_eq!((answer.authenticated, answer.rcode), (ad, rcode));
        assert_eq!(answer.records.len(), if records { 2 } else { 0 });
        if records {
            assert_eq!(answer.records[0].association, vec![1, 2, 3]);
            assert_eq!(answer.records[1].usage, 255);
            assert!(answer.records[1].association.is_empty());
        }
    }
}
