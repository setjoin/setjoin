//! Certificate/key seams: the ACME worker publishes only a pending RFC 8737 challenge.
use rcgen::PublicKeyData;
use setjoin_acme::{keys::CertKey, TlsAlpnStore};
use sha2::{Digest, Sha256};
use x509_parser::prelude::FromDer;

#[test]
fn pending_alpn_certificate_uses_p256_and_critical_digest_extension() {
    let store = TlsAlpnStore::default();
    assert!(store.get("localhost").is_none());
    let pending = store
        .present("LOCALHOST.", "token.account-thumbprint")
        .unwrap();
    let blob = store.get("localhost").unwrap();
    let blocks = pem::parse_many(blob.as_slice()).unwrap();
    assert_eq!(blocks[0].tag(), "PRIVATE KEY");
    let (_, cert) = x509_parser::parse_x509_certificate(blocks[1].contents()).unwrap();
    assert_eq!(
        cert.subject_alternative_name()
            .unwrap()
            .unwrap()
            .value
            .general_names
            .len(),
        1
    );
    assert_eq!(
        cert.subject()
            .iter_common_name()
            .next()
            .unwrap()
            .as_str()
            .unwrap(),
        "ACME Challenge TEMP"
    );
    assert_eq!(cert.key_usage().unwrap().unwrap().value.flags, 4);
    assert!((364 * 86400..=367 * 86400).contains(
        &(cert.validity().not_after.timestamp() - cert.validity().not_before.timestamp())
    ));
    let ext = cert
        .extensions()
        .iter()
        .find(|e| e.oid.to_id_string() == "1.3.6.1.5.5.7.1.31")
        .unwrap();
    assert!(ext.critical);
    assert_eq!(&ext.value[..2], &[4, 32]);
    assert_eq!(
        &ext.value[2..],
        &Sha256::digest(b"token.account-thumbprint")[..]
    );
    assert!(CertKey::from_blob(&blob).unwrap().algorithm() == &rcgen::PKCS_ECDSA_P256_SHA256);
    drop(pending);
    assert!(
        store.get("localhost").is_none(),
        "cancellation/failure must withdraw the challenge"
    );
}

#[test]
fn certificate_request_matches_go_subject_and_sans_with_p256_signature() {
    let key = CertKey::generate().unwrap();
    assert!(key.algorithm() == &rcgen::PKCS_ECDSA_P256_SHA256);
    let csr = key
        .request(&["one.example.test".into(), "two.example.test".into()])
        .unwrap();
    let (_, request) =
        x509_parser::certification_request::X509CertificationRequest::from_der(&csr).unwrap();
    assert_eq!(
        request.signature_algorithm.algorithm.to_id_string(),
        "1.2.840.10045.4.3.2"
    );
    assert_eq!(
        request
            .certification_request_info
            .subject_pki
            .algorithm
            .algorithm
            .to_id_string(),
        "1.2.840.10045.2.1"
    );
    assert_eq!(
        request
            .certification_request_info
            .subject_pki
            .algorithm
            .parameters
            .as_ref()
            .unwrap()
            .as_oid()
            .unwrap()
            .to_id_string(),
        "1.2.840.10045.3.1.7"
    );
    assert_eq!(
        request.certification_request_info.subject.to_string(),
        "CN=one.example.test"
    );
    assert!(request.requested_extensions().unwrap().any(|e|matches!(e,x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) if san.general_names.len()==2)));
}
