//! Independently specified wire expectations; all signatures are synthetic zeros.
//! Fixture bytes and goldens were authored without running the candidate parser.
use schema_adapter_simulation::canonical::*;

const W00: &[u8] = include_bytes!("../../fixtures/canonical-w00.json");
const BODY: &[u8] = include_bytes!("../../fixtures/canonical-w00-body.json");
const CORE: &[u8] = include_bytes!("../../fixtures/canonical-w00-core.json");
const MAXIMUM: &[u8] = include_bytes!("../../fixtures/canonical-maximum.json");
const SCHEMA_MAXIMUM: &[u8] = include_bytes!("../../fixtures/canonical-schema-maximum.json");
const POSTURE_MAXIMUM: &[u8] = include_bytes!("../../fixtures/canonical-posture-maximum.json");
const SET_MAXIMUM: &[u8] = include_bytes!("../../fixtures/canonical-set-maximum.json");

fn replace(bytes: &[u8], from: &str, to: &str) -> Vec<u8> {
    let text = std::str::from_utf8(bytes).unwrap();
    assert!(
        text.contains(from),
        "independent mutation must find its source"
    );
    text.replacen(from, to, 1).into_bytes()
}
fn signatures(ids: &[String]) -> Vec<u8> {
    let body = std::str::from_utf8(BODY).unwrap();
    let records: Vec<String> = ids
        .iter()
        .map(|id| {
            format!(
                "{{\"key_id\":\"{id}\",\"algorithm\":\"ed25519\",\"value\":\"{}\"}}",
                "A".repeat(86)
            )
        })
        .collect();
    format!(
        "{},\"signatures\":[{}]}}",
        &body[..body.len() - 1],
        records.join(",")
    )
    .into_bytes()
}

#[test]
fn canonical_wire_boundaries() {
    let minimal = include_bytes!("../../fixtures/canonical-minimal.json");
    let parsed = parse_attestation(minimal).unwrap();
    assert_eq!(minimal.len(), 1029);
    assert_eq!(parsed.number("schema_version"), Ok(1));
    assert_eq!(parsed.signatures.len(), 2);
    assert_eq!(parsed.canonical_bytes().unwrap(), minimal.as_slice());
    let maximal = parse_attestation(MAXIMUM).unwrap();
    assert_eq!(MAXIMUM.len(), 5362);
    assert_eq!(maximal.signatures.len(), 16);
    assert_eq!(maximal.number("schema_version"), Ok(u64::MAX));
    assert_eq!(maximal.number("not_before"), Ok(u64::MAX - 1));
    assert_eq!(maximal.number("expires_at"), Ok(u64::MAX));
    assert_eq!(maximal.canonical_bytes().unwrap(), MAXIMUM);
    for (size, expected) in [
        (5363, WireError::StructuralLimit),
        (16384, WireError::StructuralLimit),
        (16385, WireError::TransportLimit),
    ] {
        // Whitespace cannot reach the grammar because preflight limits win.
        assert_eq!(parse_attestation(&vec![b' '; size]), Err(expected));
    }
    let ids: Vec<String> = (0..17).map(|i| format!("k{i:02}")).collect();
    assert_eq!(
        parse_attestation(&signatures(&ids)),
        Err(WireError::SignatureCount)
    );
    assert!(parse_attestation(&signatures(&ids[..16])).is_ok());
    assert_eq!(
        parse_attestation(&signatures(&ids[..1])),
        Err(WireError::SignatureCount)
    );
    assert_eq!(
        parse_attestation(&signatures(&[])),
        Err(WireError::SignatureCount)
    );
    assert_eq!(
        parse_attestation(&signatures(&["a".into(), "a".into()])),
        Err(WireError::SignatureOrder)
    );
    assert_eq!(
        parse_attestation(&signatures(&["b".into(), "a".into()])),
        Err(WireError::SignatureOrder)
    );
    assert!(parse_attestation(&signatures(&["a".repeat(128), "b".repeat(128)])).is_ok());
    assert_eq!(
        parse_attestation(&signatures(&["a".repeat(129), "b".into()])),
        Err(WireError::FieldLimit)
    );
    assert_eq!(
        parse_attestation(br#"{"signatures":[{"value":{}}]}"#),
        Err(WireError::DepthLimit)
    );
    assert!(parse_attestation(W00).is_ok(), "depth-three restore");
    for (key, old) in [
        ("schema_version", "10"),
        ("read_lower", "8"),
        ("read_upper", "12"),
        ("write_lower", "8"),
        ("write_upper", "12"),
        ("metadata_sequence", "1"),
        ("trust_generation", "1"),
        ("not_before", "0"),
        ("expires_at", "100"),
    ] {
        let broken = replace(
            W00,
            &format!("\"{key}\":\"{old}\""),
            &format!("\"{key}\":\"18446744073709551616\""),
        );
        assert_eq!(
            parse_attestation(&broken),
            Err(WireError::InvalidScalar),
            "overflow {key}"
        );
    }
    for number in ["0", "01", "-1", "+1", "1.0", "1e1", ""] {
        let broken = replace(
            W00,
            "\"schema_version\":\"10\"",
            &format!("\"schema_version\":\"{number}\""),
        );
        assert_eq!(
            parse_attestation(&broken),
            Err(WireError::InvalidScalar),
            "numeric {number}"
        );
    }
    for scalar in ["10", "null", "false", "[]", "{}"] {
        let broken = replace(
            W00,
            "\"schema_version\":\"10\"",
            &format!("\"schema_version\":{scalar}"),
        );
        assert!(parse_attestation(&broken).is_err());
    }
    assert_eq!(
        parse_attestation(&replace(W00, &"01".repeat(32), &"00".repeat(32))),
        Err(WireError::InvalidScalar)
    );
    assert_eq!(
        parse_attestation(&replace(W00, &"01".repeat(32), &"AB".repeat(32))),
        Err(WireError::InvalidScalar)
    );
    assert!(
        parse_attestation(W00).is_ok(),
        "valid nonzero digest restore"
    );
    for id in ["", ".bad", "_bad", "-bad", "bad/id", "bad:id"] {
        assert!(
            parse_attestation(&replace(W00, "schema-test-v1", id)).is_err(),
            "identifier {id}"
        );
    }
    assert!(parse_attestation(&replace(W00, "schema-test-v1", "A0.z_-9")).is_ok());
}

#[test]
fn canonical_bytes_are_required() {
    let baseline = parse_attestation(W00).unwrap();
    assert_eq!(baseline.canonical_body().unwrap(), BODY);
    assert_eq!(baseline.profile_core().unwrap(), CORE);
    assert_eq!(baseline.canonical_bytes().unwrap(), W00);
    assert_eq!(
        baseline.fields["profile_id"],
        "5aa30ad2794ce63dd23864150139f45f51c11bd868cd296829c35669e8983601"
    );
    assert_eq!(baseline.identity("binary_sha256"), Ok([1; 32]));
    assert_eq!(baseline.profile_claims().unwrap().schema_identity, [3; 32]);
    let mut newline = W00.to_vec();
    newline.push(b'\n');
    let mut bom = vec![0xef, 0xbb, 0xbf];
    bom.extend_from_slice(W00);
    let mut invalid_utf8 = W00.to_vec();
    invalid_utf8[20] = 0xff;
    let mut trailing = W00.to_vec();
    trailing.extend_from_slice(b"{}");
    let bad = vec![
        replace(W00, "{\"format\"", "{ \"format\""),
        newline,
        bom,
        invalid_utf8,
        trailing,
        replace(W00, "\"format\":\"1\"", "\"format\":\"\\u0031\""),
        replace(
            W00,
            "\"format\":\"1\",\"release_epoch\":\"schema-test-v1\"",
            "\"release_epoch\":\"schema-test-v1\",\"format\":\"1\"",
        ),
        replace(W00, "\"format\":\"1\"", "\"format\":\"1\",\"format\":\"1\""),
        replace(W00, "\"format\":\"1\",", ""),
        replace(W00, "\"format\":\"1\"", "\"format\":\"1\",\"extra\":\"1\""),
        replace(W00, "ed25519", "Ed25519"),
    ];
    for bytes in bad {
        assert!(parse_attestation(&bytes).is_err(), "noncanonical rejection");
    }
    let a86 = "A".repeat(86);
    for last in ["A", "Q", "g", "w"] {
        assert!(parse_attestation(&replace(W00, &a86, &("A".repeat(85) + last))).is_ok());
    }
    for invalid in [
        "A".repeat(85) + "B",
        "A".repeat(85) + "=",
        "A".repeat(85) + "-",
        "A".repeat(85),
        "A".repeat(87),
    ] {
        assert_eq!(
            parse_attestation(&replace(W00, &a86, &invalid)),
            Err(WireError::InvalidScalar)
        );
    }
    assert!(
        parse_attestation(W00).is_ok(),
        "literal W00 restores canonical bytes and last-A Base64"
    );
}

#[test]
fn raw_parser_restorations() {
    let cases: &[&[u8]] = &[
        include_bytes!("../../fixtures/canonical-w01.json"),
        include_bytes!("../../fixtures/canonical-w02.json"),
        include_bytes!("../../fixtures/canonical-w03.json"),
        include_bytes!("../../fixtures/canonical-w04.json"),
        include_bytes!("../../fixtures/canonical-w05.json"),
    ];
    for (index, bytes) in cases.iter().enumerate() {
        let expected = if index == 0 {
            WireError::InvalidScalar
        } else {
            WireError::InvalidInterval
        };
        assert_eq!(
            parse_attestation(bytes),
            Err(expected),
            "W0{} must reject before contextual checks",
            index + 1
        );
        assert!(
            parse_attestation(W00).is_ok(),
            "full restore for W0{}",
            index + 1
        );
    }
    let w06 = parse_attestation(include_bytes!("../../fixtures/canonical-w06.json")).unwrap();
    assert_eq!(
        w06.identity("binary_sha256"),
        Ok([9; 32]),
        "wrong contextual binary is syntactically valid"
    );
    assert_eq!(w06.number("read_lower"), Ok(8));
    let w07a = parse_attestation(include_bytes!("../../fixtures/canonical-w07a.json")).unwrap();
    assert_eq!(
        w07a.identity("posture_identity"),
        Ok([9; 32]),
        "wrong contextual posture is syntactically valid"
    );
    assert_eq!(w07a.number("read_lower"), Ok(8));
    let w07b = parse_attestation(include_bytes!("../../fixtures/canonical-w07b.json")).unwrap();
    assert_eq!(w07b.identity("schema_identity"), Ok([9; 32]));
    assert!(
        parse_attestation(include_bytes!("../../fixtures/canonical-w08a.json")).is_ok(),
        "profile equality is a later stage"
    );
    for broken in [
        replace(W00, "\"read_upper\":\"12\"", "\"read_upper\":\"7\""),
        replace(W00, "\"write_upper\":\"12\"", "\"write_upper\":\"7\""),
        replace(W00, "\"not_before\":\"0\"", "\"not_before\":\"100\""),
        replace(W00, "\"expires_at\":\"100\"", "\"expires_at\":\"0\""),
    ] {
        assert_eq!(parse_attestation(&broken), Err(WireError::InvalidInterval));
    }
    assert!(
        parse_attestation(&replace(
            W00,
            "\"read_lower\":\"8\"",
            "\"read_lower\":\"10\""
        ))
        .is_ok(),
        "inclusive lower"
    );
    assert!(
        parse_attestation(&replace(
            W00,
            "\"write_upper\":\"12\"",
            "\"write_upper\":\"10\""
        ))
        .is_ok(),
        "inclusive upper"
    );
}

#[test]
fn small_descriptors_are_bounded() {
    assert_eq!(SCHEMA_MAXIMUM.len(), 557);
    let schema = parse_schema_descriptor(SCHEMA_MAXIMUM).unwrap();
    assert_eq!(schema.number("schema_version"), Ok(u64::MAX));
    assert_eq!(schema.identity("catalog_contract_sha256"), Ok([4; 32]));
    assert_eq!(schema.canonical_bytes().unwrap(), SCHEMA_MAXIMUM);
    assert_eq!(POSTURE_MAXIMUM.len(), 510);
    let posture = parse_posture_descriptor(POSTURE_MAXIMUM).unwrap();
    assert_eq!(posture.number("postgres_major"), Ok(18));
    assert_eq!(posture.identity("pool_contract_sha256"), Ok([3; 32]));
    assert_eq!(posture.canonical_bytes().unwrap(), POSTURE_MAXIMUM);
    for (size, expected) in [
        (558, WireError::StructuralLimit),
        (1024, WireError::StructuralLimit),
        (1025, WireError::TransportLimit),
    ] {
        let error = parse_schema_descriptor(&vec![b' '; size]).unwrap_err();
        assert_eq!(error, expected);
        let marker = if size > 1024 {
            "evidence.syntax.limit.transport"
        } else {
            "evidence.syntax.limit.structural"
        };
        assert_eq!(error.marker(), marker);
    }
    for (size, expected) in [
        (511, WireError::StructuralLimit),
        (1024, WireError::StructuralLimit),
        (1025, WireError::TransportLimit),
    ] {
        let error = parse_posture_descriptor(&vec![b' '; size]).unwrap_err();
        assert_eq!(error, expected);
        let marker = if size > 1024 {
            "evidence.syntax.limit.transport"
        } else {
            "evidence.syntax.limit.structural"
        };
        assert_eq!(error.marker(), marker);
    }
    assert_eq!(parse_schema_descriptor(b"{}"), Err(WireError::Syntax));
    assert_eq!(
        parse_schema_descriptor(b"{}").unwrap_err().marker(),
        "evidence.syntax.canonical"
    );
    assert_eq!(parse_posture_descriptor(b"{}"), Err(WireError::Syntax));
    assert_eq!(
        parse_posture_descriptor(&replace(
            POSTURE_MAXIMUM,
            "\"postgres_major\":\"18\"",
            "\"postgres_major\":\"17\""
        )),
        Err(WireError::InvalidScalar)
    );
    assert!(
        parse_posture_descriptor(&replace(
            POSTURE_MAXIMUM,
            "\"registry_mode\":\"observe\"",
            "\"registry_mode\":\"enforce\""
        ))
        .is_ok()
    );
    assert!(
        parse_posture_descriptor(&replace(
            POSTURE_MAXIMUM,
            "\"unknown_registry_policy\":\"observe\"",
            "\"unknown_registry_policy\":\"reject\""
        ))
        .is_ok()
    );
    assert_eq!(
        parse_posture_descriptor(&replace(
            POSTURE_MAXIMUM,
            "\"registry_mode\":\"observe\"",
            "\"registry_mode\":\"unknown\""
        )),
        Err(WireError::InvalidScalar)
    );
    assert!(parse_schema_descriptor(SCHEMA_MAXIMUM).is_ok());
    assert!(parse_posture_descriptor(POSTURE_MAXIMUM).is_ok());
}

#[test]
fn sorted_set_descriptors_are_bounded() {
    assert_eq!(SET_MAXIMUM.len(), 876545);
    let records = parse_set_descriptor(SET_MAXIMUM).unwrap();
    assert_eq!(records.len(), 4096);
    assert_eq!(records[0].id, format!("m0000{}", "x".repeat(123)));
    assert_eq!(records[4095].id, format!("m4095{}", "x".repeat(123)));
    assert_eq!(encode_set_descriptor(&records).unwrap(), SET_MAXIMUM);
    for (size, expected) in [
        (876546, WireError::StructuralLimit),
        (1048576, WireError::StructuralLimit),
        (1048577, WireError::TransportLimit),
    ] {
        assert_eq!(parse_set_descriptor(&vec![b' '; size]), Err(expected));
    }
    let count_overflow = include_bytes!("../../fixtures/canonical-set-count4097.json");
    assert!(count_overflow.len() < 876545);
    assert_eq!(
        parse_set_descriptor(count_overflow),
        Err(WireError::SetCount)
    );
    assert_eq!(
        parse_set_descriptor(b"[]"),
        Ok(vec![]),
        "empty is syntax only, never qualification"
    );
    let record = |id: &str| format!("{{\"id\":\"{id}\",\"sha256\":\"{}\"}}", "01".repeat(32));
    for (a, b) in [("a", "a"), ("b", "a")] {
        assert_eq!(
            parse_set_descriptor(format!("[{},{}]", record(a), record(b)).as_bytes()),
            Err(WireError::SetOrder)
        );
    }
    assert!(
        parse_set_descriptor(format!("[{},{}]", record("A"), record("a")).as_bytes()).is_ok(),
        "ASCII ordering"
    );
    assert!(parse_set_descriptor(format!("[{}]", record(".bad")).as_bytes()).is_err());
    assert!(
        parse_set_descriptor(format!("[{}]", record("a".repeat(129).as_str())).as_bytes()).is_err()
    );
    assert!(parse_set_descriptor(format!("[{}]", record("a")).as_bytes()).is_ok());
    assert!(parse_set_descriptor(format!("[{}]\n", record("a")).as_bytes()).is_err());
}

#[test]
fn public_claim_records_require_checked_encoding() {
    let mut attestation = parse_attestation(W00).unwrap();
    attestation.fields.insert("read_lower".into(), "0".into());
    assert_eq!(attestation.profile_claims(), Err(WireError::InvalidScalar));
    assert_eq!(attestation.canonical_body(), Err(WireError::InvalidScalar));
    attestation.fields.insert("read_lower".into(), "8".into());
    attestation.signatures[0].key_id = "bad\"injection".into();
    assert!(attestation.canonical_bytes().is_err());
    let mut schema = parse_schema_descriptor(SCHEMA_MAXIMUM).unwrap();
    schema.fields.insert("extra".into(), "x".into());
    assert_eq!(schema.canonical_bytes(), Err(WireError::Syntax));
    let mut posture = parse_posture_descriptor(POSTURE_MAXIMUM).unwrap();
    posture.fields.insert("registry_mode".into(), "off".into());
    assert_eq!(posture.canonical_bytes(), Err(WireError::InvalidScalar));
    assert!(
        encode_set_descriptor(&[SimulationSetRecord {
            id: "a".into(),
            sha256: "00".repeat(32)
        }])
        .is_err()
    );
}
