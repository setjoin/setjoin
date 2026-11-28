use schema_adapter_simulation::adapter::*;
use schema_assessor::*;
use std::collections::BTreeSet;

fn id(n: u8) -> Identity {
    [n; 32]
}
fn hex(s: &str) -> Identity {
    assert_eq!(s.len(), 64);
    let mut out = [0; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}
fn build() -> BuildContract {
    BuildContract {
        binary: id(1),
        schema_version: 10,
        schema_identity: id(3),
        required_posture: id(2),
    }
}
fn db(v: u64) -> DatabaseFacts {
    DatabaseFacts {
        version: v,
        schema_identity: id(3),
        posture: id(2),
    }
}
fn claims() -> QualifiedProfileClaims {
    QualifiedProfileClaims {
        binary: id(1),
        profile: id(4),
        schema_identity: id(3),
        schema_version: 10,
        posture: id(2),
        read: Interval {
            lower: 8,
            upper: 12,
        },
        write: Interval {
            lower: 8,
            upper: 12,
        },
    }
}
fn hash(domain: &[u8], bytes: &[u8], digest: Identity) -> SimulationHash {
    let mut input = domain.to_vec();
    input.extend_from_slice(bytes);
    SimulationHash { input, digest }
}
struct Golden {
    bytes: &'static [u8],
    body: &'static [u8],
    core: &'static [u8],
    profile: Identity,
    artifact: Identity,
    body_digest: Identity,
}
fn golden(v: u64, posture: u8, mismatch: &str) -> Golden {
    match (v, posture, mismatch) {
        (10, 2, "none") => Golden {
            bytes: include_bytes!("../../fixtures/adapter-v10-p2-none.json"),
            body: include_bytes!("../../fixtures/adapter-v10-p2-none-body.json"),
            core: include_bytes!("../../fixtures/adapter-v10-p2-none-core.json"),
            profile: hex("5aa30ad2794ce63dd23864150139f45f51c11bd868cd296829c35669e8983601"),
            artifact: hex("e65fab093032edcc18ebbc664cef1ee6e7f3b83e9f15aa2f43c9e36f488c1c58"),
            body_digest: hex("295bd9610ebc9f03679690f3adcf061e14e411aa124f91f83464c060a2919e4d"),
        },
        (10, 2, "schema") => Golden {
            bytes: include_bytes!("../../fixtures/adapter-v10-p2-schema.json"),
            body: include_bytes!("../../fixtures/adapter-v10-p2-schema-body.json"),
            core: include_bytes!("../../fixtures/adapter-v10-p2-schema-core.json"),
            profile: hex("b9276afaa124b46f71a90de76317eec844eb184d5ae4c0534eb30572720d1e15"),
            artifact: hex("9b5e805a1cc06ee31c6727e9858cbdda68e49b76e83f7a27c39ed4137c4b8419"),
            body_digest: hex("62e1ad3ad6c785d0b7a11a2646dd4dd3139acbb797a8abb4047a41c052110080"),
        },
        (10, 2, "version") => Golden {
            bytes: include_bytes!("../../fixtures/adapter-v10-p2-version.json"),
            body: include_bytes!("../../fixtures/adapter-v10-p2-version-body.json"),
            core: include_bytes!("../../fixtures/adapter-v10-p2-version-core.json"),
            profile: hex("5aa30ad2794ce63dd23864150139f45f51c11bd868cd296829c35669e8983601"),
            artifact: hex("e65fab093032edcc18ebbc664cef1ee6e7f3b83e9f15aa2f43c9e36f488c1c58"),
            body_digest: hex("295bd9610ebc9f03679690f3adcf061e14e411aa124f91f83464c060a2919e4d"),
        },
        (10, 9, "none") => Golden {
            bytes: include_bytes!("../../fixtures/adapter-v10-p9-none.json"),
            body: include_bytes!("../../fixtures/adapter-v10-p9-none-body.json"),
            core: include_bytes!("../../fixtures/adapter-v10-p9-none-core.json"),
            profile: hex("e293a19a06fbf2da234465806c22f94bc38d4a13ff48c4ac91e059166fbffd55"),
            artifact: hex("0b44eacc3c31e0c592357430ee1c97bc0bc118056de15f8b2a3dbf18e3928420"),
            body_digest: hex("371ddb3fe47d121ea33b5705113fdb11f548fd5a672d96d0752a4615e30f2659"),
        },
        (10, 9, "schema") => Golden {
            bytes: include_bytes!("../../fixtures/adapter-v10-p9-schema.json"),
            body: include_bytes!("../../fixtures/adapter-v10-p9-schema-body.json"),
            core: include_bytes!("../../fixtures/adapter-v10-p9-schema-core.json"),
            profile: hex("8d20cb6993ac40823bcfd94125c693a14fe62b55800f52af12beda8e114d57b5"),
            artifact: hex("aab22dfa0a92ee4be1402893d0538d7bbc1610bbec90f314897bdc698da3a3f2"),
            body_digest: hex("8b0fcbcfa9b626feb16165a6917a5b3bb33e8f2ea8d01bb4af2ce9ec56db7ce8"),
        },
        (10, 9, "version") => Golden {
            bytes: include_bytes!("../../fixtures/adapter-v10-p9-version.json"),
            body: include_bytes!("../../fixtures/adapter-v10-p9-version-body.json"),
            core: include_bytes!("../../fixtures/adapter-v10-p9-version-core.json"),
            profile: hex("e293a19a06fbf2da234465806c22f94bc38d4a13ff48c4ac91e059166fbffd55"),
            artifact: hex("0b44eacc3c31e0c592357430ee1c97bc0bc118056de15f8b2a3dbf18e3928420"),
            body_digest: hex("371ddb3fe47d121ea33b5705113fdb11f548fd5a672d96d0752a4615e30f2659"),
        },
        (11, 2, "none") => Golden {
            bytes: include_bytes!("../../fixtures/adapter-v11-p2-none.json"),
            body: include_bytes!("../../fixtures/adapter-v11-p2-none-body.json"),
            core: include_bytes!("../../fixtures/adapter-v11-p2-none-core.json"),
            profile: hex("10bb832e33054ef650a1339e2953b9f389fa8c53db95aeef9aaa058d793b5981"),
            artifact: hex("91880caa25ecef7fcd3850a8933d0065df88b1796a83f6d7f77aff8f9c1360d6"),
            body_digest: hex("73798d3c70f7f96b11571afae3ad28539df070e9f80dc46031f68442cd8a2d5f"),
        },
        (11, 2, "schema") => Golden {
            bytes: include_bytes!("../../fixtures/adapter-v11-p2-schema.json"),
            body: include_bytes!("../../fixtures/adapter-v11-p2-schema-body.json"),
            core: include_bytes!("../../fixtures/adapter-v11-p2-schema-core.json"),
            profile: hex("af479696e178b45045f265e1cc2124f388c314c0264a68ac654c22df4b69c162"),
            artifact: hex("09169b21185099c4c585f69266b9676693308c48f19dccc9f4dc048bb8687352"),
            body_digest: hex("9dcdf32296cea02657fb875e647b216b062e78967d3ab71163d2d40de6d92077"),
        },
        (11, 2, "version") => Golden {
            bytes: include_bytes!("../../fixtures/adapter-v11-p2-version.json"),
            body: include_bytes!("../../fixtures/adapter-v11-p2-version-body.json"),
            core: include_bytes!("../../fixtures/adapter-v11-p2-version-core.json"),
            profile: hex("f9ff23a4b7b1a19020218c398a63690d8ff98d4e8d8d8e3c6467658409d26ce6"),
            artifact: hex("50545d463cd7df70558907f9f10c77b6b5717d74c9199cc71b48955acfb545cf"),
            body_digest: hex("d90fd2a06d0f2d26af39e90794d27bf04881b05b9c7577a590c3548cfcecc43a"),
        },
        (11, 9, "none") => Golden {
            bytes: include_bytes!("../../fixtures/adapter-v11-p9-none.json"),
            body: include_bytes!("../../fixtures/adapter-v11-p9-none-body.json"),
            core: include_bytes!("../../fixtures/adapter-v11-p9-none-core.json"),
            profile: hex("15a5eb4ccf472902957dc6c7c7e7bd269cc4a7a9c63cb2f7f013b90dfe3e013c"),
            artifact: hex("c6ecb793264744b4b24c10f0b7543501abe6e8a5724b25cf568b0c6885b09532"),
            body_digest: hex("f7f10c12d7557a2676b454204136f1789e6beb5791ffbd4c1ae418994f2d9beb"),
        },
        (11, 9, "schema") => Golden {
            bytes: include_bytes!("../../fixtures/adapter-v11-p9-schema.json"),
            body: include_bytes!("../../fixtures/adapter-v11-p9-schema-body.json"),
            core: include_bytes!("../../fixtures/adapter-v11-p9-schema-core.json"),
            profile: hex("16805dd31aa37b2abc41654bda49daa3c3abb57f17c4a3bc7e2c9115883fc0ce"),
            artifact: hex("caba5cee8b669f8377a394b34034416e049419cc75534cd6598aa26e0920bdf8"),
            body_digest: hex("17cfc723650fb9459ff3be9aae29a618d566a8a6958b2daf7cb93d953c9b8b77"),
        },
        (11, 9, "version") => Golden {
            bytes: include_bytes!("../../fixtures/adapter-v11-p9-version.json"),
            body: include_bytes!("../../fixtures/adapter-v11-p9-version-body.json"),
            core: include_bytes!("../../fixtures/adapter-v11-p9-version-core.json"),
            profile: hex("7ab7f98174b56538c6ab76d7e9ee960ebd0fe6f130f7f8e282e3facb55a03a1d"),
            artifact: hex("cf253c7a51c98d45af788fca6e9516b63753065e5f8bbc558fdf45c00e270475"),
            body_digest: hex("ab7e42e2d877ebc07855fb2500cba0bcf4f506b63daf9f3f8dcf7b259a6ea867"),
        },
        (10, 2, "notyet") => Golden {
            bytes: include_bytes!("../../fixtures/adapter-v10-p2-notyet.json"),
            body: include_bytes!("../../fixtures/adapter-v10-p2-notyet-body.json"),
            core: include_bytes!("../../fixtures/adapter-v10-p2-notyet-core.json"),
            profile: hex("5aa30ad2794ce63dd23864150139f45f51c11bd868cd296829c35669e8983601"),
            artifact: hex("061cf99aead4b554f58495eebaa4bd4fb810b5e1f7eef02b56f0f9203c434d4a"),
            body_digest: hex("a14a9067e466e4c211db8c1b9efa4cdaa6c931cd72e8eae5c93ec8d00f98c1d3"),
        },
        (10, 9, "notyet") => Golden {
            bytes: include_bytes!("../../fixtures/adapter-v10-p9-notyet.json"),
            body: include_bytes!("../../fixtures/adapter-v10-p9-notyet-body.json"),
            core: include_bytes!("../../fixtures/adapter-v10-p9-notyet-core.json"),
            profile: hex("e293a19a06fbf2da234465806c22f94bc38d4a13ff48c4ac91e059166fbffd55"),
            artifact: hex("0517da1f2f6d1812261a0a7dcb7b92e4dc502f331e9f1c9bd98ad4fb0780fde6"),
            body_digest: hex("7c0282040f54941aa8f86c6833cac8be87d21347b52b59919341645eb805bd87"),
        },
        (11, 2, "notyet") => Golden {
            bytes: include_bytes!("../../fixtures/adapter-v11-p2-notyet.json"),
            body: include_bytes!("../../fixtures/adapter-v11-p2-notyet-body.json"),
            core: include_bytes!("../../fixtures/adapter-v11-p2-notyet-core.json"),
            profile: hex("10bb832e33054ef650a1339e2953b9f389fa8c53db95aeef9aaa058d793b5981"),
            artifact: hex("e1417068b69fd5ae2f6e536407601b25a2fedd2a9ad1f6ba66d7d2c9d932bd62"),
            body_digest: hex("083436765cede123daa9fe499f246c1e246ecb47175630ff2464c48faab60325"),
        },
        (11, 9, "notyet") => Golden {
            bytes: include_bytes!("../../fixtures/adapter-v11-p9-notyet.json"),
            body: include_bytes!("../../fixtures/adapter-v11-p9-notyet-body.json"),
            core: include_bytes!("../../fixtures/adapter-v11-p9-notyet-core.json"),
            profile: hex("15a5eb4ccf472902957dc6c7c7e7bd269cc4a7a9c63cb2f7f013b90dfe3e013c"),
            artifact: hex("26fdb9c122e8336bf6a70cd8839a7ba0421d94d2f2cc6965ab36fa4463901a76"),
            body_digest: hex("41b1610ad6eec46ab4897e15e5e318be0b15084e61812302068dc53c59b2af03"),
        },
        (10, 2, "binary") => Golden {
            bytes: include_bytes!("../../fixtures/adapter-v10-p2-binary.json"),
            body: include_bytes!("../../fixtures/adapter-v10-p2-binary-body.json"),
            core: include_bytes!("../../fixtures/adapter-v10-p2-binary-core.json"),
            profile: hex("ef722b70ed3baaa93afca00f8b81080661fefa31821d2b5ba9d344af9518eb52"),
            artifact: hex("c69497b0d7b388d0f289afb0aced40c9203996080c7323b565c837587fbf3c0b"),
            body_digest: hex("2bd76d3b81e3d32d2f33c67dba53ba7e81f03516082000b6d67ff818f8925f41"),
        },
        _ => panic!("fixture not independently authored"),
    }
}
fn base(v: u64, posture: u8, mismatch: &str) -> SimulationInput {
    let g = golden(v, posture, mismatch);
    SimulationInput {
        build: build(),
        acquisition: SimulationAcquisition {
            installation: SimulationInstallation::Bound,
            generation: SimulationGeneration::Coherent,
            version: Ok(v),
        },
        observation: SimulationPartialObservation {
            schema: SimulationSchema::Established(if v == 10 { id(3) } else { id(7) }),
            posture: SimulationPosture::Established(id(2)),
            catalog_member_digest: Some(id(13)),
        },
        selection: SimulationSelection::Selected(g.profile),
        actual_proof: SimulationActualProof::default(),
        generation: 42,
        cancelled: false,
        evidence: SimulationEvidence {
            artifact: Some(g.bytes.to_vec()),
            legacy: SimulationLegacy::Available,
            signers: vec![
                SimulationSigner {
                    key_id: "alpha".into(),
                    result: SimulationSignerResult::ValidRelease,
                },
                SimulationSigner {
                    key_id: "beta".into(),
                    result: SimulationSignerResult::ValidRelease,
                },
            ],
            release_threshold: 2,
            handoff: SimulationHandoff {
                authentication: SimulationAuthentication::Authenticated,
                installation_id: id(20),
                timeline_id: id(21),
                release_epoch: "schema-test-v1".into(),
                generation: 42,
                trust_generation: 1,
                issuer_manifest: id(5),
                binary: id(1),
                artifact: g.artifact,
                qualification: id(6),
            },
            artifact_hash: hash(b"", g.bytes, g.artifact),
            body_hash: hash(b"", g.body, g.body_digest),
            profile_hash: hash(b"setjoin.schema.profile.v1\0", g.core, g.profile),
            policy: Some(SimulationPolicy {
                authentication: SimulationAuthentication::Authenticated,
                release_epoch: "schema-test-v1".into(),
                trust_generation: 1,
                not_before: 0,
                expires_at: 200,
                revoked_artifacts: vec![],
                revoked_profiles: vec![],
            }),
            clock: SimulationClock::Trusted(50),
            high_water: Some(SimulationHighWater {
                installation_id: id(20),
                timeline_id: id(21),
                release_epoch: "schema-test-v1".into(),
                profile: g.profile,
                sequence: 1,
                body_digest: g.body_digest,
            }),
            persistence: SimulationPersistence::Committed,
            qualification: Some(SimulationQualification {
                authentication: SimulationAuthentication::Authenticated,
                digest: id(6),
                binary: id(1),
                schema: if v == 10 { id(3) } else { id(7) },
                posture: id(2),
                version: v,
                profile: g.profile,
            }),
        },
    }
}
fn descriptor(bytes: &[u8], raw: u8, identity: u8, domain: &[u8]) -> SimulationDescriptorProof {
    SimulationDescriptorProof {
        bytes: bytes.to_vec(),
        authentication: SimulationAuthentication::Authenticated,
        envelope: SimulationGeneration::Coherent,
        installation: SimulationInstallation::Bound,
        extraction: SimulationExtraction::Supported,
        hash: hash(b"", bytes, id(raw)),
        handoff_digest: id(raw),
        identity_hash: hash(domain, bytes, id(identity)),
        observations: SimulationObservationAgreement::CompleteMatch,
    }
}
fn proof(schema: bool, posture: u8) -> SimulationActualProof {
    let sb = include_bytes!("../../fixtures/adapter-schema.json");
    let pb = include_bytes!("../../fixtures/adapter-posture.json");
    let mb = include_bytes!("../../fixtures/adapter-members.json");
    SimulationActualProof {
        release_epoch: "schema-test-v1".into(),
        schema: if schema {
            Some(descriptor(sb, 22, 7, b"setjoin.schema.descriptor.v1\0"))
        } else {
            None
        },
        posture: Some(descriptor(pb, 23, posture, b"setjoin.schema.posture.v1\0")),
        members: Some(SimulationMemberProof {
            bytes: mb.to_vec(),
            authentication: SimulationAuthentication::Authenticated,
            installation: SimulationInstallation::Bound,
            envelope: SimulationGeneration::Coherent,
            extraction: SimulationExtraction::Supported,
            hash: hash(b"", mb, id(13)),
            handoff_digest: id(13),
            observations: SimulationObservationAgreement::CompleteMatch,
        }),
    }
}
fn expect(i: &SimulationInput, code: &str, stage: &str, label: &str) -> SimulationReport {
    let r = compose_simulation(i);
    assert_eq!(r.code(), code, "{label}: primary-code");
    assert_eq!(r.stage(), stage, "{label}: stage-marker");
    assert_eq!(r.provenance(), "synthetic", "{label}: synthetic-provenance");
    r
}
fn no_evidence(r: &SimulationReport, label: &str) {
    assert!(
        !r.trace().iter().any(|s| s.starts_with('E') && *s != "E9a"),
        "{label}: zero-evidence-visits"
    );
    assert!(
        !r.trace().contains(&"artifact.parse"),
        "{label}: zero-artifact-parser-visits"
    );
}
fn no_admission(r: &SimulationReport, label: &str) {
    assert_ne!(
        r.outcome(),
        SimulationOutcome::CompatiblePendingFence,
        "{label}: no-admission"
    );
}
fn pending(i: &SimulationInput, label: &str) {
    let r = expect(i, "COMPATIBLE_PENDING_FENCE", "fence.pending", label);
    assert!(r.trace().contains(&"N"), "{label}: pending-fence");
    assert!(r.actual_facts().is_some(), "{label}: actual-facts-only");
}

#[test]
fn all_assessor_variants_map() {
    use Assessment::{CompatibleRequiresAdmissionFence as Compatible, RefuseBusiness as Deny};
    let cases = [
        (Refusal::MalformedBuild, "MALFORMED_BUILD"),
        (
            Refusal::Probe(ProbeFailure::MissingBaseline),
            "MISSING_BASELINE",
        ),
        (
            Refusal::Probe(ProbeFailure::PermissionDenied),
            "PROBE_PERMISSION_DENIED",
        ),
        (Refusal::Probe(ProbeFailure::Timeout), "PROBE_TIMEOUT"),
        (
            Refusal::Probe(ProbeFailure::ConnectionLost),
            "PROBE_CONNECTION_LOST",
        ),
        (Refusal::Probe(ProbeFailure::Other), "PROBE_OTHER"),
        (Refusal::MalformedDatabase, "MALFORMED_DATABASE"),
        (Refusal::PostureMismatch, "POSTURE_MISMATCH"),
        (Refusal::BelowExact, "BELOW_EXACT"),
        (Refusal::AboveExact, "ABOVE_EXACT"),
        (
            Refusal::Evidence(EvidenceFailure::InvalidSignature),
            "EVIDENCE_INVALID_SIGNATURE",
        ),
        (
            Refusal::Evidence(EvidenceFailure::UnknownSigner),
            "EVIDENCE_UNKNOWN_SIGNER",
        ),
        (Refusal::Evidence(EvidenceFailure::Stale), "EVIDENCE_STALE"),
        (
            Refusal::Evidence(EvidenceFailure::Revoked),
            "EVIDENCE_REVOKED",
        ),
        (
            Refusal::Evidence(EvidenceFailure::LegacyVerifierUnavailable),
            "LEGACY_VERIFIER_UNAVAILABLE",
        ),
        (Refusal::MalformedProfile, "MALFORMED_PROFILE"),
        (Refusal::BinaryMismatch, "BINARY_MISMATCH"),
        (Refusal::SchemaMismatch, "SCHEMA_MISMATCH"),
        (Refusal::ProfilePostureMismatch, "PROFILE_POSTURE_MISMATCH"),
        (Refusal::ReadOutsideInterval, "READ_OUTSIDE_INTERVAL"),
        (Refusal::WriteOutsideInterval, "WRITE_OUTSIDE_INTERVAL"),
    ];
    for (reason, code) in cases {
        assert_eq!(
            simulation_assessor_code(Deny(reason)),
            code,
            "total-mapper-{reason:?}"
        );
    }
    for result in [
        Compatible(CompatibleProfile::Exact),
        Compatible(CompatibleProfile::Qualified(id(4))),
    ] {
        assert_eq!(simulation_assessor_code(result), "COMPATIBLE_PENDING_FENCE");
    }
    assert_eq!(
        simulation_assessor_code(Assessment::HoldInventory),
        "INVENTORY_UNRESOLVED"
    );
    // P01–P13 are literal direct-assessor calls, preserving the original boundary.
    let mut b = build();
    b.schema_version = 0;
    let mut p = claims();
    p.read.lower = 0;
    p.binary = id(9);
    let p06 = p;
    p = claims();
    p.binary = id(9);
    p.schema_identity = id(9);
    let p07 = p;
    p = claims();
    p.schema_identity = id(9);
    p.posture = id(9);
    let p08 = p;
    p = claims();
    p.posture = id(9);
    p.read = Interval {
        lower: 11,
        upper: 12,
    };
    let p09 = p;
    p = claims();
    p.read = Interval {
        lower: 11,
        upper: 12,
    };
    p.write = p.read;
    let p10 = p;
    let original = [
        (
            "P01",
            assess(
                b,
                Err(ProbeFailure::Timeout),
                ProfileClaims::Rejected(EvidenceFailure::Revoked),
            ),
            Deny(Refusal::MalformedBuild),
        ),
        (
            "P02",
            assess(
                build(),
                Err(ProbeFailure::PermissionDenied),
                ProfileClaims::Rejected(EvidenceFailure::Revoked),
            ),
            Deny(Refusal::Probe(ProbeFailure::PermissionDenied)),
        ),
        (
            "P03",
            assess(
                build(),
                Ok(DatabaseFacts {
                    posture: id(9),
                    ..db(0)
                }),
                ProfileClaims::InventoryUnresolved,
            ),
            Deny(Refusal::MalformedDatabase),
        ),
        (
            "P04",
            assess(
                build(),
                Ok(DatabaseFacts {
                    posture: id(9),
                    ..db(10)
                }),
                ProfileClaims::InventoryUnresolved,
            ),
            Deny(Refusal::PostureMismatch),
        ),
        (
            "P05",
            assess(
                build(),
                Ok(DatabaseFacts {
                    posture: id(9),
                    ..db(10)
                }),
                ProfileClaims::Rejected(EvidenceFailure::Revoked),
            ),
            Deny(Refusal::PostureMismatch),
        ),
        (
            "P06",
            assess(build(), Ok(db(10)), ProfileClaims::Qualified(p06)),
            Deny(Refusal::MalformedProfile),
        ),
        (
            "P07",
            assess(build(), Ok(db(10)), ProfileClaims::Qualified(p07)),
            Deny(Refusal::BinaryMismatch),
        ),
        (
            "P08",
            assess(build(), Ok(db(10)), ProfileClaims::Qualified(p08)),
            Deny(Refusal::SchemaMismatch),
        ),
        (
            "P09",
            assess(build(), Ok(db(10)), ProfileClaims::Qualified(p09)),
            Deny(Refusal::ProfilePostureMismatch),
        ),
        (
            "P10",
            assess(build(), Ok(db(10)), ProfileClaims::Qualified(p10)),
            Deny(Refusal::ReadOutsideInterval),
        ),
        (
            "P11",
            assess(
                build(),
                Ok(DatabaseFacts {
                    schema_identity: id(9),
                    ..db(9)
                }),
                ProfileClaims::ExactDefault,
            ),
            Deny(Refusal::BelowExact),
        ),
        (
            "P12",
            assess(
                build(),
                Ok(DatabaseFacts {
                    schema_identity: id(9),
                    ..db(11)
                }),
                ProfileClaims::ExactDefault,
            ),
            Deny(Refusal::AboveExact),
        ),
        (
            "P13",
            assess(
                build(),
                Ok(db(10)),
                ProfileClaims::Rejected(EvidenceFailure::Revoked),
            ),
            Deny(Refusal::Evidence(EvidenceFailure::Revoked)),
        ),
    ];
    for (label, actual, want) in original {
        assert_eq!(actual, want, "{label}: direct-original-precedence");
        assert_eq!(
            assess(build(), Ok(db(10)), ProfileClaims::Qualified(claims())),
            Compatible(CompatibleProfile::Qualified(id(4))),
            "{label}: direct-restore"
        );
    }
}

fn all_results() -> Vec<Assessment> {
    let mut results = vec![
        Assessment::HoldInventory,
        Assessment::CompatibleRequiresAdmissionFence(CompatibleProfile::Exact),
        Assessment::CompatibleRequiresAdmissionFence(CompatibleProfile::Qualified(id(4))),
    ];
    for r in [
        Refusal::MalformedBuild,
        Refusal::MalformedDatabase,
        Refusal::PostureMismatch,
        Refusal::BelowExact,
        Refusal::AboveExact,
        Refusal::MalformedProfile,
        Refusal::BinaryMismatch,
        Refusal::SchemaMismatch,
        Refusal::ProfilePostureMismatch,
        Refusal::ReadOutsideInterval,
        Refusal::WriteOutsideInterval,
    ] {
        results.push(Assessment::RefuseBusiness(r));
    }
    for p in [
        ProbeFailure::MissingBaseline,
        ProbeFailure::PermissionDenied,
        ProbeFailure::Timeout,
        ProbeFailure::ConnectionLost,
        ProbeFailure::Other,
    ] {
        results.push(Assessment::RefuseBusiness(Refusal::Probe(p)));
    }
    for e in [
        EvidenceFailure::InvalidSignature,
        EvidenceFailure::UnknownSigner,
        EvidenceFailure::Stale,
        EvidenceFailure::Revoked,
        EvidenceFailure::LegacyVerifierUnavailable,
    ] {
        results.push(Assessment::RefuseBusiness(Refusal::Evidence(e)));
    }
    results
}
#[test]
fn prefix_phase_impossible_returns() {
    for phase in [
        SimulationPhase::Prefix,
        SimulationPhase::ResolvedPrefix,
        SimulationPhase::CompletePrefix,
    ] {
        for r in all_results() {
            let want = match r {
                Assessment::HoldInventory => None,
                Assessment::RefuseBusiness(Refusal::PostureMismatch) => Some("POSTURE_MISMATCH"),
                Assessment::RefuseBusiness(Refusal::MalformedDatabase)
                    if phase == SimulationPhase::Prefix =>
                {
                    Some("MALFORMED_DATABASE")
                }
                _ => Some("ADAPTER_INVARIANT_VIOLATION"),
            };
            assert_eq!(
                simulation_phase_result(phase, r),
                want,
                "strict-prefix-{phase:?}-{r:?}: invariant-allowlist"
            );
        }
    }
    let mut i = base(11, 2, "none");
    i.observation.schema = SimulationSchema::NeedsSchemaProof;
    i.observation.posture = SimulationPosture::NeedsSchemaProof;
    i.actual_proof = proof(false, 2);
    let r = expect(
        &i,
        "QUALIFICATION_UNRESOLVED",
        "evidence.qualification",
        "Kr-P-control",
    );
    assert!(
        r.trace().contains(&"Kr"),
        "Kr-P-control: refinement-HoldInventory"
    );
    assert!(
        !r.trace().contains(&"A"),
        "Kr-P-control: no-complete-prefix"
    );
    i.actual_proof = proof(false, 9);
    let r = expect(&i, "POSTURE_MISMATCH", "resolved_prefix", "Kr-Q-control");
    no_evidence(&r, "Kr-Q-control");
}
#[test]
fn all_selected_profile_refusals_are_guarded() {
    for r in all_results() {
        let want = match r {
            Assessment::CompatibleRequiresAdmissionFence(CompatibleProfile::Qualified(_)) => {
                "COMPATIBLE_PENDING_FENCE"
            }
            _ => "ADAPTER_INVARIANT_VIOLATION",
        };
        assert_eq!(
            simulation_phase_result(SimulationPhase::SelectedProfile, r),
            Some(want),
            "selected-guard-{r:?}: invariant-profile-assess"
        );
        assert_eq!(SimulationPhase::SelectedProfile.marker(), "profile.assess");
    }
    pending(&base(10, 2, "none"), "validated-raw-selected-control");
    let mut i = base(10, 2, "none");
    i.selection = SimulationSelection::Exact;
    i.observation.schema = SimulationSchema::Established(id(8));
    expect(
        &i,
        "SCHEMA_MISMATCH",
        "exact.assess",
        "exact-mismatch-ordinary",
    );
}

#[test]
fn composition_partition_is_total() {
    let selections = [
        SimulationSelection::Exact,
        SimulationSelection::Selected(id(4)),
        SimulationSelection::InventoryUnresolved,
    ];
    let versions = [
        Ok(0),
        Ok(9),
        Ok(10),
        Ok(11),
        Err(ProbeFailure::MissingBaseline),
        Err(ProbeFailure::PermissionDenied),
        Err(ProbeFailure::Timeout),
        Err(ProbeFailure::ConnectionLost),
        Err(ProbeFailure::Other),
    ];
    let schemas = [
        SimulationSchema::Established(id(3)),
        SimulationSchema::Established(id(8)),
        SimulationSchema::Established(id(0)),
        SimulationSchema::NeedsSchemaProof,
        SimulationSchema::ProvenUnequalToBuild,
    ];
    let postures = [
        SimulationPosture::Established(id(2)),
        SimulationPosture::Established(id(9)),
        SimulationPosture::Established(id(0)),
        SimulationPosture::MissingIndependentObservation,
        SimulationPosture::NeedsSchemaProof,
    ];
    let mut count = 0;
    for malformed in [false, true] {
        for selection in selections {
            for foreign in [false, true] {
                for mixed in [false, true] {
                    for v in versions {
                        for s in schemas {
                            for p in postures {
                                count += 1;
                                let label = format!(
                                    "INGRESS-{count:04}-{malformed}-{selection:?}-{foreign}-{mixed}-{v:?}-{s:?}-{p:?}"
                                );
                                let mut i = base(10, 2, "none");
                                i.selection = selection;
                                i.acquisition.version = v;
                                i.observation.schema = s;
                                i.observation.posture = p;
                                i.evidence.artifact = None;
                                if malformed {
                                    i.build.schema_version = 0;
                                }
                                if foreign {
                                    i.acquisition.installation =
                                        SimulationInstallation::ForeignOrUnbound;
                                }
                                if mixed {
                                    i.acquisition.generation = SimulationGeneration::MixedOrUnbound;
                                }
                                // Independent expectations use the reviewed finite domain, not adapter output,
                                // CSV/expander data, raw parser output, or the phase-mapping implementation.
                                let (code, stage) = if malformed {
                                    ("MALFORMED_BUILD", "build")
                                } else if foreign {
                                    ("EVIDENCE_BINDING_MISMATCH", "acquisition.installation")
                                } else if mixed {
                                    ("OBSERVATION_GENERATION_MISMATCH", "acquisition.generation")
                                } else if let Err(e) = v {
                                    (
                                        match e {
                                            ProbeFailure::MissingBaseline => "MISSING_BASELINE",
                                            ProbeFailure::PermissionDenied => {
                                                "PROBE_PERMISSION_DENIED"
                                            }
                                            ProbeFailure::Timeout => "PROBE_TIMEOUT",
                                            ProbeFailure::ConnectionLost => "PROBE_CONNECTION_LOST",
                                            ProbeFailure::Other => "PROBE_OTHER",
                                        },
                                        "acquisition.version",
                                    )
                                } else if v == Ok(0)
                                    || s == SimulationSchema::Established(id(0))
                                    || p == SimulationPosture::Established(id(0))
                                {
                                    ("MALFORMED_DATABASE", "prefix")
                                } else if p == SimulationPosture::Established(id(9)) {
                                    ("POSTURE_MISMATCH", "prefix")
                                } else if p == SimulationPosture::MissingIndependentObservation {
                                    ("POSTURE_UNKNOWN", "prefix.posture")
                                } else {
                                    match selection {
                                        SimulationSelection::InventoryUnresolved => {
                                            ("INVENTORY_UNRESOLVED", "selection.inventory")
                                        }
                                        SimulationSelection::Selected(_) => {
                                            ("MISSING_SELECTED_EVIDENCE", "evidence.presence")
                                        }
                                        SimulationSelection::Exact => match v {
                                            Ok(9) => ("BELOW_EXACT", "exact.assess"),
                                            Ok(11) => ("ABOVE_EXACT", "exact.assess"),
                                            _ => {
                                                if s == SimulationSchema::Established(id(8)) {
                                                    ("SCHEMA_MISMATCH", "exact.assess")
                                                } else if s
                                                    == SimulationSchema::ProvenUnequalToBuild
                                                {
                                                    ("SCHEMA_MISMATCH", "exact.comparison")
                                                } else if s == SimulationSchema::NeedsSchemaProof
                                                    || p == SimulationPosture::NeedsSchemaProof
                                                {
                                                    ("QUALIFICATION_UNRESOLVED", "exact.proof")
                                                } else {
                                                    ("COMPATIBLE_PENDING_FENCE", "fence.pending")
                                                }
                                            }
                                        },
                                    }
                                };
                                let r = expect(&i, code, stage, &label);
                                if matches!(
                                    stage,
                                    "build"
                                        | "acquisition.installation"
                                        | "acquisition.generation"
                                        | "acquisition.version"
                                ) {
                                    assert_eq!(
                                        r.schema_identity(),
                                        None,
                                        "{label}: tainted-schema-omitted"
                                    );
                                    assert_eq!(
                                        r.posture_identity(),
                                        None,
                                        "{label}: tainted-posture-omitted"
                                    );
                                    assert_eq!(
                                        r.version(),
                                        None,
                                        "{label}: tainted-version-omitted"
                                    );
                                    assert_eq!(
                                        r.trace(),
                                        if stage == "build" {
                                            &["G"][..]
                                        } else {
                                            &["G", "C"][..]
                                        },
                                        "{label}: exact-earliest-trace"
                                    );
                                } else if stage == "prefix" || stage == "prefix.posture" {
                                    no_evidence(&r, &label);
                                    assert!(
                                        !r.trace().contains(&"X"),
                                        "{label}: no-Exact-on-prefix-refusal"
                                    );
                                } else if selection == SimulationSelection::InventoryUnresolved {
                                    assert!(r.trace().contains(&"I"));
                                    no_evidence(&r, &label);
                                } else if selection == SimulationSelection::Exact {
                                    assert!(r.trace().contains(&"X"));
                                    no_evidence(&r, &label);
                                    assert!(!r.trace().contains(&"A"));
                                } else {
                                    assert!(r.trace().contains(&"E9a"));
                                    assert!(r.trace().contains(&"E2"));
                                    assert!(!r.trace().contains(&"artifact.parse"));
                                    assert_eq!(
                                        r.trace().contains(&"A"),
                                        matches!(s, SimulationSchema::Established(_))
                                            && p == SimulationPosture::Established(id(2)),
                                        "{label}: A-only-complete"
                                    );
                                }
                                if s == SimulationSchema::NeedsSchemaProof
                                    || s == SimulationSchema::ProvenUnequalToBuild
                                {
                                    assert_eq!(
                                        r.schema_identity(),
                                        None,
                                        "{label}: no-scratch-schema"
                                    );
                                }
                                if code != "COMPATIBLE_PENDING_FENCE" {
                                    no_admission(&r, &label);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!(count, 5400, "INGRESS: exact-product-count");
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    None,
    Missing,
    Legacy,
    Syntax,
    UnknownSigner,
    InvalidSignature,
    Threshold,
    Binding,
    RecomputedId,
    SelectedId,
    Policy,
    Clock,
    HighWater,
    Revoked,
    NotYet,
    Expired,
    Replay,
    Equivocation,
    Persistence,
    Qualification,
    SchemaClaim,
    PostureClaim,
}
const FAULTS: [Fault; 22] = [
    Fault::None,
    Fault::Missing,
    Fault::Legacy,
    Fault::Syntax,
    Fault::UnknownSigner,
    Fault::InvalidSignature,
    Fault::Threshold,
    Fault::Binding,
    Fault::RecomputedId,
    Fault::SelectedId,
    Fault::Policy,
    Fault::Clock,
    Fault::HighWater,
    Fault::Revoked,
    Fault::NotYet,
    Fault::Expired,
    Fault::Replay,
    Fault::Equivocation,
    Fault::Persistence,
    Fault::Qualification,
    Fault::SchemaClaim,
    Fault::PostureClaim,
];
impl Fault {
    fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Missing => "missing_artifact",
            Self::Legacy => "legacy",
            Self::Syntax => "syntax",
            Self::UnknownSigner => "unknown_signer",
            Self::InvalidSignature => "invalid_signature",
            Self::Threshold => "threshold",
            Self::Binding => "binding",
            Self::RecomputedId => "recomputed_id",
            Self::SelectedId => "selected_id",
            Self::Policy => "policy_unavailable",
            Self::Clock => "clock_unavailable",
            Self::HighWater => "high_water_unavailable",
            Self::Revoked => "revoked",
            Self::NotYet => "not_yet_valid",
            Self::Expired => "expired",
            Self::Replay => "replay",
            Self::Equivocation => "equivocation",
            Self::Persistence => "persistence_unknown",
            Self::Qualification => "qualification_missing",
            Self::SchemaClaim => "schema_version_claim_mismatch",
            Self::PostureClaim => "posture_claim_mismatch",
        }
    }
}
fn apply_fault(i: &mut SimulationInput, f: Fault) {
    match f {
        Fault::None => {}
        Fault::Missing => i.evidence.artifact = None,
        Fault::Legacy => i.evidence.legacy = SimulationLegacy::Unavailable,
        Fault::Syntax => i.evidence.artifact = Some(b"{}".to_vec()),
        Fault::UnknownSigner => {
            for s in &mut i.evidence.signers {
                s.result = SimulationSignerResult::UnknownOrUnauthorized;
            }
        }
        Fault::InvalidSignature => {
            for s in &mut i.evidence.signers {
                s.result = SimulationSignerResult::RecognizedInvalid;
            }
        }
        Fault::Threshold => {
            i.evidence.signers[1].result = SimulationSignerResult::RecognizedInvalid
        }
        Fault::Binding => i.evidence.handoff.binary = id(8),
        Fault::RecomputedId => i.evidence.profile_hash.digest = id(8),
        Fault::SelectedId => i.selection = SimulationSelection::Selected(id(8)),
        Fault::Policy => i.evidence.policy = None,
        Fault::Clock => i.evidence.clock = SimulationClock::Unavailable,
        Fault::HighWater => i.evidence.high_water = None,
        Fault::Revoked => {
            let artifact = i.evidence.handoff.artifact;
            i.evidence
                .policy
                .as_mut()
                .unwrap()
                .revoked_artifacts
                .push(artifact);
        }
        Fault::NotYet => i.evidence.clock = SimulationClock::Trusted(0), // caller supplies positive not_before fixture below
        Fault::Expired => i.evidence.clock = SimulationClock::Trusted(100),
        Fault::Replay => i.evidence.high_water.as_mut().unwrap().sequence = 2,
        Fault::Equivocation => i.evidence.high_water.as_mut().unwrap().body_digest = id(8),
        Fault::Persistence => i.evidence.persistence = SimulationPersistence::Unknown,
        Fault::Qualification => i.evidence.qualification = None,
        Fault::SchemaClaim => i.evidence.qualification.as_mut().unwrap().schema = id(8),
        Fault::PostureClaim => i.evidence.qualification.as_mut().unwrap().posture = id(8),
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Basis {
    KnownFullP,
    KnownFullQ,
    KnownPartialP,
    KnownPartialQ,
    ResolvedFullP,
    ResolvedFullQ,
    ResolvedPartialP,
    ResolvedPartialQ,
    AbsentP,
    AbsentDeferred,
    MalformedP,
    MalformedDeferred,
    UnboundP,
    UnboundDeferred,
    UnavailableP,
    UnavailableDeferred,
    UnsupportedP,
    UnsupportedDeferred,
    IncompleteP,
    IncompleteDeferred,
    DisagreeingP,
    DisagreeingDeferred,
}
const BASES: [Basis; 22] = [
    Basis::KnownFullP,
    Basis::KnownFullQ,
    Basis::KnownPartialP,
    Basis::KnownPartialQ,
    Basis::ResolvedFullP,
    Basis::ResolvedFullQ,
    Basis::ResolvedPartialP,
    Basis::ResolvedPartialQ,
    Basis::AbsentP,
    Basis::AbsentDeferred,
    Basis::MalformedP,
    Basis::MalformedDeferred,
    Basis::UnboundP,
    Basis::UnboundDeferred,
    Basis::UnavailableP,
    Basis::UnavailableDeferred,
    Basis::UnsupportedP,
    Basis::UnsupportedDeferred,
    Basis::IncompleteP,
    Basis::IncompleteDeferred,
    Basis::DisagreeingP,
    Basis::DisagreeingDeferred,
];
impl Basis {
    fn name(self) -> &'static str {
        match self {
            Self::KnownFullP => "known_full_P",
            Self::KnownFullQ => "known_full_Q",
            Self::KnownPartialP => "known_partial_P",
            Self::KnownPartialQ => "known_partial_Q",
            Self::ResolvedFullP => "resolved_full_P",
            Self::ResolvedFullQ => "resolved_full_Q",
            Self::ResolvedPartialP => "resolved_partial_P",
            Self::ResolvedPartialQ => "resolved_partial_Q",
            Self::AbsentP => "absent_independent_P",
            Self::AbsentDeferred => "absent_independent_deferred",
            Self::MalformedP => "malformed_independent_P",
            Self::MalformedDeferred => "malformed_independent_deferred",
            Self::UnboundP => "unbound_independent_P",
            Self::UnboundDeferred => "unbound_independent_deferred",
            Self::UnavailableP => "authentication_unavailable_independent_P",
            Self::UnavailableDeferred => "authentication_unavailable_independent_deferred",
            Self::UnsupportedP => "unsupported_independent_P",
            Self::UnsupportedDeferred => "unsupported_independent_deferred",
            Self::IncompleteP => "incomplete_independent_P",
            Self::IncompleteDeferred => "incomplete_independent_deferred",
            Self::DisagreeingP => "disagreeing_independent_P",
            Self::DisagreeingDeferred => "disagreeing_independent_deferred",
        }
    }
}
fn with_basis(i: &mut SimulationInput, b: Basis) {
    i.observation.schema = SimulationSchema::NeedsSchemaProof;
    i.observation.posture = SimulationPosture::NeedsSchemaProof;
    i.observation.catalog_member_digest = None;
    i.actual_proof = SimulationActualProof::default();
    match b {
        Basis::KnownFullP | Basis::KnownFullQ => {
            i.observation.schema = SimulationSchema::Established(id(7));
            i.observation.posture =
                SimulationPosture::Established(id(if b == Basis::KnownFullP { 2 } else { 9 }));
        }
        Basis::KnownPartialP | Basis::KnownPartialQ => {
            i.observation.posture =
                SimulationPosture::Established(id(if b == Basis::KnownPartialP { 2 } else { 9 }))
        }
        Basis::ResolvedFullP | Basis::ResolvedFullQ => {
            i.actual_proof = proof(true, if b == Basis::ResolvedFullP { 2 } else { 9 })
        }
        Basis::ResolvedPartialP | Basis::ResolvedPartialQ => {
            i.actual_proof = proof(false, if b == Basis::ResolvedPartialP { 2 } else { 9 })
        }
        Basis::AbsentP
        | Basis::MalformedP
        | Basis::UnboundP
        | Basis::UnavailableP
        | Basis::UnsupportedP
        | Basis::IncompleteP
        | Basis::DisagreeingP => i.observation.posture = SimulationPosture::Established(id(2)),
        Basis::AbsentDeferred
        | Basis::MalformedDeferred
        | Basis::UnboundDeferred
        | Basis::UnavailableDeferred
        | Basis::UnsupportedDeferred
        | Basis::IncompleteDeferred
        | Basis::DisagreeingDeferred => {}
    }
    if matches!(
        b,
        Basis::AbsentP
            | Basis::AbsentDeferred
            | Basis::KnownFullP
            | Basis::KnownFullQ
            | Basis::KnownPartialP
            | Basis::KnownPartialQ
            | Basis::ResolvedFullP
            | Basis::ResolvedFullQ
            | Basis::ResolvedPartialP
            | Basis::ResolvedPartialQ
    ) {
        return;
    }
    i.actual_proof = proof(true, 2);
    let p = &mut i.actual_proof;
    for d in [&mut p.schema, &mut p.posture].into_iter().flatten() {
        match b {
            Basis::MalformedP | Basis::MalformedDeferred => d.bytes = b"{}".to_vec(),
            Basis::UnboundP | Basis::UnboundDeferred => d.handoff_digest = id(8),
            Basis::UnavailableP | Basis::UnavailableDeferred => {
                d.authentication = SimulationAuthentication::Unavailable
            }
            Basis::UnsupportedP | Basis::UnsupportedDeferred => {
                d.extraction = SimulationExtraction::Unsupported
            }
            Basis::IncompleteP | Basis::IncompleteDeferred => {
                d.observations = SimulationObservationAgreement::Incomplete
            }
            Basis::DisagreeingP | Basis::DisagreeingDeferred => {
                d.observations = SimulationObservationAgreement::Disagrees
            }
            _ => unreachable!(),
        }
    }
    let m = p.members.as_mut().unwrap();
    match b {
        Basis::MalformedP | Basis::MalformedDeferred => m.bytes = b"{}".to_vec(),
        Basis::UnboundP | Basis::UnboundDeferred => m.handoff_digest = id(8),
        Basis::UnavailableP | Basis::UnavailableDeferred => {
            m.authentication = SimulationAuthentication::Unavailable
        }
        Basis::UnsupportedP | Basis::UnsupportedDeferred => {
            m.extraction = SimulationExtraction::Unsupported
        }
        Basis::IncompleteP | Basis::IncompleteDeferred => {
            m.observations = SimulationObservationAgreement::Incomplete
        }
        Basis::DisagreeingP | Basis::DisagreeingDeferred => {
            m.observations = SimulationObservationAgreement::Disagrees
        }
        _ => unreachable!(),
    }
}
// Authored from the phase contract and immutable assessor, independently of the
// adapter, wire parser and documentary CSV. Ranks are explicit semantic order.
fn fault_oracle(f: Fault) -> Option<(u8, &'static str, &'static str, &'static str)> {
    Some(match f {
        Fault::Missing => (2, "MISSING_SELECTED_EVIDENCE", "evidence.presence", "E2"),
        Fault::Legacy => (3, "LEGACY_VERIFIER_UNAVAILABLE", "evidence.legacy", "E3"),
        Fault::Syntax => (4, "EVIDENCE_MALFORMED", "evidence.syntax", "artifact.parse"),
        Fault::UnknownSigner => (5, "EVIDENCE_UNKNOWN_SIGNER", "evidence.signers", "E5"),
        Fault::InvalidSignature => (5, "EVIDENCE_INVALID_SIGNATURE", "evidence.signers", "E5"),
        Fault::Threshold => (5, "EVIDENCE_SIGNATURE_THRESHOLD", "evidence.signers", "E5"),
        Fault::Binding => (6, "EVIDENCE_BINDING_MISMATCH", "evidence.binding", "E6"),
        Fault::RecomputedId => (7, "EVIDENCE_PROFILE_MISMATCH", "evidence.profile_id", "E7"),
        Fault::SelectedId => (
            7,
            "EVIDENCE_PROFILE_MISMATCH",
            "evidence.profile_id",
            "E7.selected",
        ),
        Fault::Policy => (
            8,
            "EVIDENCE_CURRENTNESS_UNKNOWN",
            "evidence.currentness.prerequisites",
            "E8.policy",
        ),
        Fault::Clock => (
            8,
            "EVIDENCE_CURRENTNESS_UNKNOWN",
            "evidence.currentness.prerequisites",
            "E8.clock",
        ),
        Fault::HighWater => (
            8,
            "EVIDENCE_CURRENTNESS_UNKNOWN",
            "evidence.currentness.prerequisites",
            "E8.high_water",
        ),
        Fault::Revoked => (
            9,
            "EVIDENCE_REVOKED",
            "evidence.currentness.revocation",
            "E8.revocation",
        ),
        Fault::NotYet | Fault::Expired => {
            (10, "EVIDENCE_STALE", "evidence.currentness.time", "E8.time")
        }
        Fault::Replay => (
            11,
            "EVIDENCE_REPLAY",
            "evidence.currentness.sequence",
            "E8.sequence",
        ),
        Fault::Equivocation => (
            11,
            "EVIDENCE_EQUIVOCATION",
            "evidence.currentness.sequence",
            "E8.sequence",
        ),
        Fault::Persistence => (
            12,
            "EVIDENCE_CURRENTNESS_UNKNOWN",
            "evidence.currentness.persistence",
            "E8.persistence",
        ),
        Fault::Qualification | Fault::SchemaClaim | Fault::PostureClaim => (
            13,
            "QUALIFICATION_UNRESOLVED",
            "evidence.qualification",
            "E9b",
        ),
        Fault::None => return None,
    })
}
fn matrix_oracle(
    b: Basis,
    f: Fault,
    claim: u8,
) -> (&'static str, &'static str, &'static str, bool) {
    match b {
        Basis::KnownFullQ | Basis::KnownPartialQ => {
            return ("POSTURE_MISMATCH", "prefix", "K", false);
        }
        Basis::ResolvedFullQ => return ("POSTURE_MISMATCH", "complete_prefix", "A", true),
        Basis::ResolvedPartialQ => return ("POSTURE_MISMATCH", "resolved_prefix", "Kr", false),
        _ => {}
    }
    let complete = matches!(b, Basis::KnownFullP | Basis::ResolvedFullP);
    let proof_error = match b {
        Basis::MalformedP | Basis::MalformedDeferred => {
            Some((4, "EVIDENCE_MALFORMED", "evidence.syntax", "artifact.parse"))
        }
        Basis::UnboundP
        | Basis::UnboundDeferred
        | Basis::UnavailableP
        | Basis::UnavailableDeferred => {
            Some((6, "EVIDENCE_BINDING_MISMATCH", "evidence.binding", "E6"))
        }
        _ => None,
    };
    let evidence = fault_oracle(f);
    let chosen = match (proof_error, evidence) {
        (Some(p), Some(e)) => Some(if e.0 <= p.0 { e } else { p }),
        (Some(p), None) => Some(p),
        (None, e) => e,
    };
    if let Some((_, code, stage, token)) = chosen {
        return (code, stage, token, complete);
    }
    if !complete || claim == 9 {
        return (
            "QUALIFICATION_UNRESOLVED",
            "evidence.qualification",
            "E9b",
            complete,
        );
    }
    ("COMPATIBLE_PENDING_FENCE", "fence.pending", "N", complete)
}
fn expected_matrix_trace(b: Basis, terminal: &str) -> Vec<&'static str> {
    let mut t = vec!["G", "C", "K", "K1", "K2", "K3"];
    if !matches!(b, Basis::KnownFullP | Basis::KnownFullQ) {
        t.push("K3.deferred_schema");
    }
    t.push("K4");
    if !matches!(
        b,
        Basis::KnownFullP
            | Basis::KnownFullQ
            | Basis::KnownPartialP
            | Basis::KnownPartialQ
            | Basis::AbsentP
            | Basis::MalformedP
            | Basis::UnboundP
            | Basis::UnavailableP
            | Basis::UnsupportedP
            | Basis::IncompleteP
            | Basis::DisagreeingP
    ) {
        t.push("K4.deferred_posture");
    }
    if terminal == "K" {
        return t;
    }
    t.push("E9a");
    if matches!(
        b,
        Basis::KnownFullP | Basis::ResolvedFullP | Basis::ResolvedFullQ
    ) {
        t.push("A");
    }
    if matches!(b, Basis::ResolvedPartialP | Basis::ResolvedPartialQ) {
        t.push("Kr");
    }
    if terminal == "A" || terminal == "Kr" {
        return t;
    }
    for token in [
        "E1",
        "E2",
        "E3",
        "E4",
        "artifact.parse",
        "E5",
        "E6",
        "E7.recomputed",
        "E7",
        "E7.selected",
        "E8.prerequisites",
        "E8.policy",
        "E8.clock",
        "E8.high_water",
        "E8.revocation",
        "E8.time",
        "E8.sequence",
        "E8.persistence",
        "E9b",
        "P",
        "N",
    ] {
        t.push(token);
        if token == terminal {
            return t;
        }
    }
    panic!("independent trace has no terminal {terminal}")
}
#[test]
fn composed_precedence_matrix() {
    let independent = include_str!("../../fixtures/adapter-independent-968.tsv");
    let mut oracle = std::collections::BTreeMap::new();
    for line in independent.lines().skip(1) {
        let row: Vec<&str> = line.split('\t').collect();
        assert_eq!(row.len(), 8, "independent-oracle-schema");
        let key = format!("{}|{}|{}", row[0], row[1], row[2]);
        assert!(
            oracle.insert(key, row).is_none(),
            "independent-oracle-unique"
        );
    }
    assert_eq!(oracle.len(), 968, "independent-oracle-968-literal-rows");
    let mut tuples = BTreeSet::new();
    let mut count = 0;
    for b in BASES {
        for f in FAULTS {
            for claim in [2, 9] {
                let label = format!(
                    "{}|{}|{}",
                    b.name(),
                    f.name(),
                    if claim == 2 { "P" } else { "Q" }
                );
                assert!(tuples.insert(label.clone()), "matrix-unique-tuple");
                let mut i = base(11, claim, "none");
                with_basis(&mut i, b);
                prepare_fault(&mut i, f, 11, claim);
                let independent = oracle.remove(&label).expect("independent tuple absent");
                let (code, stage, token, a) = matrix_oracle(b, f, claim);
                assert_eq!(
                    (code, stage, if a { "yes" } else { "no" }),
                    (independent[3], independent[4], independent[5]),
                    "{label}: independent-vs-author-expectation-review-HOLD"
                );
                let r = expect(&i, independent[3], independent[4], &label);
                assert_eq!(
                    r.trace().contains(&"A"),
                    independent[5] == "yes",
                    "{label}: independently-authored-A"
                );
                let normalized: Vec<&str> = r
                    .trace()
                    .iter()
                    .copied()
                    .filter(|s| {
                        !matches!(
                            *s,
                            "K1" | "K2"
                                | "K3"
                                | "K4"
                                | "K3.deferred_schema"
                                | "K4.deferred_posture"
                                | "artifact.parse"
                                | "E7"
                                | "E8.policy"
                                | "E8.clock"
                                | "E8.high_water"
                        )
                    })
                    .collect();
                assert_eq!(
                    normalized.join(","),
                    independent[7],
                    "{label}: independent-exact-phase-trace"
                );
                assert_eq!(r.trace().contains(&"A"), a, "{label}: complete-prefix-A");
                assert_eq!(
                    r.trace(),
                    expected_matrix_trace(b, token),
                    "{label}: exact-visited-stages"
                );
                if code == "POSTURE_MISMATCH" {
                    no_evidence(&r, &label);
                }
                if !a {
                    assert!(
                        r.actual_facts().is_none() || matches!(b, Basis::KnownFullQ),
                        "{label}: no-fabricated-complete-facts"
                    );
                }
                if !matches!(
                    b,
                    Basis::KnownFullP
                        | Basis::KnownFullQ
                        | Basis::ResolvedFullP
                        | Basis::ResolvedFullQ
                ) {
                    assert_eq!(r.schema_identity(), None, "{label}: scratch-schema-omitted");
                }
                count += 1;
            }
        }
    }
    assert!(oracle.is_empty(), "independent-every-literal-row-consumed");
    assert_eq!(count, 968, "matrix-exact-968-count");
    assert_eq!(tuples.len(), 968, "matrix-968-unique-tuples");
}
fn prepare_fault(i: &mut SimulationInput, f: Fault, v: u64, claim: u8) {
    if f == Fault::NotYet {
        let g = golden(v, claim, "notyet");
        i.evidence.artifact = Some(g.bytes.to_vec());
        i.evidence.handoff.artifact = g.artifact;
        i.evidence.artifact_hash = hash(b"", g.bytes, g.artifact);
        i.evidence.body_hash = hash(b"", g.body, g.body_digest);
        i.evidence.high_water.as_mut().unwrap().body_digest = g.body_digest;
    }
    apply_fault(i, f);
}

#[test]
fn early_evidence_cannot_mask_resolved_posture() {
    for (fault, name) in [
        (Fault::Missing, "MISSING"),
        (Fault::Legacy, "LEGACY"),
        (Fault::Syntax, "SYNTAX"),
    ] {
        for full in [true, false] {
            let label = format!("SD06-Q-{name}-{}", if full { "FULL" } else { "PARTIAL" });
            let mut i = base(11, 2, "none");
            i.observation.schema = SimulationSchema::NeedsSchemaProof;
            i.observation.posture = SimulationPosture::NeedsSchemaProof;
            i.actual_proof = proof(full, 9);
            apply_fault(&mut i, fault);
            let r = expect(
                &i,
                "POSTURE_MISMATCH",
                if full {
                    "complete_prefix"
                } else {
                    "resolved_prefix"
                },
                &label,
            );
            no_evidence(&r, &label);
            assert_eq!(
                r.posture_identity(),
                Some(id(9)),
                "{label}: independently-resolved-Q"
            );
            assert_eq!(
                r.trace().contains(&"A"),
                full,
                "{label}: full-versus-partial-prefix"
            );
            i.actual_proof = proof(full, 2);
            let (_, code, stage, _) = fault_oracle(fault).unwrap();
            expect(&i, code, stage, &format!("{label}-REMOVE-Q"));
            i.evidence = base(11, 2, "none").evidence;
            if full {
                pending(&i, &format!("{label}-RESTORE"));
            } else {
                expect(
                    &i,
                    "QUALIFICATION_UNRESOLVED",
                    "evidence.qualification",
                    &format!("{label}-P-LEDGER-MISSING"),
                );
                i.actual_proof = proof(true, 2);
                pending(&i, &format!("{label}-FULL-RESTORE"));
            }
        }
    }
}
#[test]
fn independent_proof_conflict_binding() {
    let mut rows = 0;
    for field in [
        "schema_identity",
        "posture_identity",
        "catalog_member_digest",
    ] {
        for q in [false, true] {
            for fault in [Fault::None, Fault::InvalidSignature, Fault::RecomputedId] {
                let label = format!(
                    "SD10-{field}-known_{}-{}",
                    if q { "Q" } else { "P" },
                    fault.name()
                );
                let mut i = base(11, 2, "none");
                i.actual_proof = proof(true, 2);
                if q {
                    i.observation.posture = SimulationPosture::Established(id(9));
                }
                match field {
                    "schema_identity" => {
                        i.actual_proof.schema.as_mut().unwrap().identity_hash.digest = id(8)
                    }
                    "posture_identity" => {
                        i.actual_proof
                            .posture
                            .as_mut()
                            .unwrap()
                            .identity_hash
                            .digest = id(8)
                    }
                    "catalog_member_digest" => i.observation.catalog_member_digest = Some(id(8)),
                    _ => unreachable!(),
                }
                apply_fault(&mut i, fault);
                let (code, stage) = if q {
                    ("POSTURE_MISMATCH", "prefix")
                } else if fault == Fault::InvalidSignature {
                    ("EVIDENCE_INVALID_SIGNATURE", "evidence.signers")
                } else {
                    ("EVIDENCE_BINDING_MISMATCH", "evidence.binding")
                };
                let r = expect(&i, code, stage, &label);
                assert_eq!(
                    r.schema_identity(),
                    Some(id(7)),
                    "{label}: preserve-established-schema"
                );
                assert_eq!(
                    r.posture_identity(),
                    Some(id(if q { 9 } else { 2 })),
                    "{label}: preserve-established-posture"
                );
                if q {
                    no_evidence(&r, &label);
                    i.observation.posture = SimulationPosture::Established(id(2));
                    let (code, stage) = if fault == Fault::InvalidSignature {
                        ("EVIDENCE_INVALID_SIGNATURE", "evidence.signers")
                    } else {
                        ("EVIDENCE_BINDING_MISMATCH", "evidence.binding")
                    };
                    expect(&i, code, stage, &format!("{label}-REMOVE-Q"));
                }
                // E5 removal reveals E6, and E6 precedes E7.
                i.evidence = base(11, 2, "none").evidence;
                i.observation.posture = SimulationPosture::Established(id(2));
                let r = expect(
                    &i,
                    "EVIDENCE_BINDING_MISMATCH",
                    "evidence.binding",
                    &format!("{label}-CONFLICT-ONLY"),
                );
                assert!(!r.trace().contains(&"E7"), "{label}: E6-before-E7");
                i.actual_proof = proof(true, 2);
                i.observation.catalog_member_digest = Some(id(13));
                apply_fault(&mut i, fault);
                if fault == Fault::None {
                    pending(&i, &format!("{label}-RESTORE"));
                } else {
                    let (_, code, stage, _) = fault_oracle(fault).unwrap();
                    expect(&i, code, stage, &format!("{label}-REMOVE-CONFLICT"));
                    i.evidence = base(11, 2, "none").evidence;
                    pending(&i, &format!("{label}-FULL-RESTORE"));
                }
                rows += 1;
            }
        }
    }
    for full in [true, false] {
        for fault in [Fault::None, Fault::InvalidSignature, Fault::RecomputedId] {
            let label = format!(
                "SD10-Q-{}-{}",
                if full { "FULL" } else { "PARTIAL" },
                fault.name()
            );
            let mut i = base(11, 2, "none");
            i.observation.schema = SimulationSchema::NeedsSchemaProof;
            i.observation.posture = SimulationPosture::NeedsSchemaProof;
            i.observation.catalog_member_digest = Some(id(8));
            i.actual_proof = proof(full, 9);
            apply_fault(&mut i, fault);
            // Supplemental catalog conflict must not erase an independently proved Q.
            let r = expect(
                &i,
                "POSTURE_MISMATCH",
                if full {
                    "complete_prefix"
                } else {
                    "resolved_prefix"
                },
                &label,
            );
            no_evidence(&r, &label);
            assert_eq!(
                r.posture_identity(),
                Some(id(9)),
                "{label}: Q-still-authoritative"
            );
            i.actual_proof = proof(full, 2);
            let (code, stage) = if fault == Fault::InvalidSignature {
                ("EVIDENCE_INVALID_SIGNATURE", "evidence.signers")
            } else {
                ("EVIDENCE_BINDING_MISMATCH", "evidence.binding")
            };
            expect(&i, code, stage, &format!("{label}-REMOVE-Q"));
            i.observation.catalog_member_digest = Some(id(13));
            i.actual_proof = proof(true, 2);
            i.evidence = base(11, 2, "none").evidence;
            pending(&i, &format!("{label}-RESTORE"));
            rows += 1;
        }
    }
    assert_eq!(rows, 24, "SD10: separate-24-conflict-rows");
}

#[test]
fn raw_stage_restoration() {
    use schema_adapter_simulation::canonical::parse_attestation;
    let invalid: [(&str, &[u8]); 5] = [
        ("W01", include_bytes!("../../fixtures/canonical-w01.json")),
        ("W02", include_bytes!("../../fixtures/canonical-w02.json")),
        ("W03", include_bytes!("../../fixtures/canonical-w03.json")),
        ("W04", include_bytes!("../../fixtures/canonical-w04.json")),
        ("W05", include_bytes!("../../fixtures/canonical-w05.json")),
    ];
    for (label, bytes) in invalid {
        assert!(
            parse_attestation(bytes).is_err(),
            "{label}: raw-parser-rejects"
        );
        let mut i = base(10, 2, "none");
        i.evidence.artifact = Some(bytes.to_vec());
        let r = expect(&i, "EVIDENCE_MALFORMED", "evidence.syntax", label);
        assert!(
            !r.trace().contains(&"E5"),
            "{label}: no-verifier-after-syntax"
        );
        assert!(
            !r.trace().contains(&"P"),
            "{label}: no-profile-after-syntax"
        );
        pending(&base(10, 2, "none"), &format!("{label}-RESTORE-W00"));
    }
    for label in ["W06a", "W06b"] {
        let i = base(10, 2, "binary");
        assert!(
            parse_attestation(i.evidence.artifact.as_ref().unwrap()).is_ok(),
            "{label}: parser-success"
        );
        expect(&i, "EVIDENCE_BINDING_MISMATCH", "evidence.binding", label);
        pending(&base(10, 2, "none"), &format!("{label}-BINARY-RESTORE"));
    }
    let i = base(10, 9, "none");
    assert!(
        parse_attestation(i.evidence.artifact.as_ref().unwrap()).is_ok(),
        "W07a: parser-success"
    );
    let r = expect(
        &i,
        "QUALIFICATION_UNRESOLVED",
        "evidence.qualification",
        "W07a",
    );
    assert!(r.trace().contains(&"A"));
    assert!(r.trace().contains(&"E8.persistence"));
    assert_eq!(
        r.posture_identity(),
        Some(id(2)),
        "W07a: actual-not-claimed-posture"
    );
    pending(&base(10, 2, "none"), "W07a-RESTORE");
    let i = base(10, 2, "schema");
    assert!(
        parse_attestation(i.evidence.artifact.as_ref().unwrap()).is_ok(),
        "W07b: parser-success"
    );
    let r = expect(
        &i,
        "QUALIFICATION_UNRESOLVED",
        "evidence.qualification",
        "W07b",
    );
    assert_eq!(
        r.schema_identity(),
        Some(id(3)),
        "W07b: preserve-independent-schema"
    );
    assert!(!r.trace().contains(&"P"));
    pending(&base(10, 2, "none"), "W07b-RESTORE");
    for (f, label) in [(Fault::RecomputedId, "W08a"), (Fault::SelectedId, "W08b")] {
        let mut i = base(10, 2, "none");
        apply_fault(&mut i, f);
        let r = expect(
            &i,
            "EVIDENCE_PROFILE_MISMATCH",
            "evidence.profile_id",
            label,
        );
        assert!(
            !r.trace().contains(&"E8.prerequisites"),
            "{label}: no-high-water-lookup"
        );
        pending(&base(10, 2, "none"), &format!("{label}-RESTORE"));
    }
}

#[test]
fn exact_acquisition_diagnoses() {
    for posture in [
        SimulationPosture::Established(id(2)),
        SimulationPosture::NeedsSchemaProof,
    ] {
        for (label, v, s, code, stage) in [
            (
                "EX01",
                9,
                SimulationSchema::NeedsSchemaProof,
                "BELOW_EXACT",
                "exact.assess",
            ),
            (
                "EX02",
                11,
                SimulationSchema::NeedsSchemaProof,
                "ABOVE_EXACT",
                "exact.assess",
            ),
            (
                "EX03",
                10,
                SimulationSchema::ProvenUnequalToBuild,
                "SCHEMA_MISMATCH",
                "exact.comparison",
            ),
            (
                "EX04",
                10,
                SimulationSchema::NeedsSchemaProof,
                "QUALIFICATION_UNRESOLVED",
                "exact.proof",
            ),
            (
                "EX05",
                10,
                SimulationSchema::Established(id(8)),
                "SCHEMA_MISMATCH",
                "exact.assess",
            ),
        ] {
            let mut i = base(10, 2, "none");
            i.selection = SimulationSelection::Exact;
            i.acquisition.version = Ok(v);
            i.observation.schema = s;
            i.observation.posture = posture;
            i.evidence.artifact = None;
            let r = expect(&i, code, stage, label);
            no_evidence(&r, label);
            assert!(!r.trace().contains(&"A"));
            assert!(!r.trace().contains(&"P"));
            assert!(!r.trace().contains(&"N"));
            if s != SimulationSchema::Established(id(8)) {
                assert_eq!(r.schema_identity(), None, "{label}: no-comparison-digest");
            }
            i.acquisition.version = Ok(10);
            i.observation.schema = SimulationSchema::Established(id(3));
            i.observation.posture = SimulationPosture::Established(id(2));
            pending(&i, &format!("{label}-RESTORE"));
        }
    }
    let mut i = base(10, 2, "none");
    i.selection = SimulationSelection::Exact;
    i.observation.posture = SimulationPosture::NeedsSchemaProof;
    i.actual_proof = proof(true, 2);
    i.actual_proof.members.as_mut().unwrap().handoff_digest = id(8);
    let r = expect(&i, "QUALIFICATION_UNRESOLVED", "exact.proof", "EX06-EX07");
    assert!(
        r.trace().contains(&"K4.deferred_posture"),
        "EX07: deferred-posture"
    );
    no_evidence(&r, "EX07");
    assert!(!r.trace().contains(&"E9a"));
    assert_eq!(
        r.posture_identity(),
        None,
        "EX07: member-auth-no-established-posture"
    );
    for (v, code) in [(9, "BELOW_EXACT"), (11, "ABOVE_EXACT")] {
        i.acquisition.version = Ok(v);
        expect(&i, code, "exact.assess", "EX07-negative-version");
    }
    i.acquisition.version = Ok(10);
    i.selection = SimulationSelection::InventoryUnresolved;
    let r = expect(&i, "INVENTORY_UNRESOLVED", "selection.inventory", "IU07");
    assert_eq!(
        r.posture_identity(),
        None,
        "IU07: member-auth-no-established-posture"
    );
    no_evidence(&r, "IU07");
    i.observation.posture = SimulationPosture::Established(id(2));
    expect(
        &i,
        "INVENTORY_UNRESOLVED",
        "selection.inventory",
        "IU07-RESTORE-PROOF",
    );
    i.selection = SimulationSelection::Exact;
    pending(&i, "EX07-RESTORE-PROOF");
}

#[test]
fn acquisition_precedence() {
    let errors = [
        ProbeFailure::MissingBaseline,
        ProbeFailure::PermissionDenied,
        ProbeFailure::Timeout,
        ProbeFailure::ConnectionLost,
        ProbeFailure::Other,
    ];
    let codes = [
        "MISSING_BASELINE",
        "PROBE_PERMISSION_DENIED",
        "PROBE_TIMEOUT",
        "PROBE_CONNECTION_LOST",
        "PROBE_OTHER",
    ];
    for (e, code) in errors.into_iter().zip(codes) {
        let mut i = base(10, 2, "none");
        i.build.schema_version = 0;
        i.acquisition.installation = SimulationInstallation::ForeignOrUnbound;
        i.acquisition.generation = SimulationGeneration::MixedOrUnbound;
        i.acquisition.version = Err(e);
        i.observation.schema = SimulationSchema::Established(id(0));
        i.observation.posture = SimulationPosture::Established(id(9));
        expect(&i, "MALFORMED_BUILD", "build", "C-build-before-envelope");
        i.build = build();
        let r = expect(
            &i,
            "EVIDENCE_BINDING_MISMATCH",
            "acquisition.installation",
            "C-installation-before-generation-probe",
        );
        assert_eq!(r.actual_facts(), None, "C: discard-tainted-facts");
        i.acquisition.installation = SimulationInstallation::Bound;
        expect(
            &i,
            "OBSERVATION_GENERATION_MISMATCH",
            "acquisition.generation",
            "C-generation-before-probe",
        );
        i.acquisition.generation = SimulationGeneration::Coherent;
        expect(&i, code, "acquisition.version", "C-actual-probe-preserved");
        i.acquisition.version = Ok(10);
        expect(
            &i,
            "MALFORMED_DATABASE",
            "prefix",
            "C-restore-probe-exposes-zero",
        );
        i.observation.schema = SimulationSchema::Established(id(3));
        expect(&i, "POSTURE_MISMATCH", "prefix", "C-restore-zero-exposes-Q");
        i.observation.posture = SimulationPosture::Established(id(2));
        pending(&i, "C-clean-actual-no-standin-Other");
    }
    for field in 0..4 {
        let mut i = base(10, 2, "none");
        match field {
            0 => i.build.schema_version = 0,
            1 => i.build.binary = id(0),
            2 => i.build.schema_identity = id(0),
            3 => i.build.required_posture = id(0),
            _ => unreachable!(),
        };
        i.acquisition.installation = SimulationInstallation::ForeignOrUnbound;
        expect(&i, "MALFORMED_BUILD", "build", "G-all-build-zero-fields");
    }
    let mut i = base(10, 2, "none");
    apply_fault(&mut i, Fault::Binding);
    let r = expect(
        &i,
        "EVIDENCE_BINDING_MISMATCH",
        "evidence.binding",
        "C-same-code-later-stage",
    );
    assert!(r.trace().contains(&"E6"));
    i.acquisition.installation = SimulationInstallation::ForeignOrUnbound;
    let r = expect(
        &i,
        "EVIDENCE_BINDING_MISMATCH",
        "acquisition.installation",
        "C-same-code-envelope-stage",
    );
    assert_eq!(r.trace(), ["G", "C"]);
}

#[test]
fn prefix_matches_assessor() {
    for malformed in 0..5 {
        for version in [0, 1, 9, 10, 11, u64::MAX] {
            for schema in [id(0), id(3), id(8)] {
                for posture in [id(0), id(2), id(9)] {
                    let mut i = base(10, 2, "none");
                    match malformed {
                        1 => i.build.schema_version = 0,
                        2 => i.build.binary = id(0),
                        3 => i.build.schema_identity = id(0),
                        4 => i.build.required_posture = id(0),
                        _ => {}
                    }
                    i.acquisition.version = Ok(version);
                    i.observation.schema = SimulationSchema::Established(schema);
                    i.observation.posture = SimulationPosture::Established(posture);
                    i.selection = SimulationSelection::InventoryUnresolved;
                    let reference = assess(
                        i.build,
                        Ok(DatabaseFacts {
                            version,
                            schema_identity: schema,
                            posture,
                        }),
                        ProfileClaims::InventoryUnresolved,
                    );
                    let r = compose_simulation(&i);
                    assert_eq!(
                        r.code(),
                        simulation_assessor_code(reference),
                        "full-prefix-differential-{malformed}-{version}-{schema:?}-{posture:?}"
                    );
                    no_evidence(&r, "full-prefix-differential");
                }
            }
        }
    }
    for e in [
        ProbeFailure::MissingBaseline,
        ProbeFailure::PermissionDenied,
        ProbeFailure::Timeout,
        ProbeFailure::ConnectionLost,
        ProbeFailure::Other,
    ] {
        let mut i = base(10, 2, "none");
        i.acquisition.version = Err(e);
        let r = compose_simulation(&i);
        assert_eq!(
            r.code(),
            simulation_assessor_code(assess(build(), Err(e), ProfileClaims::InventoryUnresolved)),
            "full-prefix-typed-probe-{e:?}"
        );
    }
}
#[test]
fn partial_prefix_matches_assessor() {
    let schemas = [
        SimulationSchema::Established(id(0)),
        SimulationSchema::Established(id(7)),
        SimulationSchema::NeedsSchemaProof,
    ];
    let postures = [
        SimulationPosture::Established(id(0)),
        SimulationPosture::Established(id(2)),
        SimulationPosture::Established(id(9)),
        SimulationPosture::MissingIndependentObservation,
        SimulationPosture::NeedsSchemaProof,
    ];
    let versions = [
        Ok(0),
        Ok(1),
        Ok(9),
        Ok(10),
        Ok(11),
        Ok(u64::MAX),
        Err(ProbeFailure::MissingBaseline),
        Err(ProbeFailure::PermissionDenied),
        Err(ProbeFailure::Timeout),
        Err(ProbeFailure::ConnectionLost),
        Err(ProbeFailure::Other),
    ];
    for malformed in 0..5 {
        for v in versions {
            for schema in schemas {
                for posture in postures {
                    for basis in [
                        Basis::AbsentP,
                        Basis::MalformedP,
                        Basis::UnboundP,
                        Basis::IncompleteP,
                        Basis::DisagreeingP,
                        Basis::ResolvedFullP,
                    ] {
                        let mut i = base(11, 2, "none");
                        with_basis(&mut i, basis);
                        i.observation.schema = schema;
                        i.observation.posture = posture;
                        i.acquisition.version = v;
                        match malformed {
                            1 => i.build.schema_version = 0,
                            2 => i.build.binary = id(0),
                            3 => i.build.schema_identity = id(0),
                            4 => i.build.required_posture = id(0),
                            _ => {}
                        }
                        // Independent differential uses only unchanged assess and contract scratch.
                        let probe = v.map(|version| DatabaseFacts {
                            version,
                            schema_identity: match schema {
                                SimulationSchema::Established(id) => id,
                                _ => id(1),
                            },
                            posture: match posture {
                                SimulationPosture::Established(id) => id,
                                _ => i.build.required_posture,
                            },
                        });
                        let reference = assess(i.build, probe, ProfileClaims::InventoryUnresolved);
                        let label = format!(
                            "partial-prefix-{malformed}-{v:?}-{schema:?}-{posture:?}-{basis:?}"
                        );
                        let r = compose_simulation(&i);
                        match reference {
                            Assessment::RefuseBusiness(reason) => {
                                assert_eq!(
                                    r.code(),
                                    simulation_assessor_code(Assessment::RefuseBusiness(reason)),
                                    "{label}: unchanged-prefix-diagnosis"
                                );
                                no_evidence(&r, &label);
                            }
                            Assessment::HoldInventory => {
                                if posture == SimulationPosture::MissingIndependentObservation {
                                    assert_eq!(
                                        r.code(),
                                        "POSTURE_UNKNOWN",
                                        "{label}: independent-missing-posture"
                                    );
                                    no_evidence(&r, &label);
                                } else {
                                    assert!(
                                        r.trace().contains(&"E9a"),
                                        "{label}: available-facts-pass-only"
                                    );
                                    if r.trace().contains(&"A") {
                                        assert!(
                                            r.actual_facts().is_some(),
                                            "{label}: A-only-actual-completion"
                                        );
                                    }
                                    if r.trace().contains(&"P") {
                                        assert!(
                                            r.trace().contains(&"A") && r.trace().contains(&"E9b"),
                                            "{label}: P-after-complete-qualification"
                                        );
                                    }
                                }
                            }
                            Assessment::CompatibleRequiresAdmissionFence(_) => {
                                panic!("independent Inventory prefix impossible")
                            }
                        }
                        if schema == SimulationSchema::NeedsSchemaProof && !r.trace().contains(&"A")
                        {
                            assert_eq!(
                                r.schema_identity(),
                                None,
                                "{label}: sentinel-never-escapes"
                            );
                        }
                    }
                }
            }
        }
    }
    let mut i = base(11, 2, "none");
    i.acquisition.version = Ok(0);
    i.observation.schema = SimulationSchema::NeedsSchemaProof;
    i.observation.posture = SimulationPosture::NeedsSchemaProof;
    let r = expect(&i, "MALFORMED_DATABASE", "prefix", "K-stop-at-database");
    assert!(
        !r.trace().contains(&"K4"),
        "K-stop-at-database: no-later-posture-check"
    );
    assert!(
        !r.trace().contains(&"K4.deferred_posture"),
        "K-stop-at-database: no-later-posture-annotation"
    );
}

#[test]
fn partial_schema_descriptor_precedence() {
    for basis in [
        Basis::AbsentP,
        Basis::MalformedP,
        Basis::UnboundP,
        Basis::IncompleteP,
        Basis::DisagreeingP,
    ] {
        let mut i = base(11, 2, "none");
        with_basis(&mut i, basis);
        let (code, stage, _, _) = matrix_oracle(basis, Fault::None, 2);
        let r = expect(&i, code, stage, &format!("SD01-05-{basis:?}"));
        assert!(!r.trace().contains(&"A"));
        assert!(!r.trace().contains(&"P"));
        assert!(!r.trace().contains(&"N"));
        assert_eq!(r.schema_identity(), None, "SD01-05: no-sentinel-schema");
        assert_eq!(r.actual_facts(), None, "SD01-05: no-DatabaseFacts");
        for early in 0..4 {
            let mut j = i.clone();
            let (code, stage) = match early {
                0 => {
                    j.build.schema_version = 0;
                    ("MALFORMED_BUILD", "build")
                }
                1 => {
                    j.acquisition.version = Err(ProbeFailure::PermissionDenied);
                    ("PROBE_PERMISSION_DENIED", "acquisition.version")
                }
                2 => {
                    j.observation.posture = SimulationPosture::Established(id(0));
                    ("MALFORMED_DATABASE", "prefix")
                }
                3 => {
                    j.observation.posture = SimulationPosture::Established(id(9));
                    ("POSTURE_MISMATCH", "prefix")
                }
                _ => unreachable!(),
            };
            let r = expect(
                &j,
                code,
                stage,
                &format!("SD-prefix-conflict-{basis:?}-{early}"),
            );
            no_evidence(&r, "SD-prefix-conflict");
            assert!(
                !r.trace().contains(&"E9a"),
                "SD-prefix-conflict: no-proof-inspection"
            );
        }
        i.actual_proof = proof(true, 2);
        pending(&i, &format!("SD01-05-{basis:?}-RESTORE"));
    }
    let mut i = base(11, 2, "none");
    with_basis(&mut i, Basis::AbsentDeferred);
    expect(
        &i,
        "QUALIFICATION_UNRESOLVED",
        "evidence.qualification",
        "SD06",
    );
    i.observation.posture = SimulationPosture::MissingIndependentObservation;
    let r = expect(&i, "POSTURE_UNKNOWN", "prefix.posture", "SD07-SD04-P");
    no_evidence(&r, "SD07-SD04-P");
    i.observation.posture = SimulationPosture::Established(id(2));
    i.observation.schema = SimulationSchema::Established(id(0));
    expect(&i, "MALFORMED_DATABASE", "prefix", "SD08");
    with_basis(&mut i, Basis::ResolvedFullP);
    i.actual_proof.members.as_mut().unwrap().bytes.push(b' ');
    let r = expect(
        &i,
        "EVIDENCE_MALFORMED",
        "evidence.syntax",
        "SD09-invalid-syntax",
    );
    assert_eq!(
        r.posture_identity(),
        None,
        "SD09-invalid-syntax: no-unbound-posture"
    );
    with_basis(&mut i, Basis::ResolvedFullP);
    i.actual_proof
        .members
        .as_mut()
        .unwrap()
        .hash
        .input
        .push(b'x');
    let r = expect(&i, "EVIDENCE_BINDING_MISMATCH", "evidence.binding", "SD09");
    assert_eq!(
        r.posture_identity(),
        None,
        "SD09: no-unbound-established-posture"
    );
    assert_eq!(r.schema_identity(), None, "SD09: no-unbound-schema");
    assert!(!r.trace().contains(&"A"), "SD09: no-complete-prefix");
    i.actual_proof = proof(true, 2);
    pending(&i, "SD09-RESTORE");
}

#[test]
fn forward_schema_descriptor() {
    let mut i = base(11, 2, "none");
    with_basis(&mut i, Basis::ResolvedFullP);
    let original = i.build;
    pending(&i, "ROLL01");
    let r = compose_simulation(&i);
    assert_eq!(
        r.schema_identity(),
        Some(id(7)),
        "ROLL01: independently-proved-forward-schema"
    );
    assert_eq!(
        r.posture_identity(),
        Some(id(2)),
        "ROLL01: unchanged-required-posture"
    );
    assert_eq!(i.build, original, "ROLL01: immutable-B1-contract");
    i.observation.schema = SimulationSchema::ProvenUnequalToBuild;
    pending(&i, "ROLL01-SELECTED-UNEQUAL-COMPARISON");
    i.actual_proof = proof(true, 9);
    let r = expect(&i, "POSTURE_MISMATCH", "complete_prefix", "ROLL02");
    no_evidence(&r, "ROLL02");
    // Neither selected-artifact binding nor epoch can authenticate actual proof.
    for fault in [
        Fault::Binding,
        Fault::InvalidSignature,
        Fault::Revoked,
        Fault::Expired,
        Fault::Replay,
        Fault::Equivocation,
        Fault::Persistence,
    ] {
        let mut j = i.clone();
        prepare_fault(&mut j, fault, 11, 2);
        let r = expect(
            &j,
            "POSTURE_MISMATCH",
            "complete_prefix",
            "ROLL02-independent-evidence-conflicts",
        );
        no_evidence(&r, "ROLL02-independent-evidence-conflicts");
    }
    i.evidence.handoff.release_epoch = "foreign-epoch".into();
    let r = expect(
        &i,
        "POSTURE_MISMATCH",
        "complete_prefix",
        "ROLL02-independent-epoch-before-E6",
    );
    no_evidence(&r, "ROLL02-independent-epoch-before-E6");
    for auth in [
        SimulationAuthentication::Unavailable,
        SimulationAuthentication::Invalid,
    ] {
        for fault in [
            Fault::None,
            Fault::InvalidSignature,
            Fault::Binding,
            Fault::Revoked,
        ] {
            let mut j = base(11, 2, "none");
            with_basis(&mut j, Basis::ResolvedFullQ);
            j.actual_proof.schema.as_mut().unwrap().authentication = auth;
            j.actual_proof.posture.as_mut().unwrap().authentication = auth;
            j.actual_proof.members.as_mut().unwrap().authentication = auth;
            apply_fault(&mut j, fault);
            let (code, stage) = if fault == Fault::InvalidSignature {
                ("EVIDENCE_INVALID_SIGNATURE", "evidence.signers")
            } else {
                ("EVIDENCE_BINDING_MISMATCH", "evidence.binding")
            };
            let r = expect(&j, code, stage, "SD06-UNTRUSTED-D2");
            assert_eq!(
                r.posture_identity(),
                None,
                "SD06-UNTRUSTED-D2: signature-cannot-establish-Q"
            );
            assert!(!r.trace().contains(&"A"));
            j.actual_proof = proof(true, 9);
            expect(
                &j,
                "POSTURE_MISMATCH",
                "complete_prefix",
                "SD06-UNTRUSTED-D2-RESTORE-AUTH",
            );
        }
    }
}

fn feasible_pair(a: Fault, b: Fault) -> bool {
    if a == Fault::None || b == Fault::None || a == b {
        return false;
    }
    if (a == Fault::Missing && b == Fault::Syntax) || (a == Fault::Syntax && b == Fault::Missing) {
        return false;
    }
    let signer = |f| {
        matches!(
            f,
            Fault::UnknownSigner | Fault::InvalidSignature | Fault::Threshold
        )
    };
    if signer(a) && signer(b) {
        return false;
    }
    if matches!(
        (a, b),
        (Fault::NotYet, Fault::Expired)
            | (Fault::Expired, Fault::NotYet)
            | (Fault::Replay, Fault::Equivocation)
            | (Fault::Equivocation, Fault::Replay)
    ) {
        return false;
    }
    // Absent policy contains no authenticated revocation claim. Missing qualification
    // cannot simultaneously carry a conflicting receipt schema/posture field.
    if (a == Fault::Policy && b == Fault::Revoked) || (b == Fault::Policy && a == Fault::Revoked) {
        return false;
    }
    if (a == Fault::Clock && matches!(b, Fault::NotYet | Fault::Expired))
        || (b == Fault::Clock && matches!(a, Fault::NotYet | Fault::Expired))
    {
        return false;
    }
    if (a == Fault::HighWater && matches!(b, Fault::Replay | Fault::Equivocation))
        || (b == Fault::HighWater && matches!(a, Fault::Replay | Fault::Equivocation))
    {
        return false;
    }
    if (a == Fault::Qualification && matches!(b, Fault::SchemaClaim | Fault::PostureClaim))
        || (b == Fault::Qualification && matches!(a, Fault::SchemaClaim | Fault::PostureClaim))
    {
        return false;
    }
    true
}
fn paired(a: Fault, b: Fault) -> SimulationInput {
    let mut i = base(11, 2, "none");
    // Prepare canonical time bytes first; malformed/absent artifact is the later
    // independently chosen fault and must not be repaired by fixture preparation.
    if a == Fault::NotYet || b == Fault::NotYet {
        prepare_fault(&mut i, Fault::NotYet, 11, 2);
    }
    if a != Fault::NotYet {
        apply_fault(&mut i, a);
    }
    if b != Fault::NotYet {
        apply_fault(&mut i, b);
    }
    i
}
#[test]
fn evidence_precedence_conflicts() {
    let mut pairs = 0;
    let mut pair_ids = BTreeSet::new();
    for a in FAULTS {
        for b in FAULTS {
            if !feasible_pair(a, b) {
                continue;
            }
            let ra = fault_oracle(a).unwrap();
            let rb = fault_oracle(b).unwrap();
            // This loop enumerates ordered faults, with each precedence pair once.
            if ra.0 > rb.0 || (ra.0 == rb.0 && a.name() >= b.name()) {
                continue;
            }
            let label = format!("ordered-conflict-{}-{}", a.name(), b.name());
            assert!(
                pair_ids.insert(label.clone()),
                "ordered-conflicts: unique-pair-ID {label}"
            );
            let i = paired(a, b);
            let r = expect(&i, ra.1, ra.2, &label);
            assert!(!r.trace().contains(&"P"), "{label}: no-profile-or-fallback");
            // Remove only the first fault: the second remains observable.
            let mut second = base(11, 2, "none");
            prepare_fault(&mut second, b, 11, 2);
            expect(&second, rb.1, rb.2, &format!("{label}-REMOVE-FIRST"));
            pending(&base(11, 2, "none"), &format!("{label}-RESTORE"));
            for full in [true, false] {
                let mut q = i.clone();
                q.observation.schema = SimulationSchema::NeedsSchemaProof;
                q.observation.posture = SimulationPosture::NeedsSchemaProof;
                q.actual_proof = proof(full, 9);
                let r = expect(
                    &q,
                    "POSTURE_MISMATCH",
                    if full {
                        "complete_prefix"
                    } else {
                        "resolved_prefix"
                    },
                    &format!("{label}-Q-{full}"),
                );
                no_evidence(&r, &label);
                q.actual_proof = proof(full, 2);
                expect(&q, ra.1, ra.2, &format!("{label}-REMOVE-Q-{full}"));
            }
            pairs += 1;
        }
    }
    // 21 failure classes choose2 =210, minus13 explicit mutually exclusive pairs.
    assert_eq!(
        pairs, 197,
        "ordered-conflicts: exact-197-feasible-class-pairs"
    );
    assert_eq!(
        pair_ids.len(),
        197,
        "ordered-conflicts: exact-197-unique-pair-IDs"
    );
    let mut i = base(10, 2, "none");
    i.evidence.artifact = None;
    expect(
        &i,
        "MISSING_SELECTED_EVIDENCE",
        "evidence.presence",
        "selected-missing-exact-version-no-fallback",
    );
    i.selection = SimulationSelection::Exact;
    pending(&i, "selected-missing-Exact-is-separate-control");
    i = base(10, 2, "none");
    apply_fault(&mut i, Fault::Expired);
    expect(
        &i,
        "EVIDENCE_STALE",
        "evidence.currentness.time",
        "stale-selected-exact-no-fallback",
    );
    for full in [true, false] {
        for f in FAULTS {
            let mut j = base(11, 2, "none");
            with_basis(
                &mut j,
                if full {
                    Basis::ResolvedFullQ
                } else {
                    Basis::ResolvedPartialQ
                },
            );
            prepare_fault(&mut j, f, 11, 2);
            let r = expect(
                &j,
                "POSTURE_MISMATCH",
                if full {
                    "complete_prefix"
                } else {
                    "resolved_prefix"
                },
                "Q-cross-every-evidence-class",
            );
            no_evidence(&r, "Q-cross-every-evidence-class");
        }
    }
}
#[test]
fn currentness_and_binding_domains() {
    // Prerequisites before revocation before time before sequence before persistence.
    let mut i = base(11, 2, "none");
    apply_fault(&mut i, Fault::Revoked);
    apply_fault(&mut i, Fault::Expired);
    apply_fault(&mut i, Fault::Replay);
    i.evidence.persistence = SimulationPersistence::Unknown;
    expect(
        &i,
        "EVIDENCE_REVOKED",
        "evidence.currentness.revocation",
        "C06-revoked-before-stale-replay",
    );
    i.evidence.clock = SimulationClock::Unavailable;
    expect(
        &i,
        "EVIDENCE_CURRENTNESS_UNKNOWN",
        "evidence.currentness.prerequisites",
        "C05-clock-before-revocation",
    );
    i.evidence.clock = SimulationClock::Trusted(100);
    i.evidence
        .policy
        .as_mut()
        .unwrap()
        .revoked_artifacts
        .clear();
    expect(
        &i,
        "EVIDENCE_STALE",
        "evidence.currentness.time",
        "C06-remove-revoked",
    );
    i.evidence.clock = SimulationClock::Trusted(50);
    expect(
        &i,
        "EVIDENCE_REPLAY",
        "evidence.currentness.sequence",
        "C06-remove-stale",
    );
    i.evidence.high_water.as_mut().unwrap().sequence = 1;
    expect(
        &i,
        "EVIDENCE_CURRENTNESS_UNKNOWN",
        "evidence.currentness.persistence",
        "C06-remove-replay",
    );
    i.evidence.persistence = SimulationPersistence::Committed;
    pending(&i, "C06-full-restore");
    let mut i = base(11, 2, "none");
    i.evidence.clock = SimulationClock::Trusted(0);
    pending(&i, "C-not-before-equality");
    i.evidence.clock = SimulationClock::Trusted(100);
    expect(
        &i,
        "EVIDENCE_STALE",
        "evidence.currentness.time",
        "C-expiry-equality",
    );
    for field in 0..7 {
        let mut i = base(11, 2, "none");
        let h = i.evidence.high_water.as_mut().unwrap();
        match field {
            0 => h.installation_id = id(8),
            1 => h.timeline_id = id(8),
            2 => h.release_epoch = "foreign".into(),
            3 => h.profile = id(8),
            4 => i.evidence.policy.as_mut().unwrap().trust_generation = 2,
            5 => i.evidence.policy.as_mut().unwrap().release_epoch = "foreign".into(),
            6 => i.evidence.policy.as_mut().unwrap().expires_at = 50,
            _ => unreachable!(),
        };
        let r = expect(
            &i,
            "EVIDENCE_CURRENTNESS_UNKNOWN",
            "evidence.currentness.prerequisites",
            "currentness-domain-boundary",
        );
        assert!(
            !r.trace().contains(&"E8.revocation"),
            "currentness-domain-boundary: no-untrusted-revocation"
        );
    }
    for p in [
        SimulationPersistence::Denied,
        SimulationPersistence::Unknown,
    ] {
        let mut i = base(11, 2, "none");
        i.evidence.persistence = p;
        expect(
            &i,
            "EVIDENCE_CURRENTNESS_UNKNOWN",
            "evidence.currentness.persistence",
            "persist-before-qualification",
        );
    }
    for field in 0..10 {
        let mut i = base(11, 2, "none");
        match field {
            0 => i.evidence.handoff.authentication = SimulationAuthentication::Unavailable,
            1 => i.evidence.handoff.generation = 41,
            2 => i.evidence.handoff.release_epoch = "foreign".into(),
            3 => i.evidence.handoff.trust_generation = 2,
            4 => i.evidence.handoff.issuer_manifest = id(8),
            5 => i.evidence.handoff.qualification = id(8),
            6 => i.evidence.artifact_hash.input.push(b' '),
            7 => i.evidence.body_hash.input.push(b' '),
            8 => i.evidence.handoff.installation_id = id(0),
            9 => i.evidence.handoff.timeline_id = id(0),
            _ => unreachable!(),
        };
        expect(
            &i,
            "EVIDENCE_BINDING_MISMATCH",
            "evidence.binding",
            "handoff-exact-bindings",
        );
    }
    for domain in [b"".as_slice(), b"setjoin.schema.profile.v2\0".as_slice()] {
        let mut i = base(11, 2, "none");
        i.evidence.profile_hash = hash(
            domain,
            golden(11, 2, "none").core,
            i.evidence.profile_hash.digest,
        );
        let r = expect(
            &i,
            "EVIDENCE_PROFILE_MISMATCH",
            "evidence.profile_id",
            "profile-domain-separation",
        );
        assert!(
            !r.trace().contains(&"E8.prerequisites"),
            "profile-domain-separation: no-high-water"
        );
    }
    for field in 0..6 {
        let mut i = base(11, 2, "none");
        let q = i.evidence.qualification.as_mut().unwrap();
        match field {
            0 => q.authentication = SimulationAuthentication::Unavailable,
            1 => q.digest = id(8),
            2 => q.binary = id(8),
            3 => q.version = 10,
            4 => q.schema = id(8),
            5 => q.profile = id(8),
            _ => unreachable!(),
        };
        expect(
            &i,
            "QUALIFICATION_UNRESOLVED",
            "evidence.qualification",
            "qualification-exact-bindings",
        );
    }
    pending(&base(11, 2, "none"), "equal-sequence-equal-body-idempotent");
    let mut i = base(11, 2, "none");
    i.evidence.high_water.as_mut().unwrap().sequence = 0;
    pending(&i, "advance-sequence-after-committed-persistence");
}
#[test]
fn reports_remain_synthetic() {
    for fault in FAULTS {
        let mut i = base(11, 2, "none");
        prepare_fault(&mut i, fault, 11, 2);
        i.evidence.signers.push(SimulationSigner {
            key_id: "/secret/untrusted/attacker-string".into(),
            result: SimulationSignerResult::UnknownOrUnauthorized,
        });
        let r = compose_simulation(&i);
        assert_eq!(r.provenance(), "synthetic", "REP01: synthetic-provenance");
        assert!(
            matches!(
                r.outcome(),
                SimulationOutcome::Deny
                    | SimulationOutcome::HoldInventory
                    | SimulationOutcome::CompatiblePendingFence
            ),
            "REP01: no-runtime-admitted"
        );
        assert_eq!(r.safe_action(), SimulationSafeAction::InspectLocalRecovery);
        assert!(
            !format!("{r:?}").contains("attacker-string"),
            "REP01: no-untrusted-text"
        );
    }
    let mut i = base(11, 2, "none");
    with_basis(&mut i, Basis::AbsentDeferred);
    let r = expect(
        &i,
        "QUALIFICATION_UNRESOLVED",
        "evidence.qualification",
        "REP01-unresolved",
    );
    assert_eq!(r.schema_identity(), None, "REP01: no-scratch-schema");
    assert_eq!(r.posture_identity(), None, "REP01: no-scratch-posture");
    assert_eq!(r.actual_facts(), None, "REP01: no-scratch-DatabaseFacts");
    i.cancelled = true;
    let r = expect(
        &i,
        "STARTUP_CANCELLED",
        "startup.cancelled",
        "REP01-cancel-before-work",
    );
    assert!(r.trace().is_empty(), "REP01: cancellation-no-new-work");
    assert_eq!(r.version(), None);
    assert_eq!(r.build(), None);
}

#[test]
fn zero_generation_invalidates_acquisition() {
    fn no_retained_facts(r: &SimulationReport, label: &str) {
        assert_eq!(r.version(), None, "{label}: zero-generation-no-version");
        assert_eq!(
            r.schema_identity(),
            None,
            "{label}: zero-generation-no-schema"
        );
        assert_eq!(
            r.posture_identity(),
            None,
            "{label}: zero-generation-no-posture"
        );
        assert_eq!(
            r.actual_facts(),
            None,
            "{label}: zero-generation-no-DatabaseFacts"
        );
        assert_eq!(
            r.generation(),
            None,
            "{label}: zero-generation-no-retained-generation"
        );
        assert_eq!(r.profile(), None, "{label}: zero-generation-no-profile");
        no_admission(r, label);
    }
    let selected = base(10, 2, "none").selection;
    for selection in [
        SimulationSelection::Exact,
        selected,
        SimulationSelection::InventoryUnresolved,
    ] {
        let label = format!("ZERO-GENERATION-{selection:?}");
        let mut i = base(10, 2, "none");
        i.selection = selection;
        i.generation = 0;
        let r = expect(
            &i,
            "OBSERVATION_GENERATION_MISMATCH",
            "acquisition.generation",
            &label,
        );
        assert_eq!(
            r.trace(),
            ["G", "C"],
            "{label}: zero-generation-before-fields"
        );
        no_retained_facts(&r, &label);
        // Selected equality at E6 must not make two zero generations coherent.
        i.evidence.handoff.generation = 0;
        let r = expect(
            &i,
            "OBSERVATION_GENERATION_MISMATCH",
            "acquisition.generation",
            &format!("{label}-EQUAL-ZERO-HANDOFF"),
        );
        assert_eq!(
            r.trace(),
            ["G", "C"],
            "{label}: zero-generation-no-later-stage"
        );
        no_retained_facts(&r, &label);
        i.evidence.handoff.generation = 42;
        for version in [
            Ok(0),
            Err(ProbeFailure::MissingBaseline),
            Err(ProbeFailure::PermissionDenied),
            Err(ProbeFailure::Timeout),
            Err(ProbeFailure::ConnectionLost),
            Err(ProbeFailure::Other),
        ] {
            i.acquisition.version = version;
            let r = expect(
                &i,
                "OBSERVATION_GENERATION_MISMATCH",
                "acquisition.generation",
                &format!("{label}-PROBE-{version:?}"),
            );
            assert_eq!(
                r.trace(),
                ["G", "C"],
                "{label}: zero-generation-before-probe"
            );
            no_retained_facts(&r, &label);
        }
        i.acquisition.version = Ok(10);
        for posture in [
            SimulationPosture::Established(id(0)),
            SimulationPosture::Established(id(9)),
            SimulationPosture::MissingIndependentObservation,
        ] {
            i.observation.schema = SimulationSchema::Established(id(0));
            i.observation.posture = posture;
            let r = expect(
                &i,
                "OBSERVATION_GENERATION_MISMATCH",
                "acquisition.generation",
                &format!("{label}-TAINTED-{posture:?}"),
            );
            assert_eq!(
                r.trace(),
                ["G", "C"],
                "{label}: zero-generation-before-tainted-fields"
            );
            no_retained_facts(&r, &label);
        }
        i.observation = base(10, 2, "none").observation;
        i.acquisition.installation = SimulationInstallation::ForeignOrUnbound;
        let r = expect(
            &i,
            "EVIDENCE_BINDING_MISMATCH",
            "acquisition.installation",
            &format!("{label}-INSTALLATION-FIRST"),
        );
        assert_eq!(
            r.trace(),
            ["G", "C"],
            "{label}: installation-before-zero-generation"
        );
        no_retained_facts(&r, &label);
        i.acquisition.installation = SimulationInstallation::Bound;
        i.acquisition.generation = SimulationGeneration::MixedOrUnbound;
        let r = expect(
            &i,
            "OBSERVATION_GENERATION_MISMATCH",
            "acquisition.generation",
            &format!("{label}-MIXED"),
        );
        no_retained_facts(&r, &label);
        i.acquisition.generation = SimulationGeneration::Coherent;
        // Restore only numeric g to its already-bound positive handoff generation.
        i.generation = 42;
        if selection == SimulationSelection::InventoryUnresolved {
            expect(
                &i,
                "INVENTORY_UNRESOLVED",
                "selection.inventory",
                &format!("{label}-POSITIVE-RESTORE"),
            );
        } else {
            pending(&i, &format!("{label}-POSITIVE-RESTORE"));
        }
    }
    for field in 0..4 {
        let mut i = base(10, 2, "none");
        i.generation = 0;
        i.acquisition.installation = SimulationInstallation::ForeignOrUnbound;
        i.acquisition.version = Err(ProbeFailure::PermissionDenied);
        match field {
            0 => i.build.schema_version = 0,
            1 => i.build.binary = id(0),
            2 => i.build.schema_identity = id(0),
            3 => i.build.required_posture = id(0),
            _ => unreachable!(),
        }
        let label = format!("ZERO-GENERATION-BUILD-FIRST-{field}");
        let r = expect(&i, "MALFORMED_BUILD", "build", &label);
        assert_eq!(
            r.trace(),
            ["G"],
            "{label}: build-before-installation-generation-probe"
        );
        no_retained_facts(&r, &label);
    }
}
