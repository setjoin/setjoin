use super::*;
use Assessment::{CompatibleRequiresAdmissionFence as Compatible, RefuseBusiness as Deny};
fn build() -> BuildContract {
    BuildContract {
        binary: [1; 32],
        schema_version: 10,
        schema_identity: [3; 32],
        required_posture: [2; 32],
    }
}
fn db(version: u64) -> DatabaseFacts {
    DatabaseFacts {
        version,
        posture: [2; 32],
        schema_identity: [3; 32],
    }
}
fn profile(version: u64, read: Interval, write: Interval) -> QualifiedProfileClaims {
    QualifiedProfileClaims {
        binary: [1; 32],
        profile: [4; 32],
        schema_identity: [3; 32],
        schema_version: version,
        posture: [2; 32],
        read,
        write,
    }
}
fn interval(lower: u64, upper: u64) -> Interval {
    Interval { lower, upper }
}
fn qualified(p: QualifiedProfileClaims, v: u64) -> Assessment {
    assess(build(), Ok(db(v)), ProfileClaims::Qualified(p))
}
const EXPECT_QUALIFIED: Assessment = Compatible(CompatibleProfile::Qualified([4; 32]));

#[test]
fn exact_default_has_no_accept_ahead() {
    for (v, want) in [
        (9, Deny(Refusal::BelowExact)),
        (10, Compatible(CompatibleProfile::Exact)),
        (11, Deny(Refusal::AboveExact)),
        (u64::MAX, Deny(Refusal::AboveExact)),
    ] {
        assert_eq!(
            assess(build(), Ok(db(v)), ProfileClaims::ExactDefault),
            want
        );
    }
}
#[test]
fn inclusive_qualified_read_and_write_boundaries() {
    for (v, want) in [
        (7, Deny(Refusal::ReadOutsideInterval)),
        (8, EXPECT_QUALIFIED),
        (12, EXPECT_QUALIFIED),
        (13, Deny(Refusal::ReadOutsideInterval)),
    ] {
        assert_eq!(
            qualified(profile(v, interval(8, 12), interval(8, 12)), v),
            want
        );
    }
}
#[test]
fn read_write_intersection_not_union() {
    for (v, want) in [
        (8, Deny(Refusal::WriteOutsideInterval)),
        (9, EXPECT_QUALIFIED),
        (11, EXPECT_QUALIFIED),
        (12, Deny(Refusal::WriteOutsideInterval)),
    ] {
        assert_eq!(
            qualified(profile(v, interval(8, 12), interval(9, 11)), v),
            want
        );
    }
    assert_eq!(
        qualified(profile(11, interval(8, 10), interval(11, 12)), 11),
        Deny(Refusal::ReadOutsideInterval)
    );
}
#[test]
fn extremes_require_no_overflow_arithmetic() {
    for v in [1, u64::MAX] {
        assert_eq!(
            qualified(profile(v, interval(v, v), interval(v, v)), v),
            EXPECT_QUALIFIED
        );
    }
    let mut b = build();
    b.schema_version = u64::MAX;
    assert_eq!(
        assess(b, Ok(db(u64::MAX)), ProfileClaims::ExactDefault),
        Compatible(CompatibleProfile::Exact)
    );
}
#[test]
fn malformed_ranges_never_admit() {
    for range in [interval(0, 0), interval(0, 12), interval(12, 8)] {
        assert_eq!(
            qualified(profile(10, range, interval(8, 12)), 10),
            Deny(Refusal::MalformedProfile)
        );
        assert_eq!(
            qualified(profile(10, interval(8, 12), range), 10),
            Deny(Refusal::MalformedProfile)
        );
    }
}
#[test]
fn malformed_build_and_database_refuse() {
    let mut b = build();
    b.schema_version = 0;
    assert_eq!(
        assess(b, Ok(db(10)), ProfileClaims::ExactDefault),
        Deny(Refusal::MalformedBuild)
    );
    b = build();
    b.binary = [0; 32];
    assert_eq!(
        assess(b, Ok(db(10)), ProfileClaims::ExactDefault),
        Deny(Refusal::MalformedBuild)
    );
    b = build();
    b.required_posture = [0; 32];
    assert_eq!(
        assess(b, Ok(db(10)), ProfileClaims::ExactDefault),
        Deny(Refusal::MalformedBuild)
    );
    for d in [
        db(0),
        DatabaseFacts {
            posture: [0; 32],
            ..db(10)
        },
        DatabaseFacts {
            schema_identity: [0; 32],
            ..db(10)
        },
    ] {
        assert_eq!(
            assess(build(), Ok(d), ProfileClaims::ExactDefault),
            Deny(Refusal::MalformedDatabase)
        );
    }
}
#[test]
fn every_probe_failure_preserves_its_diagnosis() {
    for error in [
        ProbeFailure::MissingBaseline,
        ProbeFailure::PermissionDenied,
        ProbeFailure::Timeout,
        ProbeFailure::ConnectionLost,
        ProbeFailure::Other,
    ] {
        assert_eq!(
            assess(build(), Err(error), ProfileClaims::ExactDefault),
            Deny(Refusal::Probe(error))
        );
    }
}
#[test]
fn required_posture_is_not_inferred_from_version() {
    let d = DatabaseFacts {
        posture: [9; 32],
        ..db(10)
    };
    assert_eq!(
        assess(build(), Ok(d), ProfileClaims::ExactDefault),
        Deny(Refusal::PostureMismatch)
    );
}
#[test]
fn rejected_evidence_does_not_fall_back_even_at_exact_version() {
    for error in [
        EvidenceFailure::InvalidSignature,
        EvidenceFailure::UnknownSigner,
        EvidenceFailure::Stale,
        EvidenceFailure::Revoked,
        EvidenceFailure::LegacyVerifierUnavailable,
    ] {
        for v in [10, 11] {
            assert_eq!(
                assess(build(), Ok(db(v)), ProfileClaims::Rejected(error)),
                Deny(Refusal::Evidence(error))
            );
        }
    }
}
#[test]
fn unresolved_inventory_is_explicit_hold() {
    for v in [9, 10, 11] {
        assert_eq!(
            assess(build(), Ok(db(v)), ProfileClaims::InventoryUnresolved),
            Assessment::HoldInventory
        );
    }
}
#[test]
fn qualified_rollback_can_cover_forward_schema() {
    assert_eq!(
        qualified(profile(11, interval(10, 12), interval(10, 12)), 11),
        EXPECT_QUALIFIED
    );
}
#[test]
fn profile_is_bound_to_binary_schema_and_posture() {
    let p = profile(11, interval(10, 12), interval(10, 12));
    for (changed, want) in [
        (
            QualifiedProfileClaims {
                binary: [8; 32],
                ..p
            },
            Refusal::BinaryMismatch,
        ),
        (
            QualifiedProfileClaims {
                schema_identity: [8; 32],
                ..p
            },
            Refusal::SchemaMismatch,
        ),
        (
            QualifiedProfileClaims {
                schema_version: 10,
                ..p
            },
            Refusal::SchemaMismatch,
        ),
        (
            QualifiedProfileClaims {
                posture: [8; 32],
                ..p
            },
            Refusal::ProfilePostureMismatch,
        ),
        (
            QualifiedProfileClaims {
                profile: [0; 32],
                ..p
            },
            Refusal::MalformedProfile,
        ),
    ] {
        assert_eq!(qualified(changed, 11), Deny(want));
    }
}
#[test]
fn exhaustive_small_intervals_agree_with_independent_set_oracle() {
    for lo in 1..=4 {
        for hi in lo..=4 {
            for wlo in 1..=4 {
                for whi in wlo..=4 {
                    let allowed: Vec<u64> =
                        (lo..=hi).filter(|v| (wlo..=whi).any(|w| w == *v)).collect();
                    for v in 1..=5 {
                        let result = qualified(profile(v, interval(lo, hi), interval(wlo, whi)), v);
                        assert_eq!(
                            matches!(result, Compatible(_)),
                            allowed.contains(&v),
                            "read={lo}..{hi} write={wlo}..{whi} version={v}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn exact_default_also_binds_schema_identity() {
    assert_eq!(
        assess(
            build(),
            Ok(DatabaseFacts {
                schema_identity: [9; 32],
                ..db(10)
            }),
            ProfileClaims::ExactDefault
        ),
        Deny(Refusal::SchemaMismatch)
    );
    let mut b = build();
    b.schema_identity = [0; 32];
    assert_eq!(
        assess(b, Ok(db(10)), ProfileClaims::ExactDefault),
        Deny(Refusal::MalformedBuild)
    );
}
