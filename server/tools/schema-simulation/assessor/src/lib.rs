//! Pure schema compatibility assessment. This is NOT startup admission.
//!
//! Inputs are claimed facts supplied by a future verified adapter. In particular,
//! `Qualified` is not proof of a signature. Never wire this result to readiness
//! without the independently qualified attestation verifier and cutover fence.
#![forbid(unsafe_code)]

pub type Identity = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interval {
    pub lower: u64,
    pub upper: u64,
}
impl Interval {
    fn valid(self) -> bool {
        self.lower != 0 && self.lower <= self.upper
    }
    fn contains(self, version: u64) -> bool {
        self.lower <= version && version <= self.upper
    }
}

/// Immutable build contract. The unattested profile is exactly `schema_version`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuildContract {
    pub binary: Identity,
    pub schema_version: u64,
    pub schema_identity: Identity,
    pub required_posture: Identity,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DatabaseFacts {
    pub version: u64,
    pub posture: Identity,
    pub schema_identity: Identity,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeFailure {
    MissingBaseline,
    PermissionDenied,
    Timeout,
    ConnectionLost,
    Other,
}

/// Model of already-authenticated, inventoried compatibility evidence. There is
/// deliberately no deserializer, signature verifier, trust root or DB adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QualifiedProfileClaims {
    pub binary: Identity,
    pub profile: Identity,
    pub schema_identity: Identity,
    pub schema_version: u64,
    pub posture: Identity,
    pub read: Interval,
    pub write: Interval,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceFailure {
    InvalidSignature,
    UnknownSigner,
    Stale,
    Revoked,
    LegacyVerifierUnavailable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileClaims {
    /// No wider compatibility was selected; exact-version default only.
    ExactDefault,
    Qualified(QualifiedProfileClaims),
    Rejected(EvidenceFailure),
    InventoryUnresolved,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    MalformedBuild,
    Probe(ProbeFailure),
    MalformedDatabase,
    PostureMismatch,
    BelowExact,
    AboveExact,
    Evidence(EvidenceFailure),
    MalformedProfile,
    BinaryMismatch,
    SchemaMismatch,
    ProfilePostureMismatch,
    ReadOutsideInterval,
    WriteOutsideInterval,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompatibleProfile {
    Exact,
    Qualified(Identity),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Assessment {
    /// Compatibility only. The startup synchronization/authority gate is owed.
    CompatibleRequiresAdmissionFence(CompatibleProfile),
    RefuseBusiness(Refusal),
    /// Unknown inventory is a qualification HOLD, never guessed compatibility.
    HoldInventory,
}

/// Constant-size, allocation-free assessment with typed, non-sensitive diagnosis.
/// Does not expose migration hooks, connection handles or recovery-route controls.
/// Recovery authorization is independent and must not be inferred from this enum.
pub fn assess(
    build: BuildContract,
    probe: Result<DatabaseFacts, ProbeFailure>,
    profile: ProfileClaims,
) -> Assessment {
    use Assessment::{CompatibleRequiresAdmissionFence as Compatible, RefuseBusiness as Deny};
    if build.schema_version == 0
        || build.binary == [0; 32]
        || build.required_posture == [0; 32]
        || build.schema_identity == [0; 32]
    {
        return Deny(Refusal::MalformedBuild);
    }
    let db = match probe {
        Ok(db) => db,
        Err(error) => return Deny(Refusal::Probe(error)),
    };
    if db.version == 0 || db.schema_identity == [0; 32] || db.posture == [0; 32] {
        return Deny(Refusal::MalformedDatabase);
    }
    if db.posture != build.required_posture {
        return Deny(Refusal::PostureMismatch);
    }
    match profile {
        ProfileClaims::InventoryUnresolved => Assessment::HoldInventory,
        ProfileClaims::Rejected(error) => Deny(Refusal::Evidence(error)),
        ProfileClaims::ExactDefault => {
            if db.version < build.schema_version {
                Deny(Refusal::BelowExact)
            } else if db.version > build.schema_version {
                Deny(Refusal::AboveExact)
            } else if db.schema_identity != build.schema_identity {
                Deny(Refusal::SchemaMismatch)
            } else {
                Compatible(CompatibleProfile::Exact)
            }
        }
        ProfileClaims::Qualified(p) => {
            if !p.read.valid() || !p.write.valid() || p.profile == [0; 32] {
                return Deny(Refusal::MalformedProfile);
            }
            if p.binary != build.binary {
                return Deny(Refusal::BinaryMismatch);
            }
            if p.schema_identity != db.schema_identity || p.schema_version != db.version {
                return Deny(Refusal::SchemaMismatch);
            }
            if p.posture != db.posture {
                return Deny(Refusal::ProfilePostureMismatch);
            }
            if !p.read.contains(db.version) {
                return Deny(Refusal::ReadOutsideInterval);
            }
            if !p.write.contains(db.version) {
                return Deny(Refusal::WriteOutsideInterval);
            }
            Compatible(CompatibleProfile::Qualified(p.profile))
        }
    }
}

#[cfg(test)]
mod tests;
