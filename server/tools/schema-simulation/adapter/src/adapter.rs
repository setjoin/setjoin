//! Pure synthetic composition around the immutable assessor. Injected hash/signature
//! outcomes describe a simulation; they are never cryptographic authentication.
use crate::canonical::{
    parse_attestation, parse_posture_descriptor, parse_schema_descriptor, parse_set_descriptor,
};
use schema_assessor::{
    Assessment, BuildContract, CompatibleProfile, DatabaseFacts, EvidenceFailure, Identity,
    ProbeFailure, ProfileClaims, Refusal, assess,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimulationInstallation {
    Bound,
    ForeignOrUnbound,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimulationGeneration {
    Coherent,
    MixedOrUnbound,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimulationAcquisition {
    pub installation: SimulationInstallation,
    pub generation: SimulationGeneration,
    pub version: Result<u64, ProbeFailure>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimulationSchema {
    Established(Identity),
    NeedsSchemaProof,
    ProvenUnequalToBuild,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimulationPosture {
    Established(Identity),
    MissingIndependentObservation,
    NeedsSchemaProof,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimulationPartialObservation {
    pub schema: SimulationSchema,
    pub posture: SimulationPosture,
    pub catalog_member_digest: Option<Identity>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimulationSelection {
    Exact,
    Selected(Identity),
    InventoryUnresolved,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimulationAuthentication {
    Authenticated,
    Unavailable,
    Invalid,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimulationObservationAgreement {
    CompleteMatch,
    Incomplete,
    Disagrees,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimulationExtraction {
    Supported,
    Unsupported,
}

/// Exact injected hash input and output, including its domain prefix. This binds
/// a synthetic outcome to bytes rather than accepting an unrelated digest claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulationHash {
    pub input: Vec<u8>,
    pub digest: Identity,
}
impl SimulationHash {
    fn for_bytes(&self, domain: &[u8], bytes: &[u8]) -> Option<Identity> {
        let mut input = domain.to_vec();
        input.extend_from_slice(bytes);
        if self.input == input && self.digest != [0; 32] {
            Some(self.digest)
        } else {
            None
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulationDescriptorProof {
    pub bytes: Vec<u8>,
    pub authentication: SimulationAuthentication,
    pub envelope: SimulationGeneration,
    pub installation: SimulationInstallation,
    pub extraction: SimulationExtraction,
    pub hash: SimulationHash,
    pub handoff_digest: Identity,
    pub identity_hash: SimulationHash,
    pub observations: SimulationObservationAgreement,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulationMemberProof {
    pub bytes: Vec<u8>,
    pub authentication: SimulationAuthentication,
    pub installation: SimulationInstallation,
    pub envelope: SimulationGeneration,
    pub extraction: SimulationExtraction,
    pub hash: SimulationHash,
    pub handoff_digest: Identity,
    pub observations: SimulationObservationAgreement,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SimulationActualProof {
    pub release_epoch: String,
    pub schema: Option<SimulationDescriptorProof>,
    pub posture: Option<SimulationDescriptorProof>,
    pub members: Option<SimulationMemberProof>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimulationSignerResult {
    UnknownOrUnauthorized,
    RecognizedInvalid,
    ValidRelease,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulationSigner {
    pub key_id: String,
    pub result: SimulationSignerResult,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimulationLegacy {
    Available,
    Unavailable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimulationPersistence {
    Committed,
    Denied,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimulationClock {
    Trusted(u64),
    Unavailable,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulationPolicy {
    pub authentication: SimulationAuthentication,
    pub release_epoch: String,
    pub trust_generation: u64,
    pub not_before: u64,
    pub expires_at: u64,
    pub revoked_artifacts: Vec<Identity>,
    pub revoked_profiles: Vec<Identity>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulationHighWater {
    pub installation_id: Identity,
    pub timeline_id: Identity,
    pub release_epoch: String,
    pub profile: Identity,
    pub sequence: u64,
    pub body_digest: Identity,
}
/// All handoff slots are fixed synthetic coordinator inputs, never artifact claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulationHandoff {
    pub authentication: SimulationAuthentication,
    pub installation_id: Identity,
    pub timeline_id: Identity,
    pub release_epoch: String,
    pub generation: u64,
    pub trust_generation: u64,
    pub issuer_manifest: Identity,
    pub binary: Identity,
    pub artifact: Identity,
    pub qualification: Identity,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulationQualification {
    pub authentication: SimulationAuthentication,
    pub digest: Identity,
    pub binary: Identity,
    pub schema: Identity,
    pub posture: Identity,
    pub version: u64,
    pub profile: Identity,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulationEvidence {
    pub artifact: Option<Vec<u8>>,
    pub legacy: SimulationLegacy,
    pub signers: Vec<SimulationSigner>,
    pub release_threshold: usize,
    pub handoff: SimulationHandoff,
    pub artifact_hash: SimulationHash,
    pub body_hash: SimulationHash,
    pub profile_hash: SimulationHash,
    pub policy: Option<SimulationPolicy>,
    pub clock: SimulationClock,
    pub high_water: Option<SimulationHighWater>,
    pub persistence: SimulationPersistence,
    pub qualification: Option<SimulationQualification>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulationInput {
    pub build: BuildContract,
    pub acquisition: SimulationAcquisition,
    pub observation: SimulationPartialObservation,
    pub selection: SimulationSelection,
    pub actual_proof: SimulationActualProof,
    pub evidence: SimulationEvidence,
    pub generation: u64,
    pub cancelled: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimulationOutcome {
    Deny,
    HoldInventory,
    CompatiblePendingFence,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimulationSafeAction {
    InspectLocalRecovery,
}
/// Immutable safe projection. No caller strings, paths, artifact claims or scratch
/// identities are retained. No admitted/authenticated-runtime variant exists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulationReport {
    code: &'static str,
    stage: &'static str,
    outcome: SimulationOutcome,
    trace: Vec<&'static str>,
    facts: Option<DatabaseFacts>,
    schema: Option<Identity>,
    posture: Option<Identity>,
    version: Option<u64>,
    build: Option<BuildContract>,
    profile: Option<Identity>,
    generation: Option<u64>,
}
impl SimulationReport {
    pub fn provenance(&self) -> &'static str {
        "synthetic"
    }
    pub fn code(&self) -> &'static str {
        self.code
    }
    pub fn stage(&self) -> &'static str {
        self.stage
    }
    pub fn outcome(&self) -> SimulationOutcome {
        self.outcome
    }
    pub fn trace(&self) -> &[&'static str] {
        &self.trace
    }
    pub fn actual_facts(&self) -> Option<DatabaseFacts> {
        self.facts
    }
    pub fn schema_identity(&self) -> Option<Identity> {
        self.schema
    }
    pub fn posture_identity(&self) -> Option<Identity> {
        self.posture
    }
    pub fn version(&self) -> Option<u64> {
        self.version
    }
    pub fn build(&self) -> Option<BuildContract> {
        self.build
    }
    pub fn profile(&self) -> Option<Identity> {
        self.profile
    }
    pub fn generation(&self) -> Option<u64> {
        self.generation
    }
    pub fn safe_action(&self) -> SimulationSafeAction {
        SimulationSafeAction::InspectLocalRecovery
    }
}
fn report(
    diagnosis: (&'static str, &'static str),
    trace: Vec<&'static str>,
    build: Option<BuildContract>,
    version: Option<u64>,
    observation: Option<SimulationPartialObservation>,
    generation: Option<u64>,
    profile: Option<Identity>,
) -> SimulationReport {
    let (code, stage) = diagnosis;
    let (schema, posture) = observation
        .map(|o| {
            (
                match o.schema {
                    SimulationSchema::Established(id) => Some(id),
                    SimulationSchema::NeedsSchemaProof | SimulationSchema::ProvenUnequalToBuild => {
                        None
                    }
                },
                match o.posture {
                    SimulationPosture::Established(id) => Some(id),
                    SimulationPosture::MissingIndependentObservation
                    | SimulationPosture::NeedsSchemaProof => None,
                },
            )
        })
        .unwrap_or((None, None));
    let facts = match (version, schema, posture) {
        (Some(version), Some(schema_identity), Some(posture)) => Some(DatabaseFacts {
            version,
            schema_identity,
            posture,
        }),
        _ => None,
    };
    let outcome = match code {
        "COMPATIBLE_PENDING_FENCE" => SimulationOutcome::CompatiblePendingFence,
        "INVENTORY_UNRESOLVED" | "QUALIFICATION_UNRESOLVED" | "POSTURE_UNKNOWN" => {
            SimulationOutcome::HoldInventory
        }
        _ => SimulationOutcome::Deny,
    };
    SimulationReport {
        code,
        stage,
        trace,
        outcome,
        facts,
        schema,
        posture,
        version,
        build,
        profile,
        generation,
    }
}
/// Exhaustive direct-assessor projection; does not authenticate its inputs.
pub fn simulation_assessor_code(result: Assessment) -> &'static str {
    match result {
        Assessment::HoldInventory => "INVENTORY_UNRESOLVED",
        Assessment::CompatibleRequiresAdmissionFence(
            CompatibleProfile::Exact | CompatibleProfile::Qualified(_),
        ) => "COMPATIBLE_PENDING_FENCE",
        Assessment::RefuseBusiness(reason) => match reason {
            Refusal::MalformedBuild => "MALFORMED_BUILD",
            Refusal::Probe(ProbeFailure::MissingBaseline) => "MISSING_BASELINE",
            Refusal::Probe(ProbeFailure::PermissionDenied) => "PROBE_PERMISSION_DENIED",
            Refusal::Probe(ProbeFailure::Timeout) => "PROBE_TIMEOUT",
            Refusal::Probe(ProbeFailure::ConnectionLost) => "PROBE_CONNECTION_LOST",
            Refusal::Probe(ProbeFailure::Other) => "PROBE_OTHER",
            Refusal::MalformedDatabase => "MALFORMED_DATABASE",
            Refusal::PostureMismatch => "POSTURE_MISMATCH",
            Refusal::BelowExact => "BELOW_EXACT",
            Refusal::AboveExact => "ABOVE_EXACT",
            Refusal::Evidence(EvidenceFailure::InvalidSignature) => "EVIDENCE_INVALID_SIGNATURE",
            Refusal::Evidence(EvidenceFailure::UnknownSigner) => "EVIDENCE_UNKNOWN_SIGNER",
            Refusal::Evidence(EvidenceFailure::Stale) => "EVIDENCE_STALE",
            Refusal::Evidence(EvidenceFailure::Revoked) => "EVIDENCE_REVOKED",
            Refusal::Evidence(EvidenceFailure::LegacyVerifierUnavailable) => {
                "LEGACY_VERIFIER_UNAVAILABLE"
            }
            Refusal::MalformedProfile => "MALFORMED_PROFILE",
            Refusal::BinaryMismatch => "BINARY_MISMATCH",
            Refusal::SchemaMismatch => "SCHEMA_MISMATCH",
            Refusal::ProfilePostureMismatch => "PROFILE_POSTURE_MISMATCH",
            Refusal::ReadOutsideInterval => "READ_OUTSIDE_INTERVAL",
            Refusal::WriteOutsideInterval => "WRITE_OUTSIDE_INTERVAL",
        },
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimulationPhase {
    Prefix,
    ResolvedPrefix,
    CompletePrefix,
    SelectedProfile,
}
impl SimulationPhase {
    pub fn marker(self) -> &'static str {
        match self {
            Self::Prefix => "prefix",
            Self::ResolvedPrefix => "resolved_prefix",
            Self::CompletePrefix => "complete_prefix",
            Self::SelectedProfile => "profile.assess",
        }
    }
}
/// Adversarial result-mapping seam only. It cannot inject a result into composition
/// or construct authenticated facts; it makes the strict allowlists inspectable.
#[doc(hidden)]
pub fn simulation_phase_result(phase: SimulationPhase, result: Assessment) -> Option<&'static str> {
    match result {
        Assessment::HoldInventory => match phase {
            SimulationPhase::Prefix
            | SimulationPhase::ResolvedPrefix
            | SimulationPhase::CompletePrefix => None,
            SimulationPhase::SelectedProfile => Some("ADAPTER_INVARIANT_VIOLATION"),
        },
        Assessment::RefuseBusiness(Refusal::MalformedDatabase) => match phase {
            SimulationPhase::Prefix => Some("MALFORMED_DATABASE"),
            SimulationPhase::ResolvedPrefix
            | SimulationPhase::CompletePrefix
            | SimulationPhase::SelectedProfile => Some("ADAPTER_INVARIANT_VIOLATION"),
        },
        Assessment::RefuseBusiness(Refusal::PostureMismatch) => match phase {
            SimulationPhase::Prefix
            | SimulationPhase::ResolvedPrefix
            | SimulationPhase::CompletePrefix => Some("POSTURE_MISMATCH"),
            SimulationPhase::SelectedProfile => Some("ADAPTER_INVARIANT_VIOLATION"),
        },
        Assessment::CompatibleRequiresAdmissionFence(CompatibleProfile::Qualified(_)) => {
            match phase {
                SimulationPhase::SelectedProfile => Some("COMPATIBLE_PENDING_FENCE"),
                SimulationPhase::Prefix
                | SimulationPhase::ResolvedPrefix
                | SimulationPhase::CompletePrefix => Some("ADAPTER_INVARIANT_VIOLATION"),
            }
        }
        Assessment::CompatibleRequiresAdmissionFence(CompatibleProfile::Exact)
        | Assessment::RefuseBusiness(
            Refusal::MalformedBuild
            | Refusal::Probe(
                ProbeFailure::MissingBaseline
                | ProbeFailure::PermissionDenied
                | ProbeFailure::Timeout
                | ProbeFailure::ConnectionLost
                | ProbeFailure::Other,
            )
            | Refusal::BelowExact
            | Refusal::AboveExact
            | Refusal::Evidence(
                EvidenceFailure::InvalidSignature
                | EvidenceFailure::UnknownSigner
                | EvidenceFailure::Stale
                | EvidenceFailure::Revoked
                | EvidenceFailure::LegacyVerifierUnavailable,
            )
            | Refusal::MalformedProfile
            | Refusal::BinaryMismatch
            | Refusal::SchemaMismatch
            | Refusal::ProfilePostureMismatch
            | Refusal::ReadOutsideInterval
            | Refusal::WriteOutsideInterval,
        ) => Some("ADAPTER_INVARIANT_VIOLATION"),
    }
}
// This stand-in never escapes into a report, proof, claim or DatabaseFacts output.
fn scratch(build: BuildContract, version: u64, o: SimulationPartialObservation) -> DatabaseFacts {
    DatabaseFacts {
        version,
        schema_identity: match o.schema {
            SimulationSchema::Established(id) => id,
            SimulationSchema::NeedsSchemaProof | SimulationSchema::ProvenUnequalToBuild => [1; 32],
        },
        posture: match o.posture {
            SimulationPosture::Established(id) => id,
            SimulationPosture::MissingIndependentObservation
            | SimulationPosture::NeedsSchemaProof => build.required_posture,
        },
    }
}
fn complete(version: u64, o: SimulationPartialObservation) -> Option<DatabaseFacts> {
    match (o.schema, o.posture) {
        (
            SimulationSchema::Established(schema_identity),
            SimulationPosture::Established(posture),
        ) => Some(DatabaseFacts {
            version,
            schema_identity,
            posture,
        }),
        _ => None,
    }
}
#[derive(Default)]
struct ProofCache {
    syntax: bool,
    binding: bool,
    conflict: bool,
}
fn bound(
    authentication: SimulationAuthentication,
    installation: SimulationInstallation,
    generation: SimulationGeneration,
) -> bool {
    authentication == SimulationAuthentication::Authenticated
        && installation == SimulationInstallation::Bound
        && generation == SimulationGeneration::Coherent
}
fn merge_schema(o: &mut SimulationPartialObservation, id: Identity, cache: &mut ProofCache) {
    match o.schema {
        SimulationSchema::Established(old) => {
            if old != id {
                cache.conflict = true;
            }
        }
        SimulationSchema::NeedsSchemaProof | SimulationSchema::ProvenUnequalToBuild => {
            o.schema = SimulationSchema::Established(id)
        }
    }
}
fn merge_posture(o: &mut SimulationPartialObservation, id: Identity, cache: &mut ProofCache) {
    match o.posture {
        SimulationPosture::Established(old) => {
            if old != id {
                cache.conflict = true;
            }
        }
        SimulationPosture::NeedsSchemaProof => o.posture = SimulationPosture::Established(id),
        SimulationPosture::MissingIndependentObservation => {}
    }
}
/// Inspect independent proof only. Evidence eligibility is deliberately absent.
fn refine(input: &SimulationInput, o: &mut SimulationPartialObservation) -> ProofCache {
    let mut cache = ProofCache::default();
    let mut member = None;
    if let Some(p) = &input.actual_proof.members {
        if parse_set_descriptor(&p.bytes).is_err() {
            cache.syntax = true;
        } else if !bound(p.authentication, p.installation, p.envelope)
            || p.hash.for_bytes(b"", &p.bytes) != Some(p.handoff_digest)
        {
            cache.binding = true;
        } else if p.extraction == SimulationExtraction::Supported
            && p.observations == SimulationObservationAgreement::CompleteMatch
        {
            member = Some(p.handoff_digest);
            if let Some(old) = o.catalog_member_digest {
                if old != p.handoff_digest {
                    cache.conflict = true;
                }
            } else {
                o.catalog_member_digest = member;
            }
        }
    }
    if let Some(p) = &input.actual_proof.schema {
        match parse_schema_descriptor(&p.bytes) {
            Err(_) => cache.syntax = true,
            Ok(d) => {
                if !bound(p.authentication, p.installation, p.envelope)
                    || p.hash.for_bytes(b"", &p.bytes) != Some(p.handoff_digest)
                {
                    cache.binding = true;
                } else {
                    let epoch_matches =
                        d.fields.get("release_epoch") == Some(&input.actual_proof.release_epoch);
                    let version_matches =
                        d.number("schema_version").ok() == input.acquisition.version.ok();
                    let descriptor_member = d.identity("catalog_contract_sha256").ok();
                    if let (Some(declared), Some(actual)) =
                        (descriptor_member, o.catalog_member_digest)
                        && declared != actual
                    {
                        cache.conflict = true;
                    }
                    if !epoch_matches || !version_matches {
                        cache.binding = true;
                    }
                    if p.extraction == SimulationExtraction::Supported
                        && epoch_matches
                        && version_matches
                        && descriptor_member == member
                        && member.is_some()
                        && p.observations == SimulationObservationAgreement::CompleteMatch
                    {
                        if let Some(id) = p
                            .identity_hash
                            .for_bytes(b"setjoin.schema.descriptor.v1\0", &p.bytes)
                        {
                            merge_schema(o, id, &mut cache);
                        } else {
                            cache.binding = true;
                        }
                    }
                }
            }
        }
    }
    if let Some(p) = &input.actual_proof.posture {
        match parse_posture_descriptor(&p.bytes) {
            Err(_) => cache.syntax = true,
            Ok(d) => {
                if !bound(p.authentication, p.installation, p.envelope)
                    || p.hash.for_bytes(b"", &p.bytes) != Some(p.handoff_digest)
                    || d.fields.get("release_epoch") != Some(&input.actual_proof.release_epoch)
                {
                    cache.binding = true;
                } else if p.extraction == SimulationExtraction::Supported
                    && member.is_some()
                    && p.observations == SimulationObservationAgreement::CompleteMatch
                {
                    if let Some(id) = p
                        .identity_hash
                        .for_bytes(b"setjoin.schema.posture.v1\0", &p.bytes)
                    {
                        merge_posture(o, id, &mut cache);
                    } else {
                        cache.binding = true;
                    }
                }
            }
        }
    }
    cache
}

/// No callback, connection, filesystem or provider is reachable from this function.
pub fn compose_simulation(input: &SimulationInput) -> SimulationReport {
    let mut trace = Vec::new();
    if input.cancelled {
        return report(
            ("STARTUP_CANCELLED", "startup.cancelled"),
            trace,
            None,
            None,
            None,
            None,
            None,
        );
    }
    trace.push("G");
    match assess(
        input.build,
        Err(ProbeFailure::Other),
        ProfileClaims::InventoryUnresolved,
    ) {
        Assessment::RefuseBusiness(Refusal::MalformedBuild) => {
            return report(
                ("MALFORMED_BUILD", "build"),
                trace,
                None,
                None,
                None,
                None,
                None,
            );
        }
        Assessment::RefuseBusiness(Refusal::Probe(ProbeFailure::Other)) => {}
        other => {
            let _ = simulation_assessor_code(other);
            return report(
                ("ADAPTER_INVARIANT_VIOLATION", "build"),
                trace,
                None,
                None,
                None,
                None,
                None,
            );
        }
    }
    trace.push("C");
    let build = Some(input.build);
    if input.acquisition.installation == SimulationInstallation::ForeignOrUnbound {
        return report(
            ("EVIDENCE_BINDING_MISMATCH", "acquisition.installation"),
            trace,
            build,
            None,
            None,
            None,
            None,
        );
    }
    // A coherent outcome cannot validate a zero generation: STATE requires positive g.
    // This is envelope validation before probe/field acceptance, not an assessor rule.
    if input.generation == 0 || input.acquisition.generation == SimulationGeneration::MixedOrUnbound
    {
        return report(
            ("OBSERVATION_GENERATION_MISMATCH", "acquisition.generation"),
            trace,
            build,
            None,
            None,
            None,
            None,
        );
    }
    let version = match input.acquisition.version {
        Ok(v) => v,
        Err(e) => {
            let result = assess(input.build, Err(e), ProfileClaims::InventoryUnresolved);
            let code = if result == Assessment::RefuseBusiness(Refusal::Probe(e)) {
                simulation_assessor_code(result)
            } else {
                "ADAPTER_INVARIANT_VIOLATION"
            };
            return report(
                (code, "acquisition.version"),
                trace,
                build,
                None,
                None,
                None,
                None,
            );
        }
    };
    let mut o = input.observation;
    macro_rules! finish {
        ($code:expr, $stage:expr) => {
            return report(
                ($code, $stage),
                trace,
                build,
                Some(version),
                Some(o),
                Some(input.generation),
                None,
            )
        };
    }
    trace.extend(["K", "K1", "K2", "K3"]);
    let initial_prefix = assess(
        input.build,
        Ok(scratch(input.build, version, o)),
        ProfileClaims::InventoryUnresolved,
    );
    if !matches!(o.schema, SimulationSchema::Established(_)) {
        trace.push("K3.deferred_schema");
    }
    // The immutable assessor stops at DB validation on MalformedDatabase;
    // a deferred posture is not a visit to its later required-posture check.
    if initial_prefix != Assessment::RefuseBusiness(Refusal::MalformedDatabase) {
        trace.push("K4");
        if !matches!(o.posture, SimulationPosture::Established(_)) {
            trace.push("K4.deferred_posture");
        }
    }
    if let Some(code) = simulation_phase_result(SimulationPhase::Prefix, initial_prefix) {
        finish!(code, "prefix");
    }
    if o.posture == SimulationPosture::MissingIndependentObservation {
        finish!("POSTURE_UNKNOWN", "prefix.posture");
    }
    match input.selection {
        SimulationSelection::InventoryUnresolved => {
            trace.push("I");
            finish!("INVENTORY_UNRESOLVED", "selection.inventory");
        }
        SimulationSelection::Exact => {
            trace.push("X");
            let exact = DatabaseFacts {
                schema_identity: match o.schema {
                    SimulationSchema::Established(id) => id,
                    SimulationSchema::NeedsSchemaProof | SimulationSchema::ProvenUnequalToBuild => {
                        input.build.schema_identity
                    }
                },
                ..scratch(input.build, version, o)
            };
            match assess(input.build, Ok(exact), ProfileClaims::ExactDefault) {
                Assessment::RefuseBusiness(Refusal::BelowExact) => {
                    finish!("BELOW_EXACT", "exact.assess")
                }
                Assessment::RefuseBusiness(Refusal::AboveExact) => {
                    finish!("ABOVE_EXACT", "exact.assess")
                }
                Assessment::RefuseBusiness(Refusal::SchemaMismatch) => {
                    if matches!(o.schema, SimulationSchema::Established(_)) {
                        finish!("SCHEMA_MISMATCH", "exact.assess");
                    }
                    finish!("ADAPTER_INVARIANT_VIOLATION", "exact.assess");
                }
                Assessment::CompatibleRequiresAdmissionFence(CompatibleProfile::Exact) => {
                    if o.schema == SimulationSchema::ProvenUnequalToBuild {
                        finish!("SCHEMA_MISMATCH", "exact.comparison");
                    }
                    if complete(version, o).is_none() {
                        finish!("QUALIFICATION_UNRESOLVED", "exact.proof");
                    }
                    trace.push("N");
                    finish!("COMPATIBLE_PENDING_FENCE", "fence.pending");
                }
                other => {
                    let _ = simulation_assessor_code(other);
                    finish!("ADAPTER_INVARIANT_VIOLATION", "exact.assess");
                }
            }
        }
        SimulationSelection::Selected(_) => {}
    }
    trace.push("E9a");
    let before = o;
    let proof = refine(input, &mut o);
    let actual = complete(version, o);
    if let Some(facts) = actual {
        trace.push("A");
        if let Some(code) = simulation_phase_result(
            SimulationPhase::CompletePrefix,
            assess(input.build, Ok(facts), ProfileClaims::InventoryUnresolved),
        ) {
            finish!(code, "complete_prefix");
        }
    } else if before.schema != o.schema || before.posture != o.posture {
        trace.push("Kr");
        if let Some(code) = simulation_phase_result(
            SimulationPhase::ResolvedPrefix,
            assess(
                input.build,
                Ok(scratch(input.build, version, o)),
                ProfileClaims::InventoryUnresolved,
            ),
        ) {
            finish!(code, "resolved_prefix");
        }
    }
    let evidence = &input.evidence;
    trace.push("E1");
    trace.push("E2");
    let bytes = match &evidence.artifact {
        Some(bytes) => bytes,
        None => finish!("MISSING_SELECTED_EVIDENCE", "evidence.presence"),
    };
    trace.push("E3");
    if evidence.legacy == SimulationLegacy::Unavailable {
        finish!("LEGACY_VERIFIER_UNAVAILABLE", "evidence.legacy");
    }
    trace.push("E4");
    trace.push("artifact.parse");
    let a = match parse_attestation(bytes) {
        Ok(a) => a,
        Err(_) => finish!("EVIDENCE_MALFORMED", "evidence.syntax"),
    };
    if proof.syntax {
        finish!("EVIDENCE_MALFORMED", "evidence.syntax");
    }
    // All getters below are checked by the raw parser; failure remains syntax.
    let claims = match a.profile_claims() {
        Ok(p) => p,
        Err(_) => finish!("EVIDENCE_MALFORMED", "evidence.syntax"),
    };
    trace.push("E5");
    let mut recognized = 0;
    let mut valid = 0;
    for signature in &a.signatures {
        let mut outcomes = evidence
            .signers
            .iter()
            .filter(|s| s.key_id == signature.key_id);
        if let Some(s) = outcomes.next() {
            if outcomes.next().is_some() {
                finish!("ADAPTER_INVARIANT_VIOLATION", "evidence.signers");
            }
            match s.result {
                SimulationSignerResult::UnknownOrUnauthorized => {}
                SimulationSignerResult::RecognizedInvalid => recognized += 1,
                SimulationSignerResult::ValidRelease => {
                    recognized += 1;
                    valid += 1;
                }
            }
        }
    }
    if valid < evidence.release_threshold.max(2) {
        if recognized == 0 {
            finish!("EVIDENCE_UNKNOWN_SIGNER", "evidence.signers");
        }
        if valid == 0 {
            finish!("EVIDENCE_INVALID_SIGNATURE", "evidence.signers");
        }
        finish!("EVIDENCE_SIGNATURE_THRESHOLD", "evidence.signers");
    }
    trace.push("E6");
    let h = &evidence.handoff;
    let artifact_digest = evidence.artifact_hash.for_bytes(b"", bytes);
    let body = match a.canonical_body() {
        Ok(b) => b,
        Err(_) => finish!("ADAPTER_INVARIANT_VIOLATION", "evidence.binding"),
    };
    let body_digest = evidence.body_hash.for_bytes(b"", &body);
    if proof.binding
        || proof.conflict
        || h.authentication != SimulationAuthentication::Authenticated
        || h.installation_id == [0; 32]
        || h.timeline_id == [0; 32]
        || h.generation != input.generation
        || h.binary != input.build.binary
        || claims.binary != h.binary
        || a.fields.get("release_epoch") != Some(&h.release_epoch)
        || a.number("trust_generation").ok() != Some(h.trust_generation)
        || a.identity("issuer_manifest_sha256").ok() != Some(h.issuer_manifest)
        || a.identity("qualification_sha256").ok() != Some(h.qualification)
        || artifact_digest != Some(h.artifact)
        || body_digest.is_none()
    {
        finish!("EVIDENCE_BINDING_MISMATCH", "evidence.binding");
    }
    trace.push("E7.recomputed");
    trace.push("E7");
    let core = match a.profile_core() {
        Ok(c) => c,
        Err(_) => finish!("ADAPTER_INVARIANT_VIOLATION", "evidence.profile_id"),
    };
    if evidence
        .profile_hash
        .for_bytes(b"setjoin.schema.profile.v1\0", &core)
        != Some(claims.profile)
    {
        finish!("EVIDENCE_PROFILE_MISMATCH", "evidence.profile_id");
    }
    trace.push("E7.selected");
    if input.selection != SimulationSelection::Selected(claims.profile) {
        finish!("EVIDENCE_PROFILE_MISMATCH", "evidence.profile_id");
    }
    trace.push("E8.prerequisites");
    trace.push("E8.policy");
    let policy = match &evidence.policy {
        Some(p) => p,
        None => finish!(
            "EVIDENCE_CURRENTNESS_UNKNOWN",
            "evidence.currentness.prerequisites"
        ),
    };
    if policy.authentication != SimulationAuthentication::Authenticated
        || policy.release_epoch != h.release_epoch
        || policy.trust_generation != h.trust_generation
    {
        finish!(
            "EVIDENCE_CURRENTNESS_UNKNOWN",
            "evidence.currentness.prerequisites"
        );
    }
    trace.push("E8.clock");
    let now = match evidence.clock {
        SimulationClock::Trusted(t) => t,
        SimulationClock::Unavailable => finish!(
            "EVIDENCE_CURRENTNESS_UNKNOWN",
            "evidence.currentness.prerequisites"
        ),
    };
    if !(policy.not_before <= now && now < policy.expires_at) {
        finish!(
            "EVIDENCE_CURRENTNESS_UNKNOWN",
            "evidence.currentness.prerequisites"
        );
    }
    trace.push("E8.high_water");
    let high = match &evidence.high_water {
        Some(p) => p,
        None => finish!(
            "EVIDENCE_CURRENTNESS_UNKNOWN",
            "evidence.currentness.prerequisites"
        ),
    };
    if high.installation_id != h.installation_id
        || high.timeline_id != h.timeline_id
        || high.release_epoch != h.release_epoch
        || high.profile != claims.profile
    {
        finish!(
            "EVIDENCE_CURRENTNESS_UNKNOWN",
            "evidence.currentness.prerequisites"
        );
    }
    trace.push("E8.revocation");
    if policy.revoked_artifacts.contains(&h.artifact)
        || policy.revoked_profiles.contains(&claims.profile)
    {
        finish!("EVIDENCE_REVOKED", "evidence.currentness.revocation");
    }
    trace.push("E8.time");
    let nb = match a.number("not_before") {
        Ok(n) => n,
        Err(_) => finish!("ADAPTER_INVARIANT_VIOLATION", "evidence.currentness.time"),
    };
    let expires = match a.number("expires_at") {
        Ok(n) => n,
        Err(_) => finish!("ADAPTER_INVARIANT_VIOLATION", "evidence.currentness.time"),
    };
    if !(nb <= now && now < expires) || expires > policy.expires_at {
        finish!("EVIDENCE_STALE", "evidence.currentness.time");
    }
    trace.push("E8.sequence");
    let sequence = match a.number("metadata_sequence") {
        Ok(n) => n,
        Err(_) => finish!(
            "ADAPTER_INVARIANT_VIOLATION",
            "evidence.currentness.sequence"
        ),
    };
    if sequence < high.sequence {
        finish!("EVIDENCE_REPLAY", "evidence.currentness.sequence");
    }
    if sequence == high.sequence && body_digest != Some(high.body_digest) {
        finish!("EVIDENCE_EQUIVOCATION", "evidence.currentness.sequence");
    }
    trace.push("E8.persistence");
    if evidence.persistence != SimulationPersistence::Committed {
        finish!(
            "EVIDENCE_CURRENTNESS_UNKNOWN",
            "evidence.currentness.persistence"
        );
    }
    trace.push("E9b");
    let facts = match actual {
        Some(f) => f,
        None => finish!("QUALIFICATION_UNRESOLVED", "evidence.qualification"),
    };
    let q = match &evidence.qualification {
        Some(q) => q,
        None => finish!("QUALIFICATION_UNRESOLVED", "evidence.qualification"),
    };
    if q.authentication != SimulationAuthentication::Authenticated
        || q.digest != h.qualification
        || q.binary != claims.binary
        || q.profile != claims.profile
        || q.version != facts.version
        || q.schema != facts.schema_identity
        || q.posture != facts.posture
        || claims.schema_version != facts.version
        || claims.schema_identity != facts.schema_identity
        || claims.posture != facts.posture
    {
        finish!("QUALIFICATION_UNRESOLVED", "evidence.qualification");
    }
    trace.push("P");
    let result = assess(input.build, Ok(facts), ProfileClaims::Qualified(claims));
    let code = simulation_phase_result(SimulationPhase::SelectedProfile, result)
        .unwrap_or("ADAPTER_INVARIANT_VIOLATION");
    if code != "COMPATIBLE_PENDING_FENCE" {
        finish!(code, "profile.assess");
    }
    trace.push("N");
    report(
        (code, "fence.pending"),
        trace,
        build,
        Some(version),
        Some(o),
        Some(input.generation),
        Some(claims.profile),
    )
}
