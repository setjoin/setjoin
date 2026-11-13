//! Selected source error identities. No unknown SQL error or detail leaks to clients.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainError {
    DriveNotFound,
    DriveForbidden,
    InvalidManifest,
    ChunkNotProven,
    OverQuota,
    Locked,
    ImmutableRecord,
    MeetingNotFound,
    MeetingForbidden,
    RecordingGuestExclusion,
    RecordingConflict,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Surface {
    Drive,
    Meet,
    Generic,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireError {
    pub code: &'static str,
    pub status: u16,
    pub hint_type: &'static str,
    pub problem_slug: Option<&'static str>,
}
impl DomainError {
    pub fn wire(self, surface: Surface) -> WireError {
        use DomainError::*;
        let (code, mut status, hint_type, slug, owner) = match self {
            DriveNotFound => ("BZ139", 404, "notFound", "not-found", Surface::Drive),
            DriveForbidden => ("BZ140", 403, "forbidden", "forbidden", Surface::Drive),
            InvalidManifest => (
                "BZ141",
                422,
                "invalidArguments",
                "invalid-arguments",
                Surface::Drive,
            ),
            ChunkNotProven => (
                "BZ144",
                422,
                "chunkNotProven",
                "chunk-not-proven",
                Surface::Drive,
            ),
            OverQuota => ("BZ148", 507, "overQuota", "quota-exceeded", Surface::Drive),
            Locked => ("BZ149", 409, "locked", "locked", Surface::Drive),
            // BZ175 is intentionally absent from Drive's URL slug table.
            ImmutableRecord => ("BZ175", 403, "forbidden", "", Surface::Generic),
            MeetingNotFound => ("BZ185", 404, "notFound", "not-found", Surface::Meet),
            MeetingForbidden => ("BZ186", 403, "forbidden", "forbidden", Surface::Meet),
            RecordingGuestExclusion => (
                "BZ199",
                403,
                "forbidden",
                "recording-guest-exclusion",
                Surface::Meet,
            ),
            RecordingConflict => (
                "BZ200",
                409,
                "conflict",
                "recording-conflict",
                Surface::Meet,
            ),
        };
        if surface == Surface::Drive {
            if self == OverQuota {
                status = 413;
            }
            if self == Locked {
                status = 423;
            }
        }
        WireError {
            code,
            status,
            hint_type,
            problem_slug: if surface == owner && !slug.is_empty() {
                Some(slug)
            } else {
                None
            },
        }
    }
}
/// Internal contract failure, not a new public BZ allocation. Adapters must explicitly map it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContractError {
    ActorMismatch,
    ScopeMismatch,
    StaleAuthority,
    ContractDrift,
    UnsupportedVersion,
    InvalidEnvelope,
    StaleGeneration,
    InvalidState,
    ConflictingReplay,
    UnverifiedContent,
    Held,
    Referenced,
    StaleReference,
    Arithmetic,
    UnknownOutcome,
}
