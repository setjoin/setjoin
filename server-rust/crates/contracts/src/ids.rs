//! Database bigint identities remain distinct and lossless. Wire adapters own JSON shape.
//!
//! ```compile_fail
//! use setjoin_contracts::ids::{ActorId, MailboxId};
//! let actor = ActorId::new(7).unwrap();
//! let mailbox: MailboxId = actor;
//! ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidId;
macro_rules! id {
    ($($name:ident),+ $(,)?) => {$(
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(i64);
        impl $name {
            pub fn new(value: i64) -> Result<Self, InvalidId> {
                if value > 0 { Ok(Self(value)) } else { Err(InvalidId) }
            }
            pub const fn get(self) -> i64 { self.0 }
            pub fn decimal(self) -> String { self.0.to_string() }
        }
    )+};
}
id!(
    ActorId,
    MailboxId,
    MessageId,
    MeetingId,
    SpaceId,
    NodeId,
    VersionId,
    RecordingId,
    ReferenceId
);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Generation(pub u64);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Digest(pub [u8; 32]);
impl Digest {
    /// The legacy manifest accepts exactly 64 lower-case hex characters.
    pub fn from_hex(s: &str) -> Result<Self, InvalidId> {
        if s.len() != 64 {
            return Err(InvalidId);
        }
        let mut bytes = [0; 32];
        fn nibble(b: u8) -> Result<u8, InvalidId> {
            match b {
                b'0'..=b'9' => Ok(b - b'0'),
                b'a'..=b'f' => Ok(b - b'a' + 10),
                _ => Err(InvalidId),
            }
        }
        for (i, pair) in s.as_bytes().chunks_exact(2).enumerate() {
            bytes[i] = nibble(pair[0])? * 16 + nibble(pair[1])?;
        }
        Ok(Self(bytes))
    }
}
/// Server-assigned operation identity, not a retry permission or authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationId(pub [u8; 16]);

/// Canonical lowercase identifier using frozen google/uuid.Parse's accepted forms.
/// Parsing does not grant ownership; each caller decides whether nil is allowed.
pub fn go_uuid(text: &str) -> Option<String> {
    let inner = match text.len() {
        32 | 36 => text,
        // Go ignores BOTH wrapper bytes for a 38-byte input, even non-braces.
        38 => text.get(1..37)?,
        45 if text.get(..9)?.eq_ignore_ascii_case("urn:uuid:") => text.get(9..)?,
        _ => return None,
    };
    uuid::Uuid::parse_str(inner)
        .ok()
        .map(|id| id.hyphenated().to_string())
}
