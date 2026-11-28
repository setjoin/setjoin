//! C01: separate live, historical-attendee, Chat-history and content projections.
use crate::{error::ContractError, ids::*};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceScope {
    /// A mailbox-less authenticated user domain (Chat, Meet or Drive).
    User(ActorId),
    Mailbox(MailboxId),
    Meeting(MeetingId),
    Drive(SpaceId),
}
/// A comparison key, deliberately not named AuthorizedContext or Permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorityKey {
    pub actor: ActorId,
    pub scope: ResourceScope,
    pub generation: Generation,
}
impl AuthorityKey {
    /// `current` must come from the executor's current authority read inside the owning transaction.
    pub fn check_current(self, current: Self) -> Result<(), ContractError> {
        if self.actor != current.actor {
            return Err(ContractError::ActorMismatch);
        }
        if self.scope != current.scope {
            return Err(ContractError::ScopeMismatch);
        }
        if self.generation != current.generation {
            return Err(ContractError::StaleAuthority);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MeetingRole {
    Host,
    Cohost,
    Member,
    Guest,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriveRole {
    Manager,
    Editor,
    Viewer,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MeetingMembership {
    pub actor: ActorId,
    pub meeting: MeetingId,
    pub role: MeetingRole,
    pub joined: bool,
    pub left: bool,
    pub banned: bool,
}
impl MeetingMembership {
    /// Exact meeting_member_role liveness: ban is NOT filtered here.
    /// SFU eviction remains separately owned; this is never a universal authorization gate.
    pub fn live_role(self) -> Option<MeetingRole> {
        if self.left {
            None
        } else {
            Some(self.role)
        }
    }
    pub fn attendee_role(self) -> Option<MeetingRole> {
        if self.banned {
            return None;
        }
        match self.role {
            MeetingRole::Host | MeetingRole::Cohost => Some(self.role),
            _ if self.joined => Some(self.role),
            _ => None,
        }
    }
    pub fn derived_drive_role(self) -> Option<DriveRole> {
        match self.attendee_role()? {
            MeetingRole::Host | MeetingRole::Cohost => Some(DriveRole::Manager),
            _ => Some(DriveRole::Viewer),
        }
    }
    pub fn blocks_recording_start(self) -> bool {
        self.role == MeetingRole::Guest && !self.left && !self.banned
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChatAttachmentFacts {
    pub message_deleted: bool,
    pub message_seq: i64,
    pub created_at_micros: i64,
    pub history_floor_seq: Option<i64>,
    pub joined_at_micros: i64,
}
impl ChatAttachmentFacts {
    /// Membership must already have been resolved for the exact channel and actor.
    pub fn visible_with_membership(self) -> bool {
        !self.message_deleted
            && self.message_seq > self.history_floor_seq.unwrap_or(0)
            && (self.history_floor_seq.is_none() || self.created_at_micros >= self.joined_at_micros)
    }
}
