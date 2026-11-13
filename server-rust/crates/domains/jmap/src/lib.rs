#![forbid(unsafe_code)]
pub mod blob;
pub mod email_batch;
pub mod connections;
pub mod push_state;
pub mod email_changes;
pub mod email_get;
pub mod email_list;
pub mod email_query;
pub mod email_set;
pub mod failure;
pub mod mailbox;
pub mod mailbox_set;
pub mod session;
pub mod submission;
pub mod set_seen;
pub mod messages;

pub use email_batch::{BatchOp, EmailBatch, Paged, email_batch, nudge_dismiss, read_paged};
pub use email_changes::{ChangesError, email_changes};
pub use email_get::{EmailGet, GetOutcome, email_get};
pub use email_list::{EmailListPage, EmailListQuery, Focus, query_email_list};
pub use email_query::query_email;
pub use email_set::{EmailSet, SetOutcome, SetPhase, email_set};
pub use failure::{Failure, classify as classify_failure};
pub use set_seen::{
    EmptySeen, OperationLookup, SeenEffect, SetSeenReply, lookup_set_seen, set_message_seen,
    set_message_seen_empty,
};

pub mod http_blob;

pub mod identity;
