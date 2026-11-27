#![forbid(unsafe_code)]
pub mod blob;
pub mod connections;
pub mod email_batch;
pub mod email_changes;
pub mod email_get;
pub mod email_list;
pub mod email_query;
pub mod email_set;
pub mod failure;
pub mod http_blob;
pub mod identity;
pub mod mailbox;
pub mod mailbox_set;
pub mod messages;
pub mod push_state;
pub mod session;
pub mod set_seen;
pub mod sql;
pub mod submission;

pub use email_batch::{email_batch, nudge_dismiss, read_paged, BatchOp, EmailBatch, Paged};
pub use email_changes::{email_changes, ChangesError};
pub use email_get::{email_get, EmailGet, GetOutcome};
pub use email_list::{query_email_list, EmailListPage, EmailListQuery, Focus};
pub use email_query::query_email;
pub use email_set::{
    decode_owned_blob_set, email_set, email_set_batch, snooze_message, EmailSet, SetBatch,
    SetBatchOutcome, SetOutcome, SetPhase, SnoozeOutcome,
};
pub use failure::{classify as classify_failure, Failure};
pub use set_seen::{
    lookup_set_seen, set_message_seen, set_message_seen_empty, EmptySeen, OperationLookup,
    SeenEffect, SetSeenReply,
};
pub use setjoin_authz::principals::TxFactory;
pub use sql::SQL_CONTRACTS;
