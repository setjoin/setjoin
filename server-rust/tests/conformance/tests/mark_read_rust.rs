//! The mark-read oracle against the Rust command (`setjoin-jmap`, #214): the
//! same `mark_read` cases the reducer runs, unchanged. The Rust command owns
//! its transaction through `setjoin-pg` on its own pool (the `setjoin_app`
//! credential from `DB_APP_DSN` when set, as the reducer path runs), so the
//! oracle's command `Client` is used only to resolve the session's actor.
//!
//! `repeat_read_emits_no_state_change` runs here un-ignored: owner decision
//! 2026-10-29 (#219) — a no-op read bumps no state, journals nothing and
//! pushes nothing; the Rust command implements that contract.
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use setjoin_conformance::harness::{BoxError, Db};
use setjoin_conformance::mark_read::{self, SeenOutcome, SetSeen};
use setjoin_contracts::command::{CommandEnvelope, OperationResult, SetMessageSeen};
use setjoin_contracts::ids::{ActorId, Digest, Generation, OperationId};
use setjoin_db::lifecycle::accepted_contract;
use setjoin_jmap::{set_message_seen, SeenEffect};
use setjoin_pg::{MailboxAuthContext, ScopedExecutor};
use tokio_postgres::types::Type;
use tokio_postgres::Client;

pub struct RustCommand {
    exec: ScopedExecutor,
}

impl RustCommand {
    pub fn new(db: &Db) -> Self {
        let dsn = db.app.as_deref().unwrap_or(&db.dsn);
        Self {
            exec: ScopedExecutor::from_dsn(dsn, 2).expect("command pool"),
        }
    }
}

static NEXT_OPERATION: AtomicU64 = AtomicU64::new(1);

fn operation() -> OperationId {
    let n = NEXT_OPERATION.fetch_add(1, Ordering::Relaxed);
    let mut id = [0xA5; 16];
    id[8..].copy_from_slice(&n.to_be_bytes());
    OperationId(id)
}

impl SetSeen for RustCommand {
    fn name(&self) -> &'static str {
        "rust setjoin-jmap set_message_seen"
    }

    async fn set_seen(
        &self,
        client: &mut Client,
        cmd: SetMessageSeen,
    ) -> Result<SeenOutcome, BoxError> {
        // Plays the authentication boundary: the session's actor is the
        // mailbox's bound user.
        let user: i64 = client
            .query_typed(
                "SELECT user_id FROM mailboxes WHERE id = $1",
                &[(&cmd.mailbox.get(), Type::INT8)],
            )
            .await?[0]
            .get(0);
        let auth = MailboxAuthContext::from_authenticated_session(
            ActorId::new(user).map_err(|_| "mailbox has no bound user")?,
            cmd.mailbox,
            Generation(1),
        );
        let envelope = CommandEnvelope {
            operation: operation(),
            authority: auth.authority(),
            binding: accepted_contract(),
            payload_digest: Digest([3; 32]),
            command: cmd,
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        let reply = set_message_seen(&self.exec, &envelope, &auth, deadline).await;
        match reply.result {
            OperationResult::Accepted(SeenEffect::NotFound { .. }) => Ok(SeenOutcome::NotFound),
            OperationResult::Accepted(
                SeenEffect::Changed { .. } | SeenEffect::Unchanged { .. },
            ) => Ok(SeenOutcome::Updated),
            // A per-item reducer error is not an update (no oracle case
            // provokes one; the reducer impl treats it as a failure too).
            OperationResult::Accepted(SeenEffect::NotUpdated { set_error, .. }) => {
                Err(format!("{}: reducer notUpdated {set_error}", self.name()).into())
            }
            other => Err(format!("{}: {other:?} ({:?})", self.name(), reply.rejection).into()),
        }
    }
}

macro_rules! oracle_cases {
    ($($case:ident),+ $(,)?) => {
        $(
            #[tokio::test(flavor = "current_thread")]
            async fn $case() {
                let Some(db) = Db::for_case(stringify!($case)) else { return };
                let imp = RustCommand::new(&db);
                if let Err(e) = mark_read::$case(&db, &imp).await {
                    panic!("{}: {e:?}", stringify!($case));
                }
            }
        )+

        /// Every case in `mark_read::CASES` runs against Rust, none ignored.
        #[test]
        fn every_oracle_case_runs() {
            assert_eq!(&[$(stringify!($case)),+][..], mark_read::CASES);
        }
    };
}

oracle_cases!(
    read_sets_is_read,
    read_adjusts_unread_on_every_tag,
    read_bumps_email_state_once,
    read_writes_one_journal_row,
    read_pushes_once,
    unread_restores_unread_on_every_tag,
    repeat_read_changes_no_data,
    repeat_read_emits_no_state_change,
    foreign_mailbox_message_refused_without_effect,
);
