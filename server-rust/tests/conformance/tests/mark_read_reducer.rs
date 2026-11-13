//! The mark-read oracle against the current authority (the reducer). #214 adds
//! a sibling file that runs these same cases against the Rust command.
use setjoin_conformance::harness::Db;
use setjoin_conformance::mark_read;
use setjoin_conformance::reducer::ReducerPath;

macro_rules! oracle_cases {
    ($imp:expr; $($(#[$attr:meta])* $case:ident),+ $(,)?) => {
        $(
            $(#[$attr])*
            #[tokio::test(flavor = "current_thread")]
            async fn $case() {
                let Some(db) = Db::for_case(stringify!($case)) else { return };
                if let Err(e) = mark_read::$case(&db, &$imp).await {
                    panic!("{}: {e:?}", stringify!($case));
                }
            }
        )+

        /// Every case in `mark_read::CASES` is wired here, and nothing else.
        #[test]
        fn every_oracle_case_runs() {
            assert_eq!(&[$(stringify!($case)),+][..], mark_read::CASES);
        }
    };
}

oracle_cases!(ReducerPath;
    read_sets_is_read,
    read_adjusts_unread_on_every_tag,
    read_bumps_email_state_once,
    read_writes_one_journal_row,
    read_pushes_once,
    unread_restores_unread_on_every_tag,
    repeat_read_changes_no_data,
    // Was FINDING #212 (ignored): the reducer bumped state/journal/push on a
    // no-op repeated read. Owner decision 2026-10-29: no-op means no effect;
    // fixed in the reducer by #219.
    repeat_read_emits_no_state_change,
    foreign_mailbox_message_refused_without_effect,
);
