//! The email-list oracle (#216) against the current authority, the reducer
//! `jmap_email_query` called as Go calls it. `email_list_rust.rs` runs the
//! same cases against the Rust read.
use setjoin_conformance::email_list;
use setjoin_conformance::harness::Db;
use setjoin_conformance::reducer_list::ReducerList;

macro_rules! oracle_cases {
    ($imp:expr; $($case:ident),+ $(,)?) => {
        $(
            #[tokio::test(flavor = "current_thread")]
            async fn $case() {
                let Some(db) = Db::for_case(stringify!($case)) else { return };
                if let Err(e) = email_list::$case(&db, &$imp).await {
                    panic!("{}: {e:?}", stringify!($case));
                }
            }
        )+

        /// Every case in `email_list::CASES` is wired here, and nothing else.
        #[test]
        fn every_oracle_case_runs() {
            assert_eq!(&[$(stringify!($case)),+][..], email_list::CASES);
        }
    };
}

oracle_cases!(ReducerList;
    first_page_is_newest_first_with_pinned_on_top,
    pages_continue_without_gaps_or_repeats,
    last_partial_page_and_page_at_total,
    stale_position_past_total_is_an_empty_page,
    empty_tag_is_an_empty_page,
    oldest_first_keeps_pinned_on_top,
    unread_and_read_filters,
    focused_and_other_split,
    snoozed_hidden_from_location_but_listed_under_snooze,
    label_lists_its_own_messages,
    foreign_tag_lists_nothing,
    listing_has_no_side_effects,
    equal_received_at_pages_in_id_order,
);
