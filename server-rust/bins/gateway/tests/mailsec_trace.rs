//! F06 slice `trace`: frozen-Go oracle replayed without a Go upstream.
mod common;
mod mailsec_oracle;
macro_rules! case {
    ($name:ident, $action:literal, $kind:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), common::BoxError> {
            mailsec_oracle::run("trace", $action, $kind, None).await
        }
    };
}

// GET /admin/trace
case!(list_success, "list", "success");
case!(list_empty, "list", "empty");
case!(list_denied, "list", "denied");
case!(list_scoped, "list", "scoped");
case!(list_from, "list", "from");
case!(list_to, "list", "to");
case!(list_from_wildcard, "list", "from-wildcard");
case!(list_to_underscore, "list", "to-underscore");
case!(list_event, "list", "event");
case!(list_event_none, "list", "event-none");
case!(list_status, "list", "status");
case!(list_subject, "list", "subject");
case!(list_subject_wildcard, "list", "subject-wildcard");
case!(list_subject_unicode, "list", "subject-unicode");
case!(list_combined, "list", "combined");
case!(list_no_match, "list", "no-match");
case!(list_date_from, "list", "date-from");
case!(list_date_to, "list", "date-to");
case!(list_date_range, "list", "date-range");
case!(list_date_offset, "list", "date-offset");
case!(list_date_fraction, "list", "date-fraction");
case!(list_date_micro, "list", "date-micro");
case!(list_bad_date, "list", "bad-date");
case!(list_date_space, "list", "date-space");
case!(list_date_lower, "list", "date-lower");
case!(list_date_offset_24, "list", "date-offset-24");
case!(list_bad_utf8_from, "list", "bad-utf8-from");
case!(list_bad_utf8_subject, "list", "bad-utf8-subject");
case!(list_bad_utf8_status, "list", "bad-utf8-status");
case!(list_bad_utf8_event, "list", "bad-utf8-event");
case!(list_bad_utf8_to, "list", "bad-utf8-to");
case!(list_nul_byte, "list", "nul-byte");
case!(list_bad_utf8_date, "list", "bad-utf8-date");
case!(list_limit, "list", "limit");
case!(list_offset, "list", "offset");
case!(list_big_limit, "list", "big-limit");
case!(list_max_limit, "list", "max-limit");
case!(list_bad_limit, "list", "bad-limit");
case!(list_zero_limit, "list", "zero-limit");
case!(list_negative_offset, "list", "negative-offset");
case!(list_huge_offset, "list", "huge-offset");
case!(list_past_end, "list", "past-end");
case!(list_plus_limit, "list", "plus-limit");
case!(list_ignored_query, "list", "ignored-query");

case!(list_status_mutant, "list", "success-status-mutant");

// GET /admin/trace/export
case!(export_success, "export", "success");
case!(export_empty, "export", "empty");
case!(export_denied, "export", "denied");
case!(export_scoped, "export", "scoped");
case!(export_from, "export", "from");
case!(export_to, "export", "to");
case!(export_event, "export", "event");
case!(export_status, "export", "status");
case!(export_subject, "export", "subject");
case!(export_subject_wildcard, "export", "subject-wildcard");
case!(export_combined, "export", "combined");
case!(export_no_match, "export", "no-match");
case!(export_date_range, "export", "date-range");
case!(export_bad_date, "export", "bad-date");
case!(export_bad_utf8_from, "export", "bad-utf8-from");
case!(export_bad_utf8_subject, "export", "bad-utf8-subject");
case!(export_bad_utf8_status, "export", "bad-utf8-status");
case!(export_nul_byte, "export", "nul-byte");
case!(export_ignored_query, "export", "ignored-query");

case!(export_status_mutant, "export", "success-status-mutant");

// GET /admin/trace/{messageId}
case!(timeline_success, "timeline", "success");
case!(timeline_denied, "timeline", "denied");
case!(timeline_scoped, "timeline", "scoped");
case!(timeline_queue_deferred, "timeline", "queue-deferred");
case!(timeline_queue_bounced, "timeline", "queue-bounced");
case!(timeline_queue_pending, "timeline", "queue-pending");
case!(timeline_queue_skew, "timeline", "queue-skew");
case!(timeline_queue_sending, "timeline", "queue-sending");
case!(timeline_queue_legacy, "timeline", "queue-legacy");
case!(timeline_queue_latest, "timeline", "queue-latest");
case!(timeline_events_only, "timeline", "events-only");
case!(
    timeline_events_null_details,
    "timeline",
    "events-null-details"
);
case!(timeline_events_json_null, "timeline", "events-json-null");
case!(timeline_events_array, "timeline", "events-array");
case!(timeline_events_nested, "timeline", "events-nested");
case!(timeline_unknown, "timeline", "unknown");
case!(timeline_plain_id, "timeline", "plain-id");
case!(timeline_wildcard_id, "timeline", "wildcard-id");
case!(timeline_unescaped_id, "timeline", "unescaped-id");
case!(timeline_bad_utf8, "timeline", "bad-utf8");
case!(timeline_nul_byte, "timeline", "nul-byte");
case!(timeline_case_sensitive, "timeline", "case-sensitive");
case!(timeline_undo, "timeline", "undo");
case!(timeline_nothing, "timeline", "nothing");
case!(timeline_slash_id, "timeline", "slash-id");

case!(timeline_status_mutant, "timeline", "success-status-mutant");

// GET /messages/{emailId}/trace
case!(user_inbound_success, "user", "inbound-success");
case!(user_inbound_no_listener, "user", "inbound-no-listener");
case!(user_inbound_non200, "user", "inbound-non200");
case!(user_inbound_server_error, "user", "inbound-server-error");
case!(user_inbound_redirect, "user", "inbound-redirect");
case!(user_inbound_hostile, "user", "inbound-hostile");
case!(user_inbound_space_start, "user", "inbound-space-start");
case!(user_inbound_folded, "user", "inbound-folded");
case!(user_inbound_dates, "user", "inbound-dates");
case!(user_inbound_year_overflow, "user", "inbound-year-overflow");
case!(user_inbound_invalid_utf8, "user", "inbound-invalid-utf8");
case!(user_inbound_many, "user", "inbound-many");
case!(user_inbound_long_line, "user", "inbound-long-line");
case!(user_inbound_big, "user", "inbound-big");
case!(user_inbound_empty, "user", "inbound-empty");
case!(user_inbound_no_received, "user", "inbound-no-received");
case!(user_inbound_cookie, "user", "inbound-cookie");
case!(user_inbound_subject, "user", "inbound-subject");
case!(user_inbound_nosubject, "user", "inbound-nosubject");
case!(user_sent_delivered, "user", "sent-delivered");
case!(user_sent_pending, "user", "sent-pending");
case!(user_sent_skew, "user", "sent-skew");
case!(user_sent_undo, "user", "sent-undo");
case!(user_sent_deferred, "user", "sent-deferred");
case!(user_sent_bounced, "user", "sent-bounced");
case!(user_sent_nothing, "user", "sent-nothing");
case!(user_sent_sending, "user", "sent-sending");
case!(user_other, "user", "other");
case!(user_missing, "user", "missing");
case!(user_bad_id, "user", "bad-id");
case!(user_float_id, "user", "float-id");
case!(user_huge_id, "user", "huge-id");
case!(user_negative_id, "user", "negative-id");
case!(user_plus_id, "user", "plus-id");

case!(user_status_mutant, "user", "inbound-success-status-mutant");
