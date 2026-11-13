-- scripts/e6-fixture/reset-pair.sql
-- ──────────────────────────────────────────────────────────────────────────
-- CQ E6 fixture — restore the cold corpus state between pairs (and, for
-- strict cold-server state, between member runs; the E6 readiness section
-- documents the discipline).
--
-- Deterministic: deletes exactly the E6 corpus rows (fixed 5.0e9+ id space)
-- plus everything the workload generated for the two E6 accounts, then the
-- fixture re-runs seed-corpus.sql which re-inserts the identical corpus
-- (fixed ids, content a pure function of the profile runSeed). SeaweedFS/S3
-- attachment bytes are content-addressed and NOT touched: the same SHA-256
-- refs are re-registered, so no uploads happen on a reset.
--
-- NOT reset (deliberate): audit_log — append-only by trigger
-- (trg_audit_append_only, BZ017); per-pair audit growth is bounded by the
-- run scope and is not part of the measured corpus. mailserver_e6_e2e is a
-- run-scoped disposable database (see the seed guard), so nothing here can
-- reach shared state.
--
-- GUARD: same disposable-database assertion as seed-corpus.sql.
-- Run inside a single transaction (the fixture passes psql -1).
-- ──────────────────────────────────────────────────────────────────────────
\set ON_ERROR_STOP on

DO $e6_reset_guard$
DECLARE
  v_db text := current_database();
BEGIN
  IF v_db = 'mailserver_e6_e2e' OR v_db LIKE '%\_e6\_%' THEN
    RETURN;
  END IF;
  RAISE EXCEPTION
    'reset-pair.sql refuses to run against database "%" — not the disposable E6 fixture database (mailserver_e6_e2e or *_e6_*)',
    v_db
    USING ERRCODE = 'P0001';
END
$e6_reset_guard$;

-- Workload outcomes (read receipts reference corpus + sent-copy messages).
DELETE FROM read_receipts
 WHERE recipient_email IN ('e6-a@e6.test', 'e6-b@e6.test')
    OR message_id IN (SELECT id FROM messages WHERE mailbox_id IN (5210000001, 5210000002));

-- Outbound queue: every row in this run-scoped database is E6 traffic
-- (local self-addressed sends never enqueue; MDNs/external do).
DELETE FROM outbound_queue;
DELETE FROM blob_cleanup_queue;

-- Corpus + workload mail for the two E6 accounts (messages/message_tags are
-- partitioned; folder/tag counters are trigger-maintained on delete).
DELETE FROM message_attachments
 WHERE message_id IN (SELECT id FROM messages WHERE mailbox_id IN (5210000001, 5210000002));
DELETE FROM messages WHERE mailbox_id IN (5210000001, 5210000002);

-- Orphaned attachment/raw blobs left by the deleted mail (the attachment
-- DELETE trigger already decremented ref_count). The re-seed re-registers
-- the corpus blobs; S3 bytes stay.
DELETE FROM blobs WHERE ref_count <= 0;

-- Session surface: logins from the previous pair/member run.
DELETE FROM sessions    WHERE user_id IN (5200000001, 5200000002);
DELETE FROM login_events WHERE user_id IN (5200000001, 5200000002);

-- Auth-revocation device state back to the steady no-pending-wipe shape.
UPDATE user_devices SET wipe_requested = FALSE, wipe_acked_at = NULL
 WHERE user_id IN (5200000001, 5200000002);
UPDATE devices SET wipe_requested = FALSE, revoked_at = NULL
 WHERE id IN (5220000001, 5220000002);

-- Mailbox accounting + JMAP state watermarks back to cold.
UPDATE mailboxes
   SET used_bytes = 0,
       sending_sent_today = 0,
       sending_quota_reset_at = CURRENT_DATE,
       jmap_email_state = 0,
       jmap_mailbox_state = 0,
       jmap_thread_state = 0,
       jmap_tag_state = 0,
       jmap_reminder_state = 0
 WHERE id IN (5210000001, 5210000002);

-- Candidate substrate re-projection (see seed-corpus.sql): the fixture's
-- rollout-gate rows (feature.offline_mail + feature.connectivity_aware_sync —
-- offline_effective_policy and the Go substrate surfaces gate on the PAIR)
-- stay ON across resets. Re-asserted here (never assumed) so a mid-run
-- disable cannot survive a reset and silently flatten the measured candidate
-- delta to nil. Fires the same trg_feature_notify config_changed NOTIFY, so
-- the gateway's live toggle cache converges before the next member run.
-- Fixture-scoped: disposable fixture database only; production defaults
-- (both false) are untouched.
INSERT INTO feature_toggles (key, enabled, description)
VALUES ('feature.offline_mail', TRUE,
        'E6 fixture projection: candidate substrate ON in the disposable fixture database only (production default false).')
ON CONFLICT (key) DO UPDATE SET enabled = TRUE;

INSERT INTO feature_toggles (key, enabled, description)
VALUES ('feature.connectivity_aware_sync', TRUE,
        'E6 fixture projection: candidate substrate ON in the disposable fixture database only (production default false, V209).')
ON CONFLICT (key) DO UPDATE SET enabled = TRUE;
