-- scripts/e6-fixture/seed-corpus.sql
-- ──────────────────────────────────────────────────────────────────────────
-- CQ E6 sustained-pair-run gateway fixture — deterministic corpus seed.
--
-- Profile: docs/verification/connectivity-e6-profile.json
--          (e6-electron-macos-arm64-v1): 2 accounts x 2,000 messages x
--          40 attachments per account, cold per pair.
--
-- Determinism contract (per the frozen profile's seed discipline):
--   - Every corpus row uses a FIXED primary key (5.0e9+ id space, far above
--     the sequences the workload advances), so message ids referenced by the
--     pinned E6_DRIVER_CLASS_BODIES are stable across boots AND resets.
--   - Every body/subject/attachment is a pure function of
--     "e6-pair-runbook-v1" (the profile runSeed) + the row index — no
--     random(), no now()-derived content — so re-runs are byte-identical.
--   - received_at is confined to the CURRENT month (the message_tags /
--     messages partitions create_monthly_partitions(1) pre-created at boot).
--   - reset-pair.sql deletes exactly the corpus + workload rows and re-runs
--     this file, restoring the cold state deterministically.
--
-- Reuses the repo's e2e seed conventions (mailserver/webmail/e2e/fixtures/
-- seed.sql): same loader path, same login password convention (TestPass123!,
-- hash reused verbatim), mfa_exempt + no forced password change, self-scoped
-- rows only. This file is ADDITIVE to that seed: the E6 accounts live in
-- their own domain and never touch @test.local data.
--
-- Attachment bytes go to SeaweedFS/S3 (content-addressed, SHA-256 refs,
-- blobs.ref_count trigger-maintained). Message raw bodies follow the
-- gateway's own jmap_email_set_create convention: raw_ref carries the RFC
-- 5322 text inline ("MinIO path or inline" per send.sql), so only the 80
-- attachment blobs need S3 uploads — the fixture exports the upload
-- manifest (ref + base64) with the same deterministic SELECT before running
-- this file, uploads each blob, and reset-pair never needs re-uploads
-- (S3 objects are content-addressed and survive the DB reset).
--
-- GUARD: refuses to run against any database that is not the disposable E6
-- fixture database. ON_ERROR_STOP is forced HERE so a refused seed can never
-- fall through and mutate the refused database.
-- ──────────────────────────────────────────────────────────────────────────
\set ON_ERROR_STOP on

DO $e6_seed_guard$
DECLARE
  v_db text := current_database();
BEGIN
  IF v_db = 'mailserver_e6_e2e' OR v_db LIKE '%\_e6\_%' THEN
    RETURN; -- disposable E6 fixture naming
  END IF;
  RAISE EXCEPTION
    'seed-corpus.sql refuses to run against database "%" — not the disposable E6 fixture database (mailserver_e6_e2e or *_e6_*)',
    v_db
    USING ERRCODE = 'P0001';
END
$e6_seed_guard$;

-- ── Domain, accounts, mailboxes ───────────────────────────────────────────
INSERT INTO domains (name, is_primary, is_local)
VALUES ('e6.test', FALSE, TRUE)
ON CONFLICT (name) DO NOTHING;

-- Fixed ids (5.2e9 space) so sessions/audit rows reference stable owners.
INSERT INTO users (id, username, domain_id, email, display_name, password_hash, is_admin)
SELECT u.id, u.username, d.id, u.email, u.display_name, u.password_hash, FALSE
FROM (VALUES
  (5200000001::bigint, 'e6-a', 'e6-a@e6.test', 'E6 Member A',
   '$2a$10$Cr7IyH5BDJESvufZ.DSB3.iPHh7KXlf4dI9K45.rN1FdOKSIj89hm'), -- TestPass123!
  (5200000002::bigint, 'e6-b', 'e6-b@e6.test', 'E6 Member B',
   '$2a$10$Cr7IyH5BDJESvufZ.DSB3.iPHh7KXlf4dI9K45.rN1FdOKSIj89hm')
) AS u(id, username, email, display_name, password_hash)
CROSS JOIN domains d
WHERE d.name = 'e6.test'
ON CONFLICT (id) DO NOTHING;

-- Password logins must not be gated by MFA / forced change (e2e convention).
UPDATE users
   SET mfa_exempt = TRUE, must_change_password = FALSE
 WHERE email IN ('e6-a@e6.test', 'e6-b@e6.test');

-- Mailbox insert fires the create_system_folders + create_system_tags
-- triggers automatically (baseline §mailbox insert). Fixed ids (5.21e9).
INSERT INTO mailboxes (id, user_id, domain_id, email, display_name, type, is_primary)
SELECT m.id, u.id, d.id, u.email, u.display_name, 'personal', TRUE
FROM (VALUES
  (5210000001::bigint, 5200000001::bigint, 'e6-a@e6.test', 'E6 Member A'),
  (5210000002::bigint, 5200000002::bigint, 'e6-b@e6.test', 'E6 Member B')
) AS m(id, user_id, email, display_name)
JOIN users u ON u.id = m.user_id
CROSS JOIN domains d
WHERE d.name = 'e6.test'
ON CONFLICT (id) DO NOTHING;

-- Sustained-run headroom: the queued-send Critical class fires the real
-- send() reducer ~1,000+ times per member run (per the frozen 20% mix and
-- the 1,000-per-class floor); the 500/day default would BZ004-fail the run.
-- Fixture-scoped posture, documented in the E6 readiness section.
UPDATE mailboxes
   SET sending_quota_day = 1000000
 WHERE id IN (5210000001, 5210000002);

-- ── Candidate substrate: project the rollout gates ON ─────────────────────
-- The paired run's measured delta is the candidate running WITH the
-- connectivity-aware-sync substrate. The codebase's substrate projection and
-- surfaces gate on BOTH rollout rows:
--   - offline_effective_policy (the SQL projection the session document's
--     effectiveCapabilities ride on) admits 'syncQoS' only when
--     feature.offline_mail AND feature.connectivity_aware_sync are both ON;
--   - the Go surfaces (PUT /user/offline/sync-preferences, attachment
--     transfer) gate on the same pair via the gateway's FeatureFlags cache.
-- While they are OFF the server projects no substrate at all, so the
-- candidate's coordinator would stay inert and the measured delta nil.
-- Projection path (the codebase's own): the global feature_toggles rows
-- (V209 + the offline_mail seed row), read by the gateway's FeatureFlags
-- cache (refreshed via the trg_feature_notify config_changed NOTIFY).
-- Fixture-scoped BY CONSTRUCTION: feature_toggles is global-but-per-database
-- and this is the disposable mailserver_e6_e2e fixture DB whose only accounts
-- are the two E6 members — the production defaults (both false) are untouched
-- elsewhere, and the comparator member stays flag-OFF through its CLIENT env
-- seam (SETJOIN_E6_CONNECTIVITY_SYNC_MODE=off), never through these rows.
-- reset-pair.sql re-asserts the projection after every reset.
INSERT INTO feature_toggles (key, enabled, description)
VALUES ('feature.offline_mail', TRUE,
        'E6 fixture projection: candidate substrate ON in the disposable fixture database only (production default false).')
ON CONFLICT (key) DO UPDATE SET enabled = TRUE;

INSERT INTO feature_toggles (key, enabled, description)
VALUES ('feature.connectivity_aware_sync', TRUE,
        'E6 fixture projection: candidate substrate ON in the disposable fixture database only (production default false, V209).')
ON CONFLICT (key) DO UPDATE SET enabled = TRUE;

-- ── Device rows for the auth-revocation Critical class ────────────────────
-- POST /api/offline/wipe-ack resolves user_devices.device_id → devices.id
-- (V059). One desktop device per member; the steady-state idempotent path
-- (no pending wipe → reducer BZ101 → handler 200) is the sustained shape.
INSERT INTO devices (id, user_id, device_name, platform, fingerprint, hmac_secret, compliance_status)
VALUES
  (5220000001::bigint, 5200000001::bigint, 'E6 Fixture Device A', 'desktop',
   md5('e6-pair-runbook-v1:fingerprint:a'), md5('e6-pair-runbook-v1:hmac:a'), 'compliant'),
  (5220000002::bigint, 5200000002::bigint, 'E6 Fixture Device B', 'desktop',
   md5('e6-pair-runbook-v1:fingerprint:b'), md5('e6-pair-runbook-v1:hmac:b'), 'compliant')
ON CONFLICT (id) DO NOTHING;

INSERT INTO user_devices (id, user_id, device_id, device_name, platform)
VALUES
  (5230000001::bigint, 5200000001::bigint, 5220000001::bigint, 'E6 Fixture Device A', 'desktop'),
  (5230000002::bigint, 5200000002::bigint, 5220000002::bigint, 'E6 Fixture Device B', 'desktop')
ON CONFLICT (id) DO NOTHING;

-- ── Corpus: 2 accounts x 2,000 messages ───────────────────────────────────
-- Content is a pure function of the profile runSeed + index. Delivery-state
-- columns are neutral (received, unread) so the client pair starts cold.
DO $e6_corpus$
DECLARE
  v_acc        text;
  v_own        text;
  v_other      text;
  v_mb         bigint;
  v_base       bigint;
  v_inbox_f    bigint;
  v_inbox_t    bigint;
  v_month      timestamptz := date_trunc('month', now());
  v_raw        text;
  v_body       text;
  v_from       text;
  v_i          integer;
BEGIN
  FOR v_acc, v_own, v_other, v_mb, v_base IN
    SELECT * FROM (VALUES
      ('a', 'e6-a@e6.test', 'e6-b@e6.test', 5210000001::bigint, 5000000000::bigint),
      ('b', 'e6-b@e6.test', 'e6-a@e6.test', 5210000002::bigint, 5100000000::bigint)
    ) AS t(acc, own, other, mb, base)
  LOOP
    SELECT id INTO v_inbox_f FROM folders
     WHERE mailbox_id = v_mb AND role = 'inbox';
    SELECT id INTO v_inbox_t FROM tags
     WHERE mailbox_id = v_mb AND name = 'Inbox';
    IF v_inbox_f IS NULL OR v_inbox_t IS NULL THEN
      RAISE EXCEPTION 'E6 seed: system folders/tags missing for mailbox % (trigger did not fire)', v_mb;
    END IF;

    FOR v_i IN 1..2000 LOOP
      v_body := 'E6 corpus message ' || v_i || '. '
             || md5('e6-pair-runbook-v1:msg:' || v_acc || ':' || v_i || ':1') || ' '
             || md5('e6-pair-runbook-v1:msg:' || v_acc || ':' || v_i || ':2') || ' '
             || md5('e6-pair-runbook-v1:msg:' || v_acc || ':' || v_i || ':3');
      v_from := CASE WHEN v_i % 5 = 0 THEN 'bulletins@lists.e6.test' ELSE v_other END;
      v_raw := 'Message-ID: <e6-' || v_acc || '-' || v_i || '@e6.test>' || E'\r\n'
            || 'Date: ' || to_char(v_month, 'Dy, DD Mon YYYY HH24:MI:SS +0000') || E'\r\n'
            || 'From: E6 Fixture <' || v_from || '>' || E'\r\n'
            || 'To: E6 Member <' || v_own || '>' || E'\r\n'
            || 'Subject: E6 corpus ' || v_acc || ' message ' || v_i || E'\r\n'
            || 'MIME-Version: 1.0' || E'\r\n'
            || 'Content-Type: text/plain; charset=utf-8' || E'\r\n'
            || E'\r\n' || v_body;

      INSERT INTO messages (
        id, mailbox_id, folder_id, message_id, subject,
        from_addr, from_name, to_addrs,
        body_text, size_bytes, has_attachments, is_read, is_draft,
        thread_id, raw_ref, read_receipt_requested,
        received_at, imap_uid, imap_modseq
      ) VALUES (
        v_base + v_i, v_mb, v_inbox_f,
        '<e6-' || v_acc || '-' || v_i || '@e6.test>',
        'E6 corpus ' || v_acc || ' message ' || v_i,
        v_from, 'E6 Fixture',
        jsonb_build_array(jsonb_build_object('email', v_own, 'name', 'E6 Member')),
        v_body, octet_length(v_raw), (v_i <= 40), (v_i % 3 = 0), FALSE,
        'e6-thread-' || v_acc || '-' || ((v_i + 3) / 4),
        v_raw, (v_i = 1),
        v_month + make_interval(hours => ((v_i * 7) % 640)),
        v_i, 1
      );

      INSERT INTO message_tags (message_id, received_at, tag_id, added_by, is_primary)
      VALUES (v_base + v_i, v_month + make_interval(hours => ((v_i * 7) % 640)),
              v_inbox_t, 'e6-fixture', TRUE);
    END LOOP;
  END LOOP;
END
$e6_corpus$;

-- ── Attachments: 40 per account, content-addressed in S3 ──────────────────
-- 16 KiB deterministic bytes each; one attachment on each of the first 40
-- corpus messages (has_attachment TRUE above matches). blobs.ref_count = 1
-- per reference (trigger-maintained on delete).
INSERT INTO blobs (sha256, minio_ref, size_bytes, content_type, ref_count)
SELECT encode(sha256(convert_to(a.content, 'UTF8')), 'hex'),
       'mailblobs/' || encode(sha256(convert_to(a.content, 'UTF8')), 'hex'),
       octet_length(a.content), 'application/octet-stream', 1
FROM (SELECT a.acc, g.n, repeat(md5('e6-pair-runbook-v1:att:' || a.acc || ':' || g.n), 512) AS content
      FROM (VALUES ('a'), ('b')) AS a(acc)
      CROSS JOIN generate_series(1, 40) AS g(n)) a
ON CONFLICT (sha256) DO NOTHING;

INSERT INTO message_attachments (
  id, message_id, blob_sha256, filename, content_type, disposition, size_bytes, received_at
)
SELECT
  CASE a.acc WHEN 'a' THEN 5300000000 ELSE 5300001000 END + a.n,
  CASE a.acc WHEN 'a' THEN 5000000000 ELSE 5100000000 END + a.n,
  encode(sha256(convert_to(a.content, 'UTF8')), 'hex'),
  'e6-attachment-' || a.acc || '-' || a.n || '.bin',
  'application/octet-stream', 'attachment', octet_length(a.content),
  date_trunc('month', now()) + make_interval(hours => ((a.n * 7) % 640))
FROM (SELECT a.acc, g.n, repeat(md5('e6-pair-runbook-v1:att:' || a.acc || ':' || g.n), 512) AS content
      FROM (VALUES ('a'), ('b')) AS a(acc)
      CROSS JOIN generate_series(1, 40) AS g(n)) a;

-- ── Queued-send probe drafts (one per member) ─────────────────────────────
-- The pinned queued-send route submits THIS draft every attempt with
-- onSuccessUpdateEmail present, so the reducer keeps the draft and every
-- attempt is a real send() + local deliver() (self-addressed: the only
-- recipient is the member's own mailbox, keeping each member's workload
-- self-scoped and both members symmetric).
DO $e6_drafts$
DECLARE
  v_row      record;
  v_inbox_f  bigint;
  v_drafts_f bigint;
  v_drafts_t bigint;
  v_raw      text;
  v_body     text := 'E6 queued-send probe body (fixed corpus text). '
                   || md5('e6-pair-runbook-v1:queued-send-probe');
BEGIN
  FOR v_row IN
    SELECT * FROM (VALUES
      ('a', 'e6-a@e6.test', 5210000001::bigint, 5400000001::bigint, '<e6-draft-a@e6.test>'),
      ('b', 'e6-b@e6.test', 5210000002::bigint, 5400000002::bigint, '<e6-draft-b@e6.test>')
    ) AS t(acc, own, mb, draft_id, msgid)
  LOOP
    SELECT id INTO v_inbox_f  FROM folders WHERE mailbox_id = v_row.mb AND role = 'inbox';
    SELECT id INTO v_drafts_f FROM folders WHERE mailbox_id = v_row.mb AND role = 'drafts';
    SELECT id INTO v_drafts_t FROM tags    WHERE mailbox_id = v_row.mb AND name = 'Drafts';
    IF v_drafts_f IS NULL OR v_drafts_t IS NULL THEN
      RAISE EXCEPTION 'E6 seed: drafts folder/tag missing for mailbox %', v_row.mb;
    END IF;

    v_raw := 'Message-ID: ' || v_row.msgid || E'\r\n'
          || 'From: E6 Member <' || v_row.own || '>' || E'\r\n'
          || 'To: E6 Member <' || v_row.own || '>' || E'\r\n'
          || 'Subject: E6 queued-send probe' || E'\r\n'
          || 'MIME-Version: 1.0' || E'\r\n'
          || 'Content-Type: text/plain; charset=utf-8' || E'\r\n'
          || E'\r\n' || v_body;

    INSERT INTO messages (
      id, mailbox_id, folder_id, message_id, subject,
      from_addr, from_name, to_addrs,
      body_text, size_bytes, has_attachments, is_read, is_draft,
      thread_id, raw_ref, received_at, imap_uid, imap_modseq
    ) VALUES (
      v_row.draft_id, v_row.mb, v_drafts_f, v_row.msgid, 'E6 queued-send probe',
      v_row.own, 'E6 Member',
      jsonb_build_array(jsonb_build_object('email', v_row.own, 'name', 'E6 Member')),
      v_body, octet_length(v_raw), FALSE, TRUE, TRUE,
      'e6-thread-queued-send-' || v_row.acc, v_raw,
      date_trunc('month', now()), 2001, 1
    );

    INSERT INTO message_tags (message_id, received_at, tag_id, added_by, is_primary)
    VALUES (v_row.draft_id, date_trunc('month', now()), v_drafts_t, 'e6-fixture', TRUE);
  END LOOP;
END
$e6_drafts$;
