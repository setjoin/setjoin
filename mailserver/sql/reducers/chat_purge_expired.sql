-- chat_purge_expired.sql — Chat A4a Task 6: the ONLY true destruction path
-- for chat content, plus chat_purge_run() (drains within a time budget).
-- Task 7 extends it with attachment storage reclamation (the A2 deferral).
-- Pillar C2 Task 8 Step 4 extends it again: the federation_outbox purge
-- scrub — this stays "the ONE place chat content dies" even though a
-- federated/room-bound channel's message bodies also sit, transiently, in
-- the deny-all federation_outbox transport queue (see
-- federation_outbox_redact_purged.sql).
--
-- Order of checks: classification (gxp NEVER purged, gate 2) -> hold -> retention
-- -> attachments (Task 7) -> federation_outbox scrub (C2 Task 8) -> refcount/GC
-- (existing drive rail).
-- Spec: retired-docs:superpowers/plans/archive/2026-07-12-chat-A4a-records-lifecycle.md Task 6/7;
-- retired-docs:superpowers/plans/archive/2026-07-17-pillar-C2-rooms-presence-federation.md Task 8.
CREATE OR REPLACE FUNCTION chat_purge_expired(
  p_batch_size INT DEFAULT 1000,
  p_dry_run    BOOLEAN DEFAULT FALSE
) RETURNS TABLE(channel_id BIGINT, purged_count INT, id_from BIGINT, id_to BIGINT,
                retention_days INT)
LANGUAGE plpgsql AS $$
DECLARE
  v_ch RECORD; v_total INT := 0; v_ret INT;
  v_n INT; v_from BIGINT; v_to BIGINT; v_seq_max BIGINT; v_elems JSONB;
  v_nodes BIGINT[];
  -- F4 (pipeline review fix): the scheduled_actions DELETE below had no
  -- RETURNING and no digest — a failed scheduled send is an A4b export class
  -- while retained, so its destruction was an unrecorded records event.
  -- scheduled_actions.id is a uuid (no MIN/MAX aggregate in this PG
  -- version, and no meaningful ordering over random uuids anyway, unlike
  -- chat_messages' sequential bigint identity) — array_agg is the honest
  -- "which rows" signal, not a fabricated range.
  v_sched_n INT; v_sched_ids uuid[];
  -- C2 Task 8 Step 4: origin-qualified {origin,key} pairs captured from the
  -- doomed chat_messages rows BEFORE they die — the federation_outbox purge
  -- scrub's match key (see federation_outbox_redact_purged.sql).
  v_fed_origin_keys jsonb;
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles
                   WHERE key='feature.chat_compliance'), FALSE) THEN
    RETURN;
  END IF;
  FOR v_ch IN
    SELECT c.id, chat_effective_retention(c.id) AS ret
      FROM chat_channels c
     WHERE c.classification = 'regular'        -- 1: gxp is never destroyed by a cron
       AND NOT chat_hold_active(c.id)          -- 2: hold, single-homed predicate
       AND chat_effective_retention(c.id) IS NOT NULL
  LOOP
    v_ret := v_ch.ret;
    BEGIN
      IF p_dry_run THEN
        SELECT count(*)::int, MIN(m.id), MAX(m.id) INTO v_n, v_from, v_to
          FROM chat_messages m
         WHERE m.channel_id = v_ch.id
           AND m.created_at + make_interval(days => v_ret) <= now();
        IF v_n > 0 THEN
          channel_id := v_ch.id; purged_count := v_n; id_from := v_from;
          id_to := v_to; retention_days := v_ret; RETURN NEXT;
        END IF;
        CONTINUE;
      END IF;

      -- Attachment-node collection BEFORE the message DELETE (Task 7): the
      -- CASCADE (chat_message_attachments.message_id ON DELETE CASCADE,
      -- V120:45) clears the link rows the moment the messages die, so this
      -- must run first or there is nothing left to join against.
      SELECT array_agg(DISTINCT a.file_node_id) INTO v_nodes
        FROM chat_message_attachments a
        JOIN chat_messages m ON m.id = a.message_id
       WHERE m.channel_id = v_ch.id
         AND m.created_at + make_interval(days => v_ret) <= now();

      -- risk 5 (verify N5 — BLOCKER in v2): message content OUTSIDE chat_messages.
      -- THIS DELETE RUNS BEFORE THE `CONTINUE WHEN v_n = 0` BELOW, DELIBERATELY.
      -- v2 had it after, so a channel with ZERO expired MESSAGES but expired
      -- failed/done chat_send rows — a scheduled send that failed and never became
      -- a message; or a channel whose messages were all purged on an earlier run —
      -- kept its verbatim body in a no-RLS `payload` FOREVER. Nothing else in the
      -- repo reaps these rows. Do not "tidy" this back below the CONTINUE.
      -- status <> 'pending': never destroy an UNFIRED scheduled message (that is
      -- silent content loss, not retention).
      --
      -- F4 (pipeline review fix): RETURNING id captures a count + id range so
      -- this destruction folds into the SAME purge.execute act below
      -- (alongside the message stats) instead of leaving it unrecorded — a
      -- failed/done scheduled-send body is A4b export content while
      -- retained. Originally scoped to when this destruction co-occurred
      -- with a message purge in the same channel/run — a channel with ONLY
      -- expired scheduled rows and zero expired messages still had its rows
      -- destroyed here, but the CONTINUE below used to short-circuit BEFORE
      -- the act, leaving that scheduled-only destruction unrecorded (the F4
      -- residual, closed by the confirmation-review fix: the CONTINUE below
      -- now only skips a channel with NOTHING destroyed on either leg — see
      -- chat_purge.pg's p_sched0 case).
      WITH sched_gone AS (
        DELETE FROM scheduled_actions
         WHERE action_kind = 'chat_send'
           AND (payload->>'channelId')::bigint = v_ch.id
           AND status <> 'pending'
           AND created_at + make_interval(days => v_ret) <= now()
        RETURNING id
      )
      SELECT count(*)::int, array_agg(id) INTO v_sched_n, v_sched_ids FROM sched_gone;

      -- The DELETE is BOUNDED (eng review #6). p_batch_size checked only BETWEEN
      -- channels would let ONE channel with millions of expired messages run a
      -- single unbounded DELETE + cascades in one transaction, blow the cron
      -- Timeout, roll back, and never make progress on ANY later tick. This is
      -- exactly what enforce_retention's LIMIT p_batch_size driving scan avoids
      -- (retention.sql:68). All of purgedCount/idFrom/idTo/destroyedElems derive
      -- from the `gone` CTE — never from a pre-scan, which would over-report.
      --
      -- LEAF HASH IS sha256, NEVER md5 (verify N3): this is evidentiary material
      -- in a 防篡改 feature; md5 has practical chosen-prefix collisions. Same
      -- one-liner, same cost.
      -- RETURNING builds the EXACT digest element Task 9's anchor concatenated:
      --   id ':' author_id ':' epoch(created_at) ':' sha256(original_body)
      -- author_id and created_at die with the row, so the act must record the
      -- whole element, not just the leaf — that is what lets the verifier
      -- reconcile an anchor over a purged range to a HARD boolean instead of
      -- shrugging with a purge_overlap flag (verify N1). epoch, not ::text: a
      -- timestamptz's rendering is DateStyle/TimeZone-dependent and would produce
      -- false tamper verdicts across sessions.
      WITH gone AS (
        DELETE FROM chat_messages
         WHERE id IN (SELECT id FROM chat_messages
                       -- table-qualified: chat_purge_expired's own OUT
                       -- parameter is also named channel_id, and PL/pgSQL's
                       -- default #variable_conflict=error rejects the bare
                       -- reference here as ambiguous (a real compile bug,
                       -- caught red-first, not a design point of the plan).
                       WHERE chat_messages.channel_id = v_ch.id
                         AND created_at + make_interval(days => v_ret) <= now()
                       ORDER BY id
                       LIMIT GREATEST(p_batch_size - v_total, 0))
        RETURNING id, seq, federated_origin_domain, federated_stanza_id,
                  id::text||':'||author_id::text||':'||
                  extract(epoch from created_at)::text||':'||
                  encode(sha256(convert_to(COALESCE(
                    (SELECT rv.prior_body FROM chat_message_revisions rv
                      WHERE rv.message_id = chat_messages.id
                      ORDER BY rv.id LIMIT 1), body), 'UTF8')), 'hex') AS elem
      )
      SELECT count(*)::int, MIN(id), MAX(id), MAX(seq),
             jsonb_object_agg(id::text, elem),
             jsonb_agg(jsonb_build_object('origin', federated_origin_domain,
                                           'key', COALESCE(federated_stanza_id, id::text)))
        INTO v_n, v_from, v_to, v_seq_max, v_elems, v_fed_origin_keys
        FROM gone;

      -- C2 Task 8 Step 4: scrub the transport-residue outbox copy of every
      -- doomed row's body — the ONE new call site at this choke point (see
      -- federation_outbox_redact_purged.sql for the origin-qualified match
      -- rules; a no-op on a non-federated channel or an empty batch).
      -- v_fed_origin_keys is jsonb_agg over ZERO rows (v_n = 0) -> NULL,
      -- which federation_outbox_redact_purged already treats as a no-op.
      PERFORM federation_outbox_redact_purged(v_ch.id, v_fed_origin_keys);
      -- FIX (pipeline-review confirmation, F4 residual): only skip the
      -- whole channel when NEITHER messages NOR scheduled rows were
      -- destroyed. Before this, `CONTINUE WHEN v_n = 0` also skipped the
      -- act below on a scheduled-only channel (v_sched_n > 0, v_n = 0) —
      -- leaving that destruction completely unrecorded, the exact
      -- "unrecorded destruction" gap F4 was meant to close, just on the
      -- zero-message path.
      CONTINUE WHEN v_n = 0 AND v_sched_n = 0;

      -- Node destroy loop AFTER the message DELETE (Task 7 — the A2 storage-
      -- reclamation deferral). drive_node_destroy_hard is the tier-2 trash
      -- sweeper: it returns false (never raises) unless purged_at IS NOT NULL
      -- (drive_node_destroy_hard.sql:45-47). A chat-attached node is
      -- permanently LIVE (BZ175 blocks trashing it through Drive — the very
      -- immutability guard A2 built), so calling it on a live node destroys
      -- nothing. This is a deliberate, purge-only lift of the never-trash
      -- posture: BZ175 lives in the drive *reducers* (drive_node_trash etc.),
      -- not in a trigger on drive_nodes, so a direct UPDATE here is not
      -- blocked (spec-delta 1). The NOT EXISTS guard on both statements
      -- excludes any node still referenced by another chat_message_attachments
      -- row (e.g. a shared-chunk sibling attached to a message that survives
      -- this run) — its OWN version/chunk-link stays alive even though the
      -- underlying chunk's ref_count still drops when a to-be-destroyed
      -- sibling version releases its own drive_version_chunks row.
      -- drive_node_destroy_hard already deletes chat_message_attachments rows
      -- itself (:71) — defense in depth, since the CASCADE above already
      -- cleared them — so no ordering dance around the link rows is needed.
      IF v_nodes IS NOT NULL THEN
        UPDATE drive_nodes
           SET deleted_at = COALESCE(deleted_at, now()),
               purged_at  = COALESCE(purged_at, now())
         WHERE id = ANY(v_nodes)
           AND NOT EXISTS (SELECT 1 FROM chat_message_attachments a
                            WHERE a.file_node_id = drive_nodes.id);
        PERFORM drive_node_destroy_hard(n)
           FROM unnest(v_nodes) AS n
          WHERE NOT EXISTS (SELECT 1 FROM chat_message_attachments a
                             WHERE a.file_node_id = n);
        v_nodes := NULL;
      END IF;

      -- last_purged_seq only ever advances on an actual message purge
      -- (v_seq_max is NULL for a scheduled-only channel; GREATEST ignores a
      -- NULL argument so the UPDATE would be a harmless no-op regardless,
      -- but skip it outright rather than write a no-op row).
      IF v_n > 0 THEN
        UPDATE chat_channels
           SET last_purged_seq = GREATEST(last_purged_seq, v_seq_max)
         WHERE id = v_ch.id;
      END IF;

      -- Proof of disposition, not just a count (gate 3, rewritten per verify N1/N2).
      -- `destroyedElems` is a PER-ID map {messageId -> the exact digest element
      -- the anchor concatenated: id:author_id:epoch(created_at):sha256(original_body)},
      -- naturally bounded by p_batch_size. It is what lets chat_chain_anchor_verify
      -- return a HARD boolean over a purged range: the verifier recomputes the
      -- anchor digest over (surviving leaves ∪ these recovered leaves) and gets an
      -- exact match or a genuine tamper verdict. There is NO `purge_overlap` excuse
      -- field anywhere in this design — v2 had one, and it made a lawful purge and a
      -- body rewrite inside a purged range produce the IDENTICAL verdict, i.e. the
      -- cron laundered tampering. Both this act and the anchor act ride the same
      -- HMAC chain, so these leaves cannot be forged.
      --
      -- A scalar "digest over the destroyed rows" (v2) is NOT retained: nobody can
      -- recompute a pre-image over rows that no longer exist, so it proved nothing.
      -- Do not re-add it.
      --
      -- FIX 4 — destroyedElems is KEPT despite the anchor-before-purge ordering.
      -- The anchor (02:40) always runs before the purge (02:50) and retention_days
      -- > 0 forbids same-day create-and-purge, so every purged row IS anchored
      -- before it dies — but that only guarantees a GOVERNING anchor exists to
      -- reconcile against; it does NOT make the destroyed elements recoverable. The
      -- anchor commits a SCALAR digest H(elem1|...|elemN), and a one-way hash cannot
      -- yield elem_k back, so H(surviving ∪ destroyed) is uncomputable after a purge
      -- without these retained elements. Dropping destroyedElems would break FIX 1's
      -- hard-boolean reconciliation, not simplify it.
      -- ponytail: ~120 B/destroyed message, permanent (chat_audit_log is never
      -- purged, A4a↔A4b contract #3): a 2M-message purge = ~240 MB of durable
      -- digest — the deliberate price of hard-boolean reconciliation. Upgrade path
      -- if it ever bites: a per-message body-hash column would let the anchor store
      -- recoverable-enough per-leaf commitments and shrink the purge act to bare ids
      -- (the §Goal-named tamper-evidence gap); not before a regulator or a disk asks.
      -- destroyedElems is COALESCEd to '{}' for a scheduled-only purge
      -- (v_n=0 -> jsonb_object_agg over zero rows is NULL, not '{}') — the
      -- anchor verifier's destroyedElems join is keyed on message id ranges
      -- (chat_chain_anchor.sql), so an empty map here reconciles nothing and
      -- is inert, never a gap.
      PERFORM chat_access_audit(NULL, v_ch.id, 'purge.execute', 'channel', v_ch.id,
        NULL, jsonb_build_object('purgedCount', v_n, 'idFrom', v_from, 'idTo', v_to,
                                 'seqMax', v_seq_max, 'retentionDays', v_ret,
                                 'source', 'retention', 'destroyedElems', COALESCE(v_elems, '{}'::jsonb),
                                 'scheduledDestroyedCount', v_sched_n,
                                 'scheduledDestroyedIds', COALESCE(to_jsonb(v_sched_ids), '[]'::jsonb)),
        NULL, NULL);

      -- The TABLE-returning summary row (purged_count/id_from/id_to) and the
      -- batch-size bookkeeping stay scoped to an ACTUAL message purge — a
      -- scheduled-only channel gets its act (above) but never a summary row
      -- of purged_count=0 (unchanged caller contract: chat_purge_run's
      -- SUM(purged_count)/batch-exit logic and chat_purge.pg's "no run row"
      -- assertions for a message-free channel both stay correct).
      IF v_n > 0 THEN
        channel_id := v_ch.id; purged_count := v_n; id_from := v_from;
        id_to := v_to; retention_days := v_ret; RETURN NEXT;
        v_total := v_total + v_n;
        EXIT WHEN v_total >= p_batch_size;
      END IF;
    EXCEPTION WHEN SQLSTATE 'BZ194' THEN
      -- ONLY the legal-hold trigger is a "skip this channel" outcome (belt for a
      -- hold flipped mid-run). Everything else propagates loudly — catching WHEN
      -- OTHERS here would miscount real failures as holds (retention.sql:96
      -- lesson, verbatim).
      NULL;
    END;
  END LOOP;
END $$;

-- chat_purge_run() DRAINS — it does not nibble (verify N7, decided: drain, not
-- state-the-rate). Loops until the backlog is drained or a time budget is
-- spent, so a huge backlog degrades into "several nights", never into a
-- timeout that rolls back and makes ZERO progress forever.
-- ponytail: flat batch + wall-clock budget. If a deployment ever needs faster
-- drain, raise the batch — do not build a scheduler.
CREATE OR REPLACE FUNCTION chat_purge_run() RETURNS INT
LANGUAGE plpgsql AS $$
DECLARE
  v_deadline timestamptz := clock_timestamp() + interval '90 seconds';
  v_pass_ch INT; v_pass_msg INT; v_channels INT := 0; v_messages INT := 0;
BEGIN
  LOOP
    SELECT count(*)::int, COALESCE(sum(purged_count), 0)::int
      INTO v_pass_ch, v_pass_msg
      FROM chat_purge_expired(5000, FALSE);
    v_channels := v_channels + v_pass_ch;
    v_messages := v_messages + v_pass_msg;
    EXIT WHEN v_pass_msg = 0 OR clock_timestamp() >= v_deadline;
  END LOOP;
  -- audit_write(p_actor, p_action, p_target_type, p_target_id, p_before, p_after,
  --             p_ip, p_notes, p_tier) — verified audit_write.sql:4-7; p_tier is
  --             'core'|'routine' and is NOT optional.
  PERFORM audit_write(NULL, 'chat.purge_run', 'chat', NULL, NULL,
    jsonb_build_object('channels', v_channels, 'messages', v_messages, 'source', 'cron',
                       'drained', v_pass_msg = 0),
    NULL, NULL, 'core');
  RETURN v_messages;
END $$;
