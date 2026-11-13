-- chat_chain_anchor.sql — Chat A4a Task 9: the nightly per-channel message-
-- record digest that makes "tamper-evident" true (not just the acts).
--
-- Runs at 02:40, BEFORE chat-purge-expired at 02:50, so a range is always
-- anchored before it can be destroyed.
--
-- LEAF = sha256(original_body) (verify N3 — never md5: chosen-prefix
-- collisions are not acceptable in evidentiary material). The IDENTICAL
-- expression appears in chat_purge_expired's `destroyedElems` and in the
-- verifier below; if you change one you MUST change all three or every
-- anchor over a purged range silently goes red.
--
-- Spec: retired-docs:superpowers/plans/archive/2026-07-12-chat-A4a-records-lifecycle.md Task 9.
CREATE OR REPLACE FUNCTION chat_chain_anchor(p_batch_size INT DEFAULT 5000) RETURNS INT
LANGUAGE plpgsql AS $$
DECLARE
  v_ch RECORD; v_last BIGINT; v_from BIGINT; v_to BIGINT;
  v_n INT; v_digest TEXT; v_total INT := 0;
  v_notary_id BIGINT; v_notary_cs TEXT; v_cur_head BIGINT; v_heads JSONB;   -- FIX 1 (notary)
  v_last_notary JSONB;                                                       -- last run's head map
BEGIN
  IF NOT COALESCE((SELECT enabled FROM feature_toggles
                   WHERE key='feature.chat_compliance'), FALSE) THEN
    RETURN 0;
  END IF;

  -- FIX 2 — stamp the compliance-flip moment ONCE, the chain-start floor the
  -- verifier scopes `revisions_unchained` to. chat_message_revisions is written on
  -- EVERY edit regardless of the toggle, but message.edit acts only when it is ON;
  -- without this floor the first post-flip anchor would flag every pre-flip
  -- revision (no act) → verdict FALSE forever. Stamped lazily on the first ON run
  -- (ON CONFLICT DO NOTHING) so no toggle-flip code path needs hooking.
  -- ponytail: ceiling = up to one nightly cycle of imprecision after the real flip
  -- (fail-safe: at worst a revision in the first post-flip night is not flagged,
  -- never a false FALSE). Precise stamping at flip-time if a customer ever needs it;
  -- a re-toggle OFF→ON is not a modeled production scenario (Ship-posture).
  INSERT INTO system_config (key, value, description)
    VALUES ('chat.compliance_enabled_at', to_jsonb(now()::text),
            'Chat A4a: first moment feature.chat_compliance was active — the audit chain-start floor.')
  ON CONFLICT (key) DO NOTHING;

  -- FIX 1 — last run's notarized head map, fetched ONCE (the notary records ALL
  -- channels each run, so one row covers every channel; a channel absent from it
  -- is new since last notary → no floor to check).
  SELECT after_state->'heads' INTO v_last_notary
    FROM admin_audit_log WHERE action = 'chat.chain_notary' ORDER BY id DESC LIMIT 1;

  FOR v_ch IN SELECT id FROM chat_channels ORDER BY id LOOP
    -- Per-channel subtransaction + batch bound (verify N9 — the purge has both;
    -- v2's anchor had NEITHER). One statement looping 10k channels means a
    -- failure at channel 9,999 rolls back all 9,998 successful anchors and the
    -- night produces nothing. Same narrow discipline as the purge: nothing is
    -- swallowed silently — a channel that fails is RAISEd as a WARNING (visible
    -- in the cron log) and the remaining channels still get anchored.
    BEGIN
      -- highest id already anchored on this channel's chain (0 if never anchored).
      SELECT COALESCE(MAX((after_state->>'idTo')::bigint), 0) INTO v_last
        FROM chat_audit_log
       WHERE channel_id = v_ch.id AND action = 'chain.anchor';

      -- FIX 1 — TRUNCATION FLOOR. v_last is derived from the very chain it protects,
      -- so a tail-truncation (DELETE the anchor act + every higher chat_audit_log
      -- row) resets it to the surviving in-band MAX and the anchor below would
      -- happily RE-BLESS the truncated range over a rewritten body. Pin the floor to
      -- the last notarized head on the SEPARATE, append-only, HMAC-chained
      -- admin_audit_log (written after this loop): fetch this channel's last
      -- notarized (id, checksum); if the live chain head is now BELOW it, or the row
      -- at the notarized id no longer carries the notarized checksum, the chain was
      -- truncated/rewritten under us — SKIP LOUDLY (VerifyAudit reports it too), never
      -- re-anchor.
      v_notary_id := (v_last_notary->(v_ch.id::text)->>'id')::bigint;
      v_notary_cs := v_last_notary->(v_ch.id::text)->>'checksum';
      IF v_notary_id IS NOT NULL THEN
        SELECT MAX(id) INTO v_cur_head FROM chat_audit_log WHERE channel_id = v_ch.id;
        IF v_cur_head IS NULL OR v_cur_head < v_notary_id
           OR (SELECT after_state->>'_checksum' FROM chat_audit_log
                WHERE channel_id = v_ch.id AND id = v_notary_id) IS DISTINCT FROM v_notary_cs THEN
          RAISE WARNING 'chat_chain_anchor: channel % chain truncated/rewritten below notarized head % — skipping re-anchor', v_ch.id, v_notary_id;
          CONTINUE;
        END IF;
      END IF;

      -- Only fully-past days: never race today's live traffic.
      SELECT count(*)::int, MIN(m.id), MAX(m.id),
             encode(sha256(convert_to(COALESCE(string_agg(
               m.id::text||':'||m.author_id::text||':'||extract(epoch from m.created_at)::text||':'||
               encode(sha256(convert_to(COALESCE(r.prior_body, m.body), 'UTF8')), 'hex'),
               '|' ORDER BY m.id), ''), 'UTF8')), 'hex')
        INTO v_n, v_from, v_to, v_digest
        FROM chat_messages m
        LEFT JOIN LATERAL (
          SELECT prior_body FROM chat_message_revisions rv
           WHERE rv.message_id = m.id ORDER BY rv.id LIMIT 1
        ) r ON TRUE
       WHERE m.channel_id = v_ch.id
         AND m.id > v_last
         AND m.created_at < date_trunc('day', now());
      CONTINUE WHEN v_n = 0;

      PERFORM chat_access_audit(NULL, v_ch.id, 'chain.anchor', 'channel', v_ch.id, NULL,
        jsonb_build_object('idFrom', v_from, 'idTo', v_to, 'count', v_n, 'digest', v_digest),
        NULL, NULL);
      v_total := v_total + 1;
      EXIT WHEN v_total >= p_batch_size;   -- bound the run; the next tick resumes
    EXCEPTION WHEN OTHERS THEN
      -- Deliberately WIDE here and deliberately NOT silent: an anchor is
      -- best-effort per channel (unlike the purge, it destroys nothing), and one
      -- bad channel must not cost the org its whole night of evidence. The
      -- WARNING is the loud part.
      RAISE WARNING 'chat_chain_anchor: channel % failed: %', v_ch.id, SQLERRM;
    END;
  END LOOP;

  -- FIX 1 — THE CHAIN-HEAD NOTARY. After anchoring, record EVERY channel's head
  -- (id, checksum) in ONE row on the global admin_audit_log chain. That table is a
  -- DIFFERENT, append-only (trg_audit_append_only), HMAC-chained (trg_admin_audit_
  -- checksum, V037/V087) table an attacker must ALSO truncate coherently — so a
  -- tail-truncation of a channel's own chain leaves a head below the notarized
  -- floor, which the loop above (next run) and VerifyAudit both catch. audit_write
  -- is the only insert path (verified audit_write.sql:4-7). Chat's per-row checksum
  -- lives in after_state->>'_checksum' (V037 convention, V126 §F). All channels are
  -- notarized (a channel with acts but no new past-day messages still advanced its
  -- head and must be pinned).
  --
  -- NON-REGRESSING FLOOR: record GREATEST(current head, prior notarized floor) per
  -- channel, so a truncation detected this run does NOT heal into tomorrow's
  -- baseline — the higher floor persists in the (append-only, tamper-evident)
  -- notary until the chain is genuinely restored above it. A fully-truncated
  -- channel (no live rows) is carried forward from the prior notary.
  -- ponytail: the READ above (v_last_notary) is the single latest notary row, kept
  -- cheap by this carry-forward; if the notary is ever moved to its own table,
  -- switch the floor to MAX(head) across rows and drop the carry-forward.
  WITH cur AS (
    SELECT DISTINCT ON (channel_id) channel_id::text AS ch, id AS mx,
           after_state->>'_checksum' AS cs
      FROM chat_audit_log ORDER BY channel_id, id DESC
  ), prior AS (
    SELECT e.key AS ch, (e.value->>'id')::bigint AS pid, e.value->>'checksum' AS pcs
      FROM jsonb_each(COALESCE(v_last_notary, '{}'::jsonb)) e
  ), merged AS (
    SELECT COALESCE(c.ch, p.ch) AS ch,
           CASE WHEN p.pid IS NOT NULL AND (c.mx IS NULL OR p.pid > c.mx)
                THEN jsonb_build_object('id', p.pid, 'checksum', p.pcs)
                ELSE jsonb_build_object('id', c.mx, 'checksum', c.cs) END AS blob
      FROM cur c FULL JOIN prior p ON p.ch = c.ch
  )
  SELECT jsonb_object_agg(ch, blob) INTO v_heads FROM merged;
  IF v_heads IS NOT NULL THEN
    PERFORM audit_write(NULL, 'chat.chain_notary', 'chat', NULL, NULL,
      jsonb_build_object('heads', v_heads), NULL, NULL, 'core');
  END IF;

  RETURN v_total;
END $$;

-- Verifier: HARD verdict. Recompute each anchor's digest over
--   (rows still present in the id-range) ∪ (rows recovered from the chained
--    purge.execute acts' destroyedElems)
-- and additionally assert that every chat_message_revisions row in the range has
-- a matching message.edit act on the chain.
--
-- There is NO purge_overlap output (verify N1). v2 had one, and it made a lawful
-- purge and a body rewrite inside a purged range produce the IDENTICAL verdict —
-- i.e. the nightly cron laundered tampering in exactly the channels this feature
-- targets. `destroyedElems` (Task 6) is what replaces the excuse with a
-- reconciliation. Do not re-add purge_overlap.
--
-- Both the anchor act and the purge act live on the same HMAC chain, so the
-- recovered leaves cannot be forged. Callers MUST run verify_chat_audit_chain
-- first: if the chain itself is broken, this function's inputs are untrusted and
-- the route reports the chain break (Task 11b enforces the ordering).
CREATE OR REPLACE FUNCTION chat_chain_anchor_verify(
  p_channel_id BIGINT, p_anchor_id BIGINT DEFAULT NULL
) RETURNS TABLE(anchor_id BIGINT, id_from BIGINT, id_to BIGINT,
                valid BOOLEAN, reconciled_from_purge INT, revisions_unchained INT)
LANGUAGE plpgsql STABLE AS $$
DECLARE v_a RECORD; v_calc TEXT; v_flip TIMESTAMPTZ;
BEGIN
  -- FIX 2 — the chain-start floor: revisions written before compliance was flipped
  -- ON have no message.edit act (the act is toggle-gated; the revision row is not),
  -- so they must NOT be demanded of. NULL only if no anchor has ever run, in which
  -- case the loop below is empty anyway.
  SELECT (value #>> '{}')::timestamptz INTO v_flip
    FROM system_config WHERE key = 'chat.compliance_enabled_at';
  FOR v_a IN
    SELECT id, (after_state->>'idFrom')::bigint AS f, (after_state->>'idTo')::bigint AS t,
           after_state->>'digest' AS d
      FROM chat_audit_log
     WHERE channel_id = p_channel_id AND action = 'chain.anchor'
       AND (p_anchor_id IS NULL OR id = p_anchor_id)
     ORDER BY id
  LOOP
    -- elems(id) = the surviving rows' recomputed digest elements, UNION the elems
    -- the chained purge acts recorded for the rows they destroyed. author_id and
    -- created_at of a destroyed row are gone forever, so the purge act records the
    -- WHOLE pre-image element, not just the leaf — see the note under this snippet.
    WITH surviving AS (
      SELECT m.id,
             m.id::text||':'||m.author_id::text||':'||extract(epoch from m.created_at)::text||':'||
             encode(sha256(convert_to(COALESCE(r.prior_body, m.body), 'UTF8')), 'hex') AS elem
        FROM chat_messages m
        LEFT JOIN LATERAL (
          SELECT prior_body FROM chat_message_revisions rv
           WHERE rv.message_id = m.id ORDER BY rv.id LIMIT 1
        ) r ON TRUE
       WHERE m.channel_id = p_channel_id AND m.id BETWEEN v_a.f AND v_a.t
    ), destroyed AS (
      SELECT (e.key)::bigint AS id, e.value #>> '{}' AS elem
        FROM chat_audit_log p
        CROSS JOIN LATERAL jsonb_each(COALESCE(p.after_state->'destroyedElems', '{}'::jsonb)) e
       WHERE p.channel_id = p_channel_id AND p.action = 'purge.execute'
         AND (e.key)::bigint BETWEEN v_a.f AND v_a.t
    ), merged AS (
      SELECT id, elem FROM surviving
      UNION ALL
      SELECT id, elem FROM destroyed WHERE id NOT IN (SELECT id FROM surviving)
    )
    SELECT encode(sha256(convert_to(COALESCE(string_agg(elem, '|' ORDER BY id), ''), 'UTF8')), 'hex'),
           (SELECT count(*)::int FROM destroyed)
      INTO v_calc, reconciled_from_purge
      FROM merged;

    -- N6: a fabricated revision row launders a body rewrite (INSERT on
    -- chat_message_revisions is unrestricted, and the anchor's original_body is
    -- the FIRST revision's prior_body). Every revision in the range must have a
    -- matching, unforgeable message.edit act.
    SELECT count(*)::int INTO revisions_unchained
      FROM chat_message_revisions rv
     WHERE rv.channel_id = p_channel_id
       AND rv.message_id BETWEEN v_a.f AND v_a.t
       AND (v_flip IS NULL OR rv.created_at >= v_flip)     -- FIX 2: chained era only
       AND NOT EXISTS (SELECT 1 FROM chat_audit_log a
                        WHERE a.channel_id = p_channel_id
                          AND a.action = 'message.edit'
                          AND a.target_id = rv.message_id);

    anchor_id := v_a.id; id_from := v_a.f; id_to := v_a.t;
    valid := (v_calc = v_a.d) AND revisions_unchained = 0;
    RETURN NEXT;
  END LOOP;
END $$;
