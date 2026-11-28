-- ════════════════════════════════════════════════════════════════════════
-- V252__chat_unfurl_legacy_preview_quarantine.sql — med-chat-unfurl-href-001
-- (r4 QUARANTINE arm): strip every stored payload.preview that exists at
-- migration time, regardless of any provenance marker.
--
-- med-chat-unfurl-href-001 r2 made MessageRow render an unfurl card ONLY for a
-- preview carrying 'appliedBy' => 'chat_message_unfurl_apply' — the marker the
-- unfurl reducer stamps (chat_unfurl.sql). chat_message_send strips sender-
-- supplied previews outright and chat_message_edit writes body only, so the
-- marker cannot be forged through any reducer path GOING FORWARD. The render
-- gate alone cannot establish LEGACY provenance, though: the old send path
-- accepted arbitrary payloads, so an already-stored forged HTTPS card —
-- marker-less — sat in chat_messages, failing closed at render while still
-- shipping attacker-authored content inside the stored payload (a forged row
-- would render the instant the client-side gate ever weakened).
--
-- This migration is the QUARANTINE arm: it removes payload.preview from the
-- ENTIRE at-migration population — every row, marker-bearing or not. The r3
-- sweep exempted rows already carrying the marker; that exemption was wrong
-- (Astra r3 re-review): the appliedBy stamp's only writer,
-- chat_message_unfurl_apply, is installed by THIS delta, and migrations run
-- at startup before the new code serves traffic — so any row present when
-- V252 runs, marker included, predates the legitimate writer. A legacy
-- marker-bearing row proves nothing: the marker is a public constant the old
-- send path would have stored verbatim inside an attacker-controlled
-- payload, and a marker it did not carry at render time says nothing about
-- who wrote the rest of the JSON. Quarantining it costs nothing but a
-- re-fetch the new worker performs anyway; trusting it would keep attacker-
-- authored card content rendering behind the very gate meant to exclude it.
--
-- Honest residual (explicitly retained as unresolved, per the review arm),
-- confined to POST-migration rows: only rows written after this migration by
-- chat_message_unfurl_apply carry a trusted marker. A row written LATER
-- bearing a FORGED marker is client-side indistinguishable from a reducer-
-- written one — the marker is a public constant, so closing that case
-- requires sender/worker signing, an owner decision out of scope here.
-- MessageRow.svelte keeps the marker gate as the go-forward check; V252
-- empties the entire at-migration population that gate cannot prove, and the
-- reducer is the only writer the surviving population can have.
--
-- WORM safety: payload is EXEMPT from trg_chat_message_worm (V126 §D — a
-- "payload/seq/edited_at-only change: allowed"; body and deleted_at are
-- untouched), so the sweep is legal even inside gxp retention — the same
-- exemption the unfurl worker itself relies on. trg_chat_message_hold fires
-- BEFORE DELETE only and does not see this UPDATE.
--
-- One-statement data sweep: no reducer function is installed (post-ARCH-007
-- the fixed-point reload re-applies reducers — a one-shot quarantine must not
-- become live code). The sweep is idempotent: a second application matches no
-- rows. Full scan over chat_messages WHERE payload ? 'preview' is the price
-- of a one-shot migration; no GIN index on payload exists to lean on.
-- ════════════════════════════════════════════════════════════════════════

UPDATE public.chat_messages
   SET payload = payload - 'preview'
 WHERE payload ? 'preview';

-- ── schema_migrations row ────────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (252, now())
    ON CONFLICT (version) DO NOTHING;
