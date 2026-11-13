-- V139__federation_chat_binding.sql — Pillar C1 Task 1: the chat<->federation
-- binding schema. Promotes the C0 spike (V138, feature.federation) toward a
-- real federated-DM channel model: chat_channels gains the columns that mark
-- a channel as a federated DM + its dedup key; chat_messages gains the
-- columns that let a message's author be a REMOTE address instead of a local
-- user row. No new toggle — rides feature.federation (V138), seeded OFF.
--
-- The load-bearing compliance decision (plan "Identity, keys, and the one
-- poison-proof invariant" + Task 1): author_id DROP NOT NULL + a CHECK
-- requiring author_id OR federated_sender_addr. A sentinel local user (e.g.
-- id 0) would lie to every downstream reader — eDiscovery search/export,
-- retention, the read path all trust author_id as "this IS a local user".
-- NULL + federated_sender_addr is honest: the author is the remote address,
-- full stop. (Task 4 is the reducer that actually inserts such a row; this
-- migration only carries the shape.)

-- ── chat_channels: federated-DM marker + dedup key ─────────────────────────
-- federated_peer_domain non-NULL marks a chat_channels row as a federated DM
-- (kind='dm', sole local member — Task 2/4 enforce the shape; this migration
-- only adds the columns + the dedup guard). federated_remote_id is the bare
-- remote address (e.g. 'bob@bravo.test'). federated_local_key is the
-- symmetric dedup key — hash(lower(sorted(local_addr, remote_addr))) —
-- computed identically on both send (Task 2) and receive (Task 4); it is
-- DISTINCT from member_key (V119) on purpose: a federated DM's sole local
-- member means a sorted-member-ids key would collide the moment one user has
-- two federated DMs (with two different remote peers) — member_key stays
-- NULL for federated channels, this is a parallel key on a parallel axis.
ALTER TABLE public.chat_channels
    ADD COLUMN federated_peer_domain text NULL,
    ADD COLUMN federated_remote_id   text NULL,
    ADD COLUMN federated_local_key   text NULL;

-- The DM-dedup TOCTOU guard (V119 chat_channels_member_key_uq precedent):
-- two concurrent federation_dm_ensure() calls for the same (peer,local_key)
-- race on this index, not on a lookup. NULLs are distinct under a partial
-- UNIQUE, so non-federated channels (federated_peer_domain IS NULL) are
-- untouched. Task 2's ON CONFLICT arbiter must repeat this WHERE predicate.
CREATE UNIQUE INDEX chat_channels_federated_key_uk ON public.chat_channels
    (federated_peer_domain, federated_local_key) WHERE federated_peer_domain IS NOT NULL;

-- ── chat_messages: nullable author_id + federated sender/delivery columns ──
ALTER TABLE public.chat_messages
    ALTER COLUMN author_id DROP NOT NULL;

ALTER TABLE public.chat_messages
    ADD COLUMN federated_sender_addr text NULL,        -- remote author's bare address (author_id IS NULL)
    ADD COLUMN delivered_at          timestamptz NULL,  -- Task 6: ack-as-receipt, peer-scoped
    ADD COLUMN federated_stanza_id   text NULL,         -- sender's local chat_messages.id (clientMsgId)
    ADD COLUMN spam_quarantined      boolean NOT NULL DEFAULT false,  -- Task 4B: inbound quarantine-on-apply
    ADD COLUMN spam_reason           text NULL;

-- Every row has an author: a local user OR a remote address, never neither.
ALTER TABLE public.chat_messages
    ADD CONSTRAINT chat_messages_author_or_federated_ck
    CHECK (author_id IS NOT NULL OR federated_sender_addr IS NOT NULL);

-- Scoped inbound-dedup GUARD (not a plain index — a DB-enforced constraint,
-- same posture as chat_channels_federated_key_uk above): clientMsgId is
-- per-sender-DB and collides across peers, so idempotency is scoped to
-- (channel_id, federated_stanza_id), never a bare global key. Task 4's
-- inbound applier relies on this being ON CONFLICT-able (DO NOTHING) so a
-- clientMsgId dup arriving under a NEW (peer,seq) never aborts the txn.
CREATE UNIQUE INDEX chat_messages_fed_stanza_uk ON public.chat_messages
    (channel_id, federated_stanza_id) WHERE federated_stanza_id IS NOT NULL;

-- ── federation.manage permission ────────────────────────────────────────
-- Sensitive perm (Task 8's admin allow-list console). Deliberately OUTSIDE
-- the SoD class map — the drive.view/drive.manage (V114:551-560) and
-- chat.ediscovery (V127:112-115) precedent: cross-org trust-anchor
-- management doesn't fit the 等保 (SoD) class taxonomy any more than
-- eDiscovery export does. Do NOT add to shared/permissions.PermClasses or
-- the SQL perm->class map copies (sod_perm_map_guard_test.go enforces the
-- two stay in lockstep — adding federation.manage there would need a real
-- SoD classification decision this task doesn't make).
INSERT INTO public.admin_permissions (permission_key, category, description, is_sensitive) VALUES
  ('federation.manage', 'Federation', 'Manage the cross-org federation allow-list and trust anchors', true)
ON CONFLICT (permission_key) DO NOTHING;

UPDATE public.admin_role_groups
   SET permissions = (SELECT array_agg(DISTINCT p ORDER BY p)
                        FROM unnest(permissions || ARRAY['federation.manage']) AS p)
 WHERE id = 1;   -- Super Admin, exactly as V126:234-237 / V127:120-123

-- No new toggle (rides feature.federation, V138). No new act types.
INSERT INTO public.schema_migrations (version, applied_at) VALUES (139, now())
    ON CONFLICT (version) DO NOTHING;
