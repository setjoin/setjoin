-- chat_read.sql: read-watermark + conversation-list reducers (Pillar A1 Task 6).
-- (self-scoped only — chat_mark_read deliberately does NOT route through
-- notify_chat_state's all-member fan-out; see the function body. Bug found
-- + fixed mid-Task-17-gate: the ORIGINAL two-line "-- deps:" comment put
-- prose on the SAME grep-matched line, and reload-reducers.sh's dep parser
-- word-splits that line looking for function names — it picked up the
-- prose word "chat_mark_read" (this file's OWN function) as a bogus
-- dependency, resolved it back to this file via the def-file lookup, and
-- created a self-referential cycle. sort_reducers() detected the cycle and
-- returned empty-handed; reload-reducers.sh's caller never checks that exit
-- code, so the ENTIRE reducer set silently failed to load (~200+ functions
-- missing from pg_proc) while every gate reported OK. Keep the "-- deps:"
-- line to EXACTLY the function-name list — put any explanation on a
-- following line without that prefix.)
--
-- Producers: chat_mark_read, chat_conversation_list.
--
-- BZ block (chat = BZ160-BZ175, this file's slice): BZ163 not a channel
-- member (both reducers).
--
-- App-level-primary (ARCH-006): membership scoped via a direct SELECT
-- against chat_channel_members, not the chat_member_role() DEFINER helper
-- (that helper exists solely for the latent FORCE-RLS policy).

-- F7: the watermark is clamped to the channel's CURRENT change_seq and only
-- ever moves forward. A client racing ahead with a stale/garbage seq (or a
-- bogus Long.MAX_VALUE) can never push last_read_seq past what actually
-- exists — an unclamped watermark would zero the unread count forever
-- (nothing future could ever out-seq it, since real messages only ever
-- reach the channel's true change_seq, never beyond a client's guess).
CREATE OR REPLACE FUNCTION chat_mark_read(
    p_user_id bigint, p_channel_id bigint, p_seq bigint
) RETURNS void AS $$
DECLARE
    v_change_seq bigint;
    v_clamped    bigint;
    v_kind       text;
    v_peer_id    bigint;
    v_floor      bigint;
BEGIN
    PERFORM guest_require_active(p_user_id);  -- BZ219 belt (no-op for members)
    SELECT c.change_seq, c.kind, m.history_floor_seq INTO v_change_seq, v_kind, v_floor
      FROM chat_channels c JOIN chat_channel_members m ON m.channel_id = c.id
     WHERE c.id = p_channel_id AND m.user_id = p_user_id;
    IF v_change_seq IS NULL THEN
        RAISE EXCEPTION 'not a member of channel %', p_channel_id
            USING ERRCODE='BZ163', HINT='{"type":"forbidden"}';
    END IF;
    v_clamped := GREATEST(COALESCE(v_floor, 0), LEAST(p_seq, v_change_seq));
    -- monotonic: GREATEST ignores a client re-sending an OLDER watermark
    -- (out-of-order acks, a stale tab reconnecting) — the read cursor can
    -- only advance, never rewind.
    UPDATE chat_channel_members
       SET last_read_seq = GREATEST(last_read_seq, v_clamped)
     WHERE channel_id = p_channel_id AND user_id = p_user_id;
    -- self-notify ONLY the acting user's own chat:{user_id} channel — this
    -- is per-user state (last_read_seq for user_id), not channel-wide state,
    -- so it must NOT go through notify_chat_state's all-member fan-out: that
    -- would (a) push an unattributable event to every OTHER member too
    -- (O(members) amplification on the highest-frequency chat event), and
    -- (b) hand Task 12's applyEvent a payload with no userId, so a naive
    -- "read syncs the watermark" client would apply user A's watermark to
    -- user B's own state and silently clear B's unread badge. Event name is
    -- 'read' per the plan/Task 12 contract; userId is carried explicitly so
    -- a client can defend even if it ever listens broader than its own
    -- self-channel.
    PERFORM app_notify('chat:' || p_user_id, jsonb_build_object(
        'event', 'read', 'channelId', p_channel_id,
        'userId', p_user_id, 'seq', v_clamped)::text);
    -- Pillar A3 QoL Task 4 (ADR DES-010): fan out 'member_read' to the OTHER
    -- member(s) so a DM read-tick updates live — DM-only (kind='dm' is
    -- exactly 2 members, V119's chat_dm_open), because a channel of any
    -- real size would turn this into O(members) live notify traffic on the
    -- highest-frequency chat event for a feature the UI only needs on
    -- open/focus (channels refetch chat_channel_readers there instead, no
    -- live event). A group_dm (kind='group_dm') is deliberately excluded
    -- too — it can grow past "2 members, cheap".
    IF v_kind = 'dm' THEN
        FOR v_peer_id IN
            SELECT user_id FROM chat_channel_members
             WHERE channel_id = p_channel_id AND user_id <> p_user_id
        LOOP
            PERFORM app_notify('chat:' || v_peer_id, jsonb_build_object(
                'event', 'member_read', 'channelId', p_channel_id,
                'userId', p_user_id, 'seq', v_clamped)::text);
        END LOOP;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Per-conversation summary for the chat home view. Archived channels are
-- hidden here too (Task 4's "archive = read-only + hidden from browse/
-- conversation list"). unreadCount is computed against top-level messages
-- only (grill Q4: thread replies never bump channel unread — they surface
-- via the parent's live replyCount; My Threads is A3). hasMention is
-- DELIBERATELY not top-level-only: an @mention inside a thread reply still
-- flags the channel — mentions are the "someone needs you" signal, and grill
-- Q4 excluded replies from unread COUNTS, not from mention visibility. Both
-- read above the caller's OWN last_read_seq and both ignore soft-deleted
-- messages (a delete re-stamps seq, which must not resurrect a phantom badge).
CREATE OR REPLACE FUNCTION chat_conversation_list(p_user_id bigint) RETURNS jsonb AS $$
    SELECT COALESCE(jsonb_agg(jsonb_build_object(
             'channelId', c.id,
             'kind', c.kind,
             'name', c.name,
             'topic', c.topic,
             'changeSeq', c.change_seq,
             'lastReadSeq', m.last_read_seq,
             -- Chat A4a Task 8: classification is the ONLY compliance state
             -- projected to end users — legalHold and last_purged_seq are
             -- deliberately NOT (design review #11: a hold must be invisible
             -- to the custodians it targets; last_purged_seq is provenance,
             -- not a cursor). retentionDays reads the same knob under two
             -- DIFFERENT client-side labels depending on classification (a
             -- destroy ceiling for 'regular', a WORM keep-floor for 'gxp') —
             -- the client, never this reducer, picks the label.
             'classification', c.classification,
             'retentionDays', chat_effective_retention(c.id),
             -- A3 QoL Task 7: the settings/composer UIs need all three —
             -- notifLevel is the CALLER's own per-channel mute preference
             -- (m.notif_level, set via chat_member_set_notif), while
             -- postPermission/broadcastPermission are channel-wide policy
             -- (V119/V122). No push filtering rides on any of these three
             -- (Global Constraints: "Push discipline... never filter [the
             -- WS relay] by notif_level" — suppression is client-side only).
             'notifLevel', m.notif_level,
             'postPermission', c.post_permission,
             'broadcastPermission', c.broadcast_permission,
             -- Pillar C1 Task 3: federated-DM marker (V139). NULL for every
             -- ordinary channel/DM/group_dm — non-NULL federatedPeerDomain
             -- is the client's ONLY signal to special-case title resolution
             -- (the roster has just the local user, chat_roster.sql) and
             -- render the persistent External badge (ExternalSenderBanner
             -- precedent — a phishing + records-jurisdiction signal).
             'federatedPeerDomain', c.federated_peer_domain,
             'federatedRemoteId', c.federated_remote_id,
             -- Pillar C2 Task 7: room-federation envelope additions.
             -- federatedRoomId non-NULL marks BOTH the hub channel and every
             -- spoke mirror of a federated room (V140) — the client's signal
             -- to render the persistent "Federated · N orgs" badge and the
             -- roster-sheet entry point on either side. isFederatedRoomHub
             -- distinguishes which shape this org holds (hub: real channel,
             -- federated_peer_domain NULL; spoke: mirror, federated_peer_
             -- domain = the bound hub) — the same "shape carries the proof"
             -- rule federation_room_create's own header documents.
             -- federatedRoomRemoved is the kicked/scope-revoked marker
             -- (Task 5's op:'remove'/'room_revoked' arms set it on a spoke)
             -- — the client's banner + composer-disable signal (enforcement
             -- stays BZ213 at send, this is honesty).
             'federatedRoomId', c.federated_room_id,
             'isFederatedRoomHub', c.federated_room_id IS NOT NULL AND c.federated_peer_domain IS NULL,
             'federatedRoomRemoved', c.federated_room_removed_at IS NOT NULL,
             -- Chat A2 Task 5: the channel's Drive space id, if one has ever
             -- been provisioned (lazy — chat_space_ensure only runs on the
             -- first attachment). NULL until then; the client uses it as the
             -- "Open in Drive" deep-link target, never a browse entry (the
             -- space itself stays hidden from /drive, DES-009 D5).
             'spaceId', (SELECT s.id FROM drive_spaces s WHERE s.chat_channel_id = c.id),
             -- pipeline review fix (webmail-adjacent projection): the meeting
             -- whose bridged chat IS this channel, if any — lets the chat
             -- rail mark meeting channels. NULL for an ordinary channel. If
             -- more than one huddle was ever launched into the same
             -- pre-existing channel, the most-recently-active (live over
             -- ended, then most recently created) meeting wins — a single,
             -- deterministic pick, never a multi-row error.
             'meetingId', (
               SELECT mt.id FROM meetings mt WHERE mt.chat_channel_id = c.id
                ORDER BY (mt.state <> 'ended') DESC, mt.created_at DESC LIMIT 1
             ),
             'hasExternalMembers', EXISTS (
               SELECT 1
                 FROM chat_channel_members gx
                WHERE gx.channel_id = c.id
                  AND EXISTS (
                    SELECT 1 FROM guest_account_status(gx.user_id) gs
                     WHERE gs.status IN ('invited','active')
                       AND (gs.expires_at IS NULL OR gs.expires_at > now()))
             ),
             -- M4: capped at 100 — a channel with thousands of unread
             -- top-level messages reports "100", not an exact count a
             -- badge has no use for.
             'unreadCount', LEAST((
               SELECT count(*)::int FROM chat_messages cm
                WHERE cm.channel_id = c.id AND cm.parent_message_id IS NULL
                  AND cm.deleted_at IS NULL
                  -- GUEST_HISTORY_FLOOR: chat_conversation_list
                  AND cm.seq > GREATEST(m.last_read_seq, COALESCE(m.history_floor_seq, 0))
                  AND (m.history_floor_seq IS NULL OR cm.created_at >= m.joined_at)
             ), 100),
             'hasMention', EXISTS (
               SELECT 1 FROM chat_mentions mn
                 JOIN chat_messages cm2 ON cm2.id = mn.message_id
                WHERE mn.mentioned_user_id = p_user_id
                  AND cm2.channel_id = c.id AND cm2.seq > m.last_read_seq
                  AND cm2.seq > COALESCE(m.history_floor_seq, 0)
                  AND (m.history_floor_seq IS NULL OR cm2.created_at >= m.joined_at)
                  AND (cm2.parent_message_id IS NULL OR EXISTS (
                        SELECT 1 FROM chat_messages parent
                         WHERE parent.id = cm2.parent_message_id
                           AND parent.seq > COALESCE(m.history_floor_seq, 0)
                           AND (m.history_floor_seq IS NULL OR parent.created_at >= m.joined_at)))
                  AND cm2.deleted_at IS NULL
             ),
             -- whole-pipeline review UX #16: msgType was missing from this
             -- projection, so a voice message (empty body) rendered as a
             -- blank preview in the conversation list — the client needs
             -- msgType to map it to a "Voice message" label the same way
             -- PinsPanel/SavedView/SearchView already do for their own
             -- snippet() helpers.
             'lastMessagePreview', (
               SELECT jsonb_build_object('authorId', lm.author_id,
                        'snippet', left(lm.body, 120), 'createdAt', lm.created_at,
                        'msgType', lm.msg_type)
                FROM chat_messages lm
                WHERE lm.channel_id = c.id AND lm.deleted_at IS NULL
                  AND lm.seq > COALESCE(m.history_floor_seq, 0)
                  AND (m.history_floor_seq IS NULL OR lm.created_at >= m.joined_at)
                  AND (lm.parent_message_id IS NULL OR EXISTS (
                        SELECT 1 FROM chat_messages parent
                         WHERE parent.id = lm.parent_message_id
                           AND parent.seq > COALESCE(m.history_floor_seq, 0)
                           AND (m.history_floor_seq IS NULL OR parent.created_at >= m.joined_at)))
                ORDER BY lm.seq DESC LIMIT 1
             ),
             -- DM/group_dm carry no name — the client resolves a title from
             -- these ids (a directory lookup, not this reducer's job).
             'memberIds', (
               SELECT jsonb_agg(cm3.user_id ORDER BY cm3.user_id)
                 FROM chat_channel_members cm3 WHERE cm3.channel_id = c.id
             )
           ) ORDER BY c.change_seq DESC), '[]'::jsonb)
    FROM chat_channels c
    JOIN chat_channel_members m ON m.channel_id = c.id AND m.user_id = p_user_id
    WHERE NOT c.is_archived;
$$ LANGUAGE sql STABLE;
