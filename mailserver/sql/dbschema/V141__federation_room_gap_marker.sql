-- V141__federation_room_gap_marker.sql — Pillar C2 Task 5 bug fix: the V139
-- "every row has an author" invariant (chat_messages_author_or_federated_ck:
-- author_id IS NOT NULL OR federated_sender_addr IS NOT NULL) predates the
-- V140 msg_type='system' widening and blocks the ONE thing that widening
-- exists for — federation_apply_room's op:'invite' arm inserts a LOCAL
-- federation-gap marker (Q9 coverage epochs, the re-admit gapFrom/gapTo
-- carry) that is neither authored by a local user NOR a federated sender —
-- it isn't wire content at all, just a local system record. Every such
-- insert (chat_messages_author_or_federated_ck) fails outright without this
-- fix. Relaxed to also allow msg_type = 'system' with neither column set —
-- the same widen-the-CHECK precedent V140 itself used for msg_type.
ALTER TABLE public.chat_messages DROP CONSTRAINT chat_messages_author_or_federated_ck;
ALTER TABLE public.chat_messages ADD CONSTRAINT chat_messages_author_or_federated_ck
    CHECK (author_id IS NOT NULL OR federated_sender_addr IS NOT NULL OR msg_type = 'system');

INSERT INTO public.schema_migrations (version, applied_at) VALUES (141, now())
    ON CONFLICT (version) DO NOTHING;
