-- Isolated disposable gofree_e2e_fed1 only. Restores the federation oracle's world.
DELETE FROM chat_messages WHERE federated_origin_domain IS NOT NULL;
DELETE FROM chat_channel_members WHERE channel_id IN (SELECT id FROM chat_channels WHERE federated_peer_domain IS NOT NULL OR federated_room_id IS NOT NULL);
DELETE FROM chat_channels WHERE federated_peer_domain IS NOT NULL OR federated_room_id IS NOT NULL;
DELETE FROM federation_room_members;
DELETE FROM federation_rooms;
DELETE FROM federation_outbox;
DELETE FROM federation_peers;
DELETE FROM federation_inbox;
DELETE FROM federation_inbox_cursor;
DELETE FROM federation_ingress_counters;
DELETE FROM federation_allowlist;
DELETE FROM mailboxes WHERE id=9346021;
DELETE FROM users WHERE id=9346011;
DELETE FROM domains WHERE id=9346001;
