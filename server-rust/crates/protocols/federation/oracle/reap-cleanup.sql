DELETE FROM federation_inbox WHERE peer_domain='gofree-fed2-reap.test';
DELETE FROM federation_outbox WHERE peer_domain='gofree-fed2-reap.test';
DELETE FROM federation_peers WHERE peer_domain='gofree-fed2-reap.test';
DELETE FROM federation_inbox_cursor WHERE peer_domain='gofree-fed2-reap.test';
