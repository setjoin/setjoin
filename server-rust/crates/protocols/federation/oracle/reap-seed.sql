DELETE FROM federation_inbox WHERE peer_domain='gofree-fed2-reap.test';
DELETE FROM federation_outbox WHERE peer_domain='gofree-fed2-reap.test';
INSERT INTO federation_peers(peer_domain) VALUES ('gofree-fed2-reap.test') ON CONFLICT DO NOTHING;
INSERT INTO federation_inbox_cursor(peer_domain,last_applied_seq) VALUES ('gofree-fed2-reap.test',2) ON CONFLICT(peer_domain) DO UPDATE SET last_applied_seq=2;
INSERT INTO federation_inbox(peer_domain,peer_seq,stanza_id,content_type,payload,applied_at)
SELECT 'gofree-fed2-reap.test',n,'in-'||n,'application/test','{}',now()- CASE WHEN n=1 THEN interval '8 days' ELSE interval '1 day' END FROM generate_series(1,2)n;
INSERT INTO federation_outbox(peer_domain,peer_seq,stanza_id,content_type,payload,acked_at)
SELECT 'gofree-fed2-reap.test',n,'out-'||n,'application/test','{}',CASE WHEN n=1 THEN now()-interval '8 days' WHEN n=2 THEN now()-interval '1 day' END FROM generate_series(1,3)n;
