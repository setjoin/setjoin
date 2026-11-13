-- #217 frozen fixture: 64 unread messages in alice@test.local's Inbox, delivered
-- through the real inbound reducer (deliver) on top of the webmail e2e seed
-- (mailserver/webmail/e2e/fixtures/seed.sql). Subjects 'BENCH 01'..'BENCH 64';
-- received_at is fixed so the set is the same on every load.
DO $$
DECLARE i INT;
BEGIN
  FOR i IN 1..64 LOOP
    PERFORM deliver(
      'bench-ref-' || i, '<bench-' || i || '@test.local>',
      'bench' || i || '@partner.test', 'Bench ' || i,
      'alice@test.local',
      '[]'::JSONB, '[]'::JSONB, '[]'::JSONB,
      'BENCH ' || lpad(i::text, 2, '0'),
      NULL, NULL,
      'Body of bench message ' || i || '.',
      NULL, 200, FALSE,
      TIMESTAMPTZ '2026-10-01 00:00:00+00' + (i || ' minutes')::INTERVAL,
      'pass', 'pass', 'pass', 0.0, NULL);
  END LOOP;
END $$;
