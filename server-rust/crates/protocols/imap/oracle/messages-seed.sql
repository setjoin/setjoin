-- Disposable gofree_e2e_imap2 only (#344). Divergent IDs 9344xxx. Alice owns the
-- messages under test; Bob owns one message so a cross-mailbox leak is visible.
INSERT INTO domains(id,name,is_local) VALUES (9344001,'imap2.test',true);
INSERT INTO users(id,username,email,display_name,domain_id,password_hash,enabled) VALUES
 (9344011,'alice','alice@imap2.test','Alice',9344001,'x',true),
 (9344012,'bob','bob@imap2.test','Bob',9344001,'x',true);
INSERT INTO mailboxes(id,user_id,domain_id,email,display_name,type,is_primary,enabled) VALUES
 (9344021,9344011,9344001,'alice@imap2.test','Alice','personal',true,true),
 (9344022,9344012,9344001,'bob@imap2.test','Bob','personal',true,true);
INSERT INTO app_passwords(user_id,name,token_hash) VALUES
 (9344011,'alice',encode(sha256('imap2-app-token-alice'::bytea),'hex')),
 (9344012,'bob',encode(sha256('imap2-app-token-bob'::bytea),'hex'));
UPDATE tags SET imap_uid_validity=1000 WHERE mailbox_id BETWEEN 9344021 AND 9344029;
INSERT INTO tags(mailbox_id,name,imap_expose,imap_uid_validity,imap_uid_next) VALUES
 (9344021,'Project',true,4444,1),
 (9344021,'Label',true,5555,1);

-- Alice's Inbox, ascending by UID with gaps (3,5,11,12,14,20). The NULL-column rows
-- frozen Go cannot scan are added by the null-columns session's sql actions.
INSERT INTO messages(id,mailbox_id,folder_id,message_id,subject,from_addr,to_addrs,cc_addrs,
  body_text,size_bytes,is_read,is_flagged,is_answered,is_draft,is_deleted,thread_id,imap_uid,raw_ref,received_at) VALUES
 (9344101,9344021,0,'<mid-3@imap2.test>','Hello','bob@example.org','["alice@imap2.test"]','[]',
  'plain greeting',1200,true,false,false,false,false,'t1',3,'blob/1','2025-03-04 10:20:30+00'),
 (9344102,9344021,0,'<mid-5@imap2.test>','Quote "me" \ slash','carol@example.net','["a@x.org","b@y.org"]','["c@z.org"]',
  'needle in the body',2500,false,true,false,false,false,'t2',5,'blob/2','2025-03-05 11:21:31+00'),
 (9344105,9344021,0,'<mid-11@imap2.test>','','nohost','[]','[]',
  'empty subject, no host, no recipients',77,true,true,true,true,false,'t5',11,'blob/5','2025-03-08 14:24:34+00'),
 (9344106,9344021,0,'<mid-12@imap2.test>','Deleted one','frank@example.org','["alice@imap2.test"]','[]',
  'marked deleted',900,false,false,true,false,true,'t6',12,'blob/6','2025-03-09 15:25:35+00'),
 (9344107,9344021,0,'<mid-14@imap2.test>','Subject Needle UPPER','gina@example.org','["alice@imap2.test","h@x.org"]','["i@x.org","j@x.org"]',
  'body with 50% off_and more',4096,false,false,false,true,false,'t7',14,'blob/7','2025-03-10 16:26:36+00'),
 (9344108,9344021,0,'<mid-20@imap2.test>','Last message','hank@example.org','["alice@imap2.test"]','[]',
  'last',10,false,false,false,false,false,'t8',20,'blob/8','2025-03-11 17:27:37+00'),
 -- Project tag members (primary there) and one message only in Project.
 (9344109,9344021,0,'<mid-p1@imap2.test>','Project one','pm@example.org','["alice@imap2.test"]','[]',
  'project body',100,false,false,false,false,false,'t9',1,'blob/9','2025-03-12 08:00:00+00'),
 (9344110,9344021,0,'<mid-p2@imap2.test>','Project two','pm@example.org','["alice@imap2.test"]','[]',
  'project body two',200,true,false,false,false,false,'t10',2,'blob/10','2025-03-13 09:00:00+00'),
 (9344111,9344022,0,'<mid-bob@imap2.test>','Bob private','zed@example.org','["bob@imap2.test"]','[]',
  'bob secret',50,false,false,false,false,false,'t11',1,'blob/11','2025-03-14 09:00:00+00');
INSERT INTO message_tags(message_id,received_at,tag_id,is_primary,imap_uid)
SELECT m.id, m.received_at, t.id, TRUE, m.imap_uid FROM messages m
  JOIN tags t ON t.mailbox_id=m.mailbox_id AND t.name='Inbox'
 WHERE m.id BETWEEN 9344101 AND 9344108 OR m.id=9344111;
INSERT INTO message_tags(message_id,received_at,tag_id,is_primary,imap_uid)
SELECT m.id, m.received_at, t.id, TRUE, m.imap_uid FROM messages m
  JOIN tags t ON t.mailbox_id=m.mailbox_id AND t.name='Project'
 WHERE m.id IN (9344109, 9344110);
-- Secondary (non-primary) membership: a keyword for SEARCH KEYWORD, invisible to FETCH.
INSERT INTO message_tags(message_id,received_at,tag_id,is_primary,imap_uid)
SELECT m.id, m.received_at, t.id, FALSE, NULL FROM messages m
  JOIN tags t ON t.mailbox_id=m.mailbox_id AND t.name='Label'
 WHERE m.id IN (9344101, 9344107);
UPDATE tags SET imap_uid_validity=1111, imap_uid_next=21 WHERE mailbox_id=9344021 AND name='Inbox';
UPDATE tags SET imap_uid_validity=4444, imap_uid_next=3 WHERE mailbox_id=9344021 AND name='Project';
UPDATE tags SET imap_uid_validity=8888, imap_uid_next=2 WHERE mailbox_id=9344022 AND name='Inbox';
