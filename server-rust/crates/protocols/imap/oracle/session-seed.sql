-- Disposable gofree_e2e_imap3 only (#345). Divergent IDs 9345xxx. Alice owns the
-- messages and folders under test; Bob owns one message so a cross-mailbox leak is
-- visible; Dave and Erin carry user_imap_settings rows for LIST; Erin has a tiny quota.
INSERT INTO domains(id,name,is_local) VALUES (9345001,'imap3.test',true);
INSERT INTO users(id,username,email,display_name,domain_id,password_hash,enabled) VALUES
 (9345011,'alice','alice@imap3.test','Alice',9345001,'x',true),
 (9345012,'bob','bob@imap3.test','Bob',9345001,'x',true),
 (9345013,'dave','dave@imap3.test','Dave',9345001,'x',true),
 (9345014,'erin','erin@imap3.test','Erin',9345001,'x',true);
INSERT INTO mailboxes(id,user_id,domain_id,email,display_name,type,is_primary,enabled) VALUES
 (9345021,9345011,9345001,'alice@imap3.test','Alice','personal',true,true),
 (9345022,9345012,9345001,'bob@imap3.test','Bob','personal',true,true),
 (9345023,9345013,9345001,'dave@imap3.test','Dave','personal',true,true),
 (9345024,9345014,9345001,'erin@imap3.test','Erin','personal',true,true);
UPDATE mailboxes SET quota_bytes = 100 WHERE id = 9345024;
INSERT INTO app_passwords(user_id,name,token_hash) VALUES
 (9345011,'alice',encode(sha256('imap3-app-token-alice'::bytea),'hex')),
 (9345012,'bob',encode(sha256('imap3-app-token-bob'::bytea),'hex')),
 (9345013,'dave',encode(sha256('imap3-app-token-dave'::bytea),'hex')),
 (9345014,'erin',encode(sha256('imap3-app-token-erin'::bytea),'hex'));
UPDATE tags SET imap_uid_validity=1000 WHERE mailbox_id BETWEEN 9345021 AND 9345029;

-- Alice's folder tree. Project/Sub is a child; Orphan names a parent that sorts after it.
INSERT INTO tags(mailbox_id,name,sort_order,imap_expose,imap_uid_validity,imap_uid_next) VALUES
 (9345021,'Project',100,true,4444,3),
 (9345021,'Empty',120,true,6666,1),
 (9345021,'Dup',130,true,7777,1),
 (9345021,'Label',140,true,5555,1);
INSERT INTO tags(mailbox_id,name,sort_order,imap_expose,imap_name,imap_uid_validity,imap_uid_next) VALUES
 (9345021,'Reports',110,true,'Work',8888,1),
 (9345021,'Hidden',150,false,NULL,9999,1);
INSERT INTO tags(mailbox_id,parent_id,name,sort_order,imap_expose,imap_uid_validity,imap_uid_next)
 SELECT 9345021,id,'Sub',101,true,3333,1 FROM tags WHERE mailbox_id=9345021 AND name='Project';
INSERT INTO tags(mailbox_id,parent_id,name,sort_order,imap_expose,imap_uid_validity,imap_uid_next)
 SELECT 9345021,id,'Orphan',99,true,2222,1 FROM tags WHERE mailbox_id=9345021 AND name='Label';

-- Dave and Erin: a child folder and a settings row each.
INSERT INTO tags(mailbox_id,name,sort_order,imap_expose,imap_uid_validity,imap_uid_next) VALUES
 (9345023,'Project',100,true,4444,1),(9345024,'Project',100,true,4444,1);
INSERT INTO tags(mailbox_id,parent_id,name,sort_order,imap_expose,imap_uid_validity,imap_uid_next)
 SELECT mailbox_id,id,'Sub',101,true,3333,1 FROM tags WHERE mailbox_id IN (9345023,9345024) AND name='Project';
INSERT INTO user_imap_settings(user_id,expose_all,show_subscribed_only,folder_separator,exposed_tag_ids)
 SELECT 9345013,false,true,'.',ARRAY(SELECT id FROM tags WHERE mailbox_id=9345023 AND name IN ('Inbox','Project','Sub'));
INSERT INTO user_imap_settings(user_id,expose_all,show_subscribed_only,folder_separator,exposed_tag_ids)
 VALUES (9345014,true,true,'',ARRAY[]::bigint[]);

-- Alice's Inbox, ascending by UID with gaps (3,5,11,12 deleted,14,20).
INSERT INTO messages(id,mailbox_id,folder_id,message_id,subject,from_addr,to_addrs,cc_addrs,
  body_text,size_bytes,is_read,is_flagged,is_answered,is_draft,is_deleted,thread_id,imap_uid,raw_ref,received_at) VALUES
 (9345101,9345021,0,'<mid-3@imap3.test>','Hello','bob@example.org','["alice@imap3.test"]','[]',
  'plain greeting',1200,true,false,false,false,false,'t1',3,'imap3/1','2025-03-04 10:20:30+00'),
 (9345102,9345021,0,'<mid-5@imap3.test>','Second','carol@example.net','["a@x.org","b@y.org"]','["c@z.org"]',
  'needle in the body',2500,false,true,false,false,false,'t2',5,'imap3/2','2025-03-05 11:21:31+00'),
 (9345105,9345021,0,'<mid-11@imap3.test>','Third','nohost','[]','[]',
  'third',77,true,true,true,true,false,'t5',11,'imap3/5','2025-03-08 14:24:34+00'),
 (9345106,9345021,0,'<mid-12@imap3.test>','Deleted one','frank@example.org','["alice@imap3.test"]','[]',
  'marked deleted',900,false,false,true,false,true,'t6',12,'imap3/6','2025-03-09 15:25:35+00'),
 (9345107,9345021,0,'<mid-14@imap3.test>','Fifth','gina@example.org','["alice@imap3.test","h@x.org"]','["i@x.org"]',
  'fifth body',4096,false,false,false,true,false,'t7',14,'imap3/7','2025-03-10 16:26:36+00'),
 (9345108,9345021,0,'<mid-20@imap3.test>','Last message','hank@example.org','["alice@imap3.test"]','[]',
  'last',10,false,false,false,false,false,'t8',20,'imap3/8','2025-03-11 17:27:37+00'),
 (9345109,9345021,0,'<mid-p1@imap3.test>','Project one','pm@example.org','["alice@imap3.test"]','[]',
  'project body',100,false,false,false,false,false,'t9',1,'imap3/9','2025-03-12 08:00:00+00'),
 (9345110,9345021,0,'<mid-p2@imap3.test>','Project two','pm@example.org','["alice@imap3.test"]','[]',
  'project body two',200,true,false,false,false,true,'t10',2,'imap3/10','2025-03-13 09:00:00+00'),
 (9345111,9345022,0,'<mid-bob@imap3.test>','Bob private','zed@example.org','["bob@imap3.test"]','[]',
  'bob secret',50,false,false,false,false,false,'t11',1,'imap3/11','2025-03-14 09:00:00+00'),
 (9345112,9345024,0,'<mid-erin@imap3.test>','Erin one','zed@example.org','["erin@imap3.test"]','[]',
  'erin body',40,false,false,false,false,false,'t12',1,'imap3/12','2025-03-15 09:00:00+00');
INSERT INTO message_tags(message_id,received_at,tag_id,is_primary,imap_uid)
SELECT m.id, m.received_at, t.id, TRUE, m.imap_uid FROM messages m
  JOIN tags t ON t.mailbox_id=m.mailbox_id AND t.name='Inbox'
 WHERE m.id BETWEEN 9345101 AND 9345108 OR m.id IN (9345111, 9345112) ORDER BY m.id;
INSERT INTO message_tags(message_id,received_at,tag_id,is_primary,imap_uid)
SELECT m.id, m.received_at, t.id, TRUE, m.imap_uid FROM messages m
  JOIN tags t ON t.mailbox_id=m.mailbox_id AND t.name='Project'
 WHERE m.id IN (9345109, 9345110) ORDER BY m.id;
INSERT INTO message_tags(message_id,received_at,tag_id,is_primary,imap_uid)
SELECT m.id, m.received_at, t.id, FALSE, NULL FROM messages m
  JOIN tags t ON t.mailbox_id=m.mailbox_id AND t.name='Label'
 WHERE m.id IN (9345101, 9345107) ORDER BY m.id;
UPDATE tags SET imap_uid_validity=1111, imap_uid_next=21 WHERE mailbox_id=9345021 AND name='Inbox';
UPDATE tags SET imap_uid_validity=8888, imap_uid_next=2 WHERE mailbox_id=9345022 AND name='Inbox';
UPDATE tags SET imap_uid_validity=1212, imap_uid_next=2 WHERE mailbox_id=9345024 AND name='Inbox';
