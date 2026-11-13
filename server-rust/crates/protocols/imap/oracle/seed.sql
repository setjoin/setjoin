-- Disposable gofree_e2e_imap1 only. Fixed divergent IDs 9343xxx; the recorder
-- and the Rust replay load this file and then oracle/password-hashes.json.
INSERT INTO domains(id,name,is_local) VALUES (9343001,'imap1.test',true);
INSERT INTO users(id,username,email,display_name,domain_id,password_hash,enabled) VALUES
 (9343011,'alice','alice@imap1.test','Alice',9343001,'x',true),
 (9343012,'bob','bob@imap1.test','Bob',9343001,'x',true),
 (9343013,'carol','carol@imap1.test','Carol',9343001,'x',true),
 (9343014,'dave','dave@imap1.test','Dave',9343001,'x',true),
 (9343015,'erin','erin@imap1.test','Erin',9343001,'x',true),
 (9343016,'gina','gina@imap1.test','Gina',9343001,'x',true),
 (9343017,'hank','hank@imap1.test','Hank',9343001,'x',true),
 (9343018,'ivan','ivan@imap1.test','Ivan',9343001,'x',false),
 (9343019,'jack','jack@imap1.test','Jack',9343001,'x',true);
INSERT INTO mailboxes(id,user_id,domain_id,email,display_name,type,is_primary,enabled) VALUES
 (9343021,9343011,9343001,'alice@imap1.test','Alice','personal',true,true),
 (9343022,9343012,9343001,'bob@imap1.test','Bob','personal',true,true),
 (9343023,9343013,9343001,'carol@imap1.test','Carol','personal',true,false),
 (9343026,9343016,9343001,'gina@imap1.test','Gina','personal',true,true),
 (9343027,9343017,9343001,'hank@imap1.test','Hank','personal',true,true),
 (9343028,9343018,9343001,'ivan@imap1.test','Ivan','personal',true,true),
 (9343029,9343019,9343001,'jack@imap1.test','Jack','personal',true,true);
INSERT INTO user_imap_settings(user_id,imap_enabled) VALUES (9343012,false);
INSERT INTO guest_accounts(user_id,invited_email,invited_by_email,host_domain_id,status)
 VALUES (9343014,'dave@imap1.test','alice@imap1.test',9343001,'active');
-- Default system tags come from the mailbox trigger; pin the ones SELECT reads.
UPDATE tags SET imap_uid_validity=1000 WHERE mailbox_id BETWEEN 9343021 AND 9343029;
UPDATE tags SET imap_uid_validity=1111, imap_uid_next=7, total_count=3, unread_count=1
 WHERE mailbox_id=9343021 AND name='Inbox';
UPDATE tags SET imap_uid_validity=2222, imap_uid_next=1, total_count=0, unread_count=0
 WHERE mailbox_id=9343021 AND name='Sent';
UPDATE tags SET imap_uid_validity=3333, imap_uid_next=9, total_count=0, unread_count=0
 WHERE mailbox_id=9343021 AND name='Trash';
INSERT INTO tags(mailbox_id,name,imap_expose,imap_uid_validity,imap_uid_next,total_count,unread_count) VALUES
 (9343021,'Project',true,4444,12,5,2),
 (9343021,'Gap',true,5555,0,0,0),
 (9343021,'Hidden',false,6666,3,0,0),
 (9343021,'Zero',true,0,5,0,0),
 (9343026,'GinaPrivate',true,7777,2,1,1),
 (9343022,'BobBox',true,8888,2,0,0);
INSERT INTO app_passwords(user_id,name,token_hash,expires_at,revoked_at) VALUES
 (9343011,'valid',encode(sha256('imap1-app-token-valid'::bytea),'hex'),NULL,NULL),
 (9343011,'revoked',encode(sha256('imap1-app-token-revoked'::bytea),'hex'),NULL,now()),
 (9343011,'expired',encode(sha256('imap1-app-token-expired'::bytea),'hex'),now()-interval '1 day',NULL),
 (9343012,'bob',encode(sha256('imap1-app-token-bob'::bytea),'hex'),NULL,NULL),
 (9343018,'ivan',encode(sha256('imap1-app-token-ivan'::bytea),'hex'),NULL,NULL);
