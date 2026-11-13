-- Disposable gofree_e2e_smtp5 only. Fixed IDs 9501xxx. Every user's password is
-- 'IMAP1-correct-password!' (bcrypt cost 10, shared with the IMAP oracle).
INSERT INTO domains(id,name,is_local) VALUES (9501001,'smtp5.test',true);
INSERT INTO users(id,username,email,display_name,domain_id,password_hash,enabled) VALUES
 (9501011,'alice','alice@smtp5.test','Alice A',9501001,'$2a$10$7Jkhas3r3pTm3PrWmRVz0eOLVkDWrwuKgh3gPBeGtYTDyYcdXM3T6',true),
 (9501012,'bob','bob@smtp5.test','Bob B',9501001,'$2a$10$7Jkhas3r3pTm3PrWmRVz0eOLVkDWrwuKgh3gPBeGtYTDyYcdXM3T6',true),
 (9501013,'guest','guest@smtp5.test','Guest',9501001,'$2a$10$7Jkhas3r3pTm3PrWmRVz0eOLVkDWrwuKgh3gPBeGtYTDyYcdXM3T6',true),
 (9501014,'off','off@smtp5.test','Off',9501001,'$2a$10$7Jkhas3r3pTm3PrWmRVz0eOLVkDWrwuKgh3gPBeGtYTDyYcdXM3T6',false),
 (9501015,'nomb','nomb@smtp5.test','No Mailbox',9501001,'$2a$10$7Jkhas3r3pTm3PrWmRVz0eOLVkDWrwuKgh3gPBeGtYTDyYcdXM3T6',true);
INSERT INTO mailboxes(id,user_id,domain_id,email,display_name,type,is_primary,enabled) VALUES
 (9501021,9501011,9501001,'alice@smtp5.test','Alice A','personal',true,true),
 (9501022,9501012,9501001,'bob@smtp5.test','Bob B','personal',true,true),
 (9501023,9501013,9501001,'guest@smtp5.test','Guest','personal',true,true);
INSERT INTO aliases(mailbox_id,domain_id,email) VALUES (9501021,9501001,'alias@smtp5.test');
INSERT INTO guest_accounts(user_id,invited_email,invited_by_email,host_domain_id,status)
 VALUES (9501013,'guest@smtp5.test','alice@smtp5.test',9501001,'active');
INSERT INTO app_passwords(user_id,name,token_hash,expires_at,revoked_at) VALUES
 (9501011,'valid',encode(sha256('smtp5-app-token-valid'::bytea),'hex'),NULL,NULL),
 (9501011,'revoked',encode(sha256('smtp5-app-token-revoked'::bytea),'hex'),NULL,now());
