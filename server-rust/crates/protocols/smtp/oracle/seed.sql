-- SMTP is a cross-tenant transport; recipient identity comes from the envelope
-- resolved by the worker credential, never a fabricated authenticated user.
INSERT INTO domains(id,name,is_local) VALUES (9348001,'smtp1.test',true),(9348002,'smtp1-other.test',true),(9348003,'smtp1-catch.test',true);
INSERT INTO users(id,username,email,display_name,domain_id,password_hash,enabled) VALUES
 (9348011,'alice','alice@smtp1.test','Alice',9348001,'x',true),
 (9348012,'bob','bob@smtp1-other.test','Bob',9348002,'x',true),
 (9348013,'closed','closed@smtp1.test','Closed',9348001,'x',true);
INSERT INTO mailboxes(id,user_id,domain_id,email,display_name,type,is_primary,enabled) VALUES
 (9348021,9348011,9348001,'alice@smtp1.test','Alice','personal',true,true),
 (9348022,9348012,9348002,'bob@smtp1-other.test','Bob','personal',true,true),
 (9348023,9348013,9348001,'closed@smtp1.test','Closed','personal',true,true);
INSERT INTO aliases(mailbox_id,domain_id,email) VALUES (9348021,9348001,'alias@smtp1.test');
UPDATE domains SET catch_all_mailbox_id=9348021 WHERE id=9348003;
