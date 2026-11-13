-- Isolated disposable gofree_e2e_ldap1 only. Fixed divergent user/mailbox IDs.
INSERT INTO domains(id,name,is_local) VALUES(9342001,'ldap1.test',true),(9342002,'ldap1-foreign.test',true);
INSERT INTO users(id,username,email,display_name,domain_id,password_hash) VALUES
 (9342011,'alice','alice@ldap1.test','Alice',9342001,'x'),
 (9342012,'bob','bob@ldap1.test','Bob',9342001,'x'),
 (9342013,'hidden','hidden@ldap1.test','Hidden',9342001,'x'),
 (9342014,'foreign','foreign@ldap1-foreign.test','Foreign',9342002,'x');
INSERT INTO mailboxes(id,user_id,domain_id,email,display_name,type,is_primary,hidden_from_gal) VALUES
 (9342021,9342011,9342001,'alice@ldap1.test','Alice','personal',true,false),
 (9342022,9342012,9342001,'bob@ldap1.test','Bob','personal',true,false),
 (9342023,9342013,9342001,'hidden@ldap1.test','Hidden','personal',true,true),
 (9342024,9342014,9342002,'foreign@ldap1-foreign.test','Foreign','personal',true,false);
INSERT INTO aliases(mailbox_id,domain_id,email) VALUES(9342022,9342001,'bob-alias@ldap1.test');
UPDATE users SET ad_upn='bob-upn@identity.test' WHERE id=9342012;
