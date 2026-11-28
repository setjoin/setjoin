INSERT INTO blobs(sha256,minio_ref,size_bytes) VALUES('ldap1-fixture-avatar','ldap1-fixture-avatar',1),('ldap1-fixture-contact','ldap1-fixture-contact',1);
INSERT INTO departments(id,name,path,ldap_ou) VALUES(9342051,'Engineering','engineering','Engineering');
UPDATE users SET department_id=9342051,first_name='Robert',last_name='Builder',phone='+123',job_title='Engineer',avatar_sha256='ldap1-fixture-avatar' WHERE id=9342012;
INSERT INTO mailboxes(id,domain_id,email,display_name,type,resource_type) VALUES
 (9342031,9342001,'team@ldap1.test','Team','personal',NULL),
 (9342032,9342001,'room@ldap1.test','Room','personal','room');
INSERT INTO distribution_groups(id,mailbox_id) VALUES(9342041,9342031);
INSERT INTO addressbooks(id,mailbox_id,name,is_shared) VALUES(9342042,9342021,'Shared',true),(9342043,9342021,'Private',false);
INSERT INTO contacts(id,addressbook_id,vcard_uid,display_name,first_name,last_name,company,job_title,department,avatar_sha256) VALUES
 (9342044,9342042,'ldap1-contact','External','Ex','Ternal','Example Inc','Contact','Vendor','ldap1-fixture-contact'),
 (9342045,9342043,'ldap1-private-contact','Private','Private','Contact',NULL,NULL,NULL,NULL);
