INSERT INTO domains(id,name,is_local) VALUES(9420001,'authrt.test',true);
INSERT INTO users(id,username,email,display_name,domain_id,password_hash,enabled)
 VALUES(9420011,'alice','alice@authrt.test','Alice',9420001,'x',true);
INSERT INTO oauth_tokens(user_id,token_hash,token_type,rotated_at,expires_at) VALUES
 (9420011,decode('420001','hex'),'refresh',now()-interval '2 minutes',now()+interval '1 hour'),
 (9420011,decode('420002','hex'),'refresh',now()-interval '10 seconds',now()+interval '1 hour'),
 (9420011,decode('420003','hex'),'refresh',NULL,now()-interval '1 hour');
INSERT INTO oidc_clients(id,name,secret,redirect_uris) VALUES('authrt','authrt','unused','{}');
INSERT INTO oidc_tokens(id,client_id,user_id,subject,scopes,expires_at,refresh_expires_at,revoked_at) VALUES
 ('authrt-expired','authrt',9420011,'alice','{}',now()-interval '6 minutes',NULL,NULL),
 ('authrt-live-refresh','authrt',9420011,'alice','{}',now()-interval '6 minutes',now()+interval '1 hour',NULL),
 ('authrt-recent-revoke','authrt',9420011,'alice','{}',now()-interval '6 minutes',NULL,now()),
 ('authrt-old-revoke','authrt',9420011,'alice','{}',now()-interval '6 minutes',NULL,now()-interval '6 minutes'),
 ('authrt-live-access','authrt',9420011,'alice','{}',now()+interval '1 hour',NULL,NULL);
