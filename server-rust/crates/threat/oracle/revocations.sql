DELETE FROM session_revocations WHERE user_id=9420011;
INSERT INTO session_revocations(user_id,scope,jti,family_id,not_before,reason,expires_at)
 VALUES (9420011,'jti','authrt-jti',NULL,now(),'authrt',now()+interval '1 hour'),
 (9420011,'family',NULL,'authrt-family',now(),'authrt',now()+interval '1 hour'),
 (9420011,'all',NULL,NULL,now()-interval '1 hour','authrt',now()+interval '1 hour');
