DELETE FROM oauth_tokens WHERE user_id=9420011;
DELETE FROM oidc_tokens WHERE user_id=9420011;
DELETE FROM oidc_clients WHERE id='authrt';
DELETE FROM users WHERE id=9420011;
DELETE FROM domains WHERE id=9420001;
