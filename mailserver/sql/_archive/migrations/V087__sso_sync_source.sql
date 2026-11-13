-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V087 (ARCH-004 Half A bug-fix): allow 'sso' as a users.sync_source value.
--
-- The federated-auth JIT path (authserver createJITUser) provisions SAML/OIDC
-- users with sync_source = 'sso' (documented in authserver/AGENTS.md), but the
-- users_sync_source_check CHECK only permitted ('local','ad','ldap','scim').
-- Every SSO/JIT provisioning therefore failed the constraint, so JIT user
-- creation was broken (it returned "user creation failed"). 'sso' is already an
-- accepted source value for distribution_group_members.source (V023/V026), so
-- the user-table omission was the defect.
--
-- Idempotent: the same widened CHECK ships in schema/003_users.sql so a fresh
-- load matches. Nothing reads users.sync_source = 'sso' (the AD write-back path
-- keys on 'ad'); this only widens the permitted set.

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_sync_source_check;
ALTER TABLE users ADD CONSTRAINT users_sync_source_check
  CHECK (sync_source IN ('local','ad','ldap','scim','sso'));
