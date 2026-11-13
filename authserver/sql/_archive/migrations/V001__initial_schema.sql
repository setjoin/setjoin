-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V001: Auth server initial schema (shared PostgreSQL cluster)
\i ../schema/001_auth_extensions.sql
\i ../schema/002_directory_connectors.sql
\i ../schema/003_passkey_credentials.sql
\i ../schema/004_push_devices.sql
\i ../schema/005_oauth_tokens.sql
\i ../schema/006_saml_sp_registrations.sql
\i ../schema/007_users_extend.sql
