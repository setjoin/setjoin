-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V027: OIDC client_type — distinguish confidential (secret-based) from public (PKCE-only) clients.
-- Public clients: AuthMethodNone, ApplicationTypeNative, PKCE S256 required.
-- Confidential clients (default): AuthMethodBasic, ApplicationTypeWeb.
ALTER TABLE oidc_clients
  ADD COLUMN IF NOT EXISTS client_type TEXT NOT NULL DEFAULT 'confidential';
