-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V009: First-party token signing keystore (`signing_keys`)  — ADR-005
--
-- DB-backed, encrypted keystore for the asymmetric (ES256 / P-256) keys that
-- sign first-party authserver tokens. The KeySet module
-- (authserver/internal/token/keyset.go) generate-loads from this table on boot:
-- if no `active` key exists it mints a P-256 keypair, encrypts the PKCS#8-DER
-- private key with the cryptokey seam (AES-256-GCM column envelope), and INSERTs
-- it as 'active'. The public keys (active + retiring) are published by `kid` in
-- the first-party JWKS the mailserver gateway verifies against — no shared
-- secret. Rotation: insert a new 'active', mark the old 'retiring'; after one
-- access-token lifetime the old key goes 'retired' (dropped from the JWKS).
--
-- This is a server-internal table with no per-user rows, so RLS is not enabled
-- (matching every other authserver auth table — none use RLS; access is gated by
-- the server's DB role, not row-level policies).
-- TRIAGE CORRECTION (D-AUTHSERVER-SQL--ARCHIVE-008, 2026-09): the universal
-- claim above is STALE and must not be propagated — the live schema's V060
-- (devices) and V064 (auth_attempts) DO enable FORCE RLS, so "none use RLS"
-- no longer holds. The per-table reasoning for signing_keys itself remains
-- valid (server-internal, no per-user rows). Any new authserver user-data
-- table still needs its own R4 isolation posture; decide per table, never by
-- citing this archived blanket statement.

CREATE TABLE IF NOT EXISTS signing_keys (
    id              BIGSERIAL   PRIMARY KEY,
    kid             TEXT        NOT NULL UNIQUE,
    alg             TEXT        NOT NULL,                 -- 'ES256' (or 'SM2' on the SMx profile)
    public_jwk      JSONB       NOT NULL,                 -- public key as a JWK (never the private half)
    private_key_enc BYTEA       NOT NULL,                 -- PKCS#8-DER private key, AES-256-GCM column envelope
    status          TEXT        NOT NULL
        CHECK (status IN ('active', 'retiring', 'retired')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at      TIMESTAMPTZ
);

-- At most ONE active signing key at a time (the current signer). A partial
-- unique index makes the invariant a DB constraint: a second INSERT/UPDATE that
-- would produce two 'active' rows fails with 23505, so generate-on-first-boot is
-- race-safe (the losing instance re-SELECTs the winner) and rotation is a
-- transaction. 'retiring'/'retired' rows are unconstrained and coexist freely.
CREATE UNIQUE INDEX IF NOT EXISTS signing_keys_one_active_idx
    ON signing_keys (status)
    WHERE status = 'active';

-- Status lookup index (the JWKS / load path selects active+retiring keys).
CREATE INDEX IF NOT EXISTS signing_keys_status_idx ON signing_keys (status);
