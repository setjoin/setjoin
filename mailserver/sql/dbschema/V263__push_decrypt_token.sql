-- ════════════════════════════════════════════════════════════════════════
-- V263__push_decrypt_token.sql — per-token exception isolation for push
-- device resolution (debt plan D-6, Astra r1 amendment).
--
-- FINDING. shared/push.ResolveDevices documents "a single undecryptable token
-- must not sink the whole send", but resolved the token with pgp_sym_decrypt
-- inline in the result set's target list. PostgreSQL raises the decrypt
-- failure ("Wrong key or corrupt data", SQLSTATE 39000) while producing the
-- row, which marks the whole pgx result set broken: one wrong-key row (a
-- stale key-rotation leftover) errored the ENTIRE resolve, and for a
-- transaction caller the raised error also poisoned the surrounding
-- transaction. The documented skip contract existed only in the Go-side
-- fake-rows unit test.
--
-- FIX. push_decrypt_token(p_token_enc) moves the decrypt into a PL/pgSQL
-- function whose EXCEPTION handler isolates EXACTLY the undecryptable-token
-- outcome (SQLSTATE '39000', the pgcrypto external-routine-exception class
-- "Wrong key or corrupt data" — verified empirically) and reports it as NULL
-- for the reader to skip and aggregate-log. The PL/pgSQL EXCEPTION block runs
-- as an internal subtransaction, so the error never escapes the statement:
-- the resolve returns N-1 good tokens, and a transaction caller's
-- transaction stays usable afterward. Everything else propagates unchanged —
-- a missing app.encryption_key GUC (SQLSTATE 42704, configuration error),
-- real query errors and cancellation still fail the resolve loudly; the
-- function adds no table access, so push_devices' RLS/ownership posture is
-- untouched (the reader keeps its user_id + revoked_at filtering; the
-- function only sees the single BYTEA value the row already yielded).
--
-- EMPTY-KEY GUARD (Astra r2, D-6). pgcrypto raises the SAME SQLSTATE 39000
-- for an EMPTY configured key ("Illegal argument to function") as it does for
-- a wrong-key/corrupt-ciphertext token — so a blanket 39000 handler silently
-- turned the configuration error into "zero devices, no error", and pushjobs
-- marked the dispatch intent done as if the user had no devices. The key is
-- therefore read and validated in an OUTER block that carries NO EXCEPTION
-- clause: an empty (or missing) app.encryption_key raises configuration
-- error 42704 BEFORE the EXCEPTION-scoped decrypt can swallow it, while the
-- inner block still isolates exactly the per-token undecryptable outcome.
--
-- VOLATILITY. Deliberately left at the default VOLATILE (pgp_sym_decrypt's
-- own marking): the reader wants guaranteed per-row evaluation, and a STABLE
-- declaration around a volatile builtin would be an author claim the planner
-- could exploit in ways this read path never needs.
--
-- No reader SQL changes shape beyond calling this helper (same table, same
-- WHERE). Token and key material never reach logs — the Go reader logs only
-- the skipped-row count (aggregate, no contents).
-- ════════════════════════════════════════════════════════════════════════

CREATE OR REPLACE FUNCTION public.push_decrypt_token(p_token_enc BYTEA)
RETURNS TEXT
LANGUAGE plpgsql
AS $func$
DECLARE
    v_key TEXT;
BEGIN
    -- Configuration validation OUTSIDE the protected block: the key is read
    -- and checked here, in a block with NO EXCEPTION clause, so neither the
    -- missing-GUC error (42704 from current_setting) nor the explicit
    -- empty-key raise below can ever be converted into a NULL skip. pgcrypto
    -- fails an empty key with the same SQLSTATE 39000 as a wrong-key token —
    -- raising here, before the EXCEPTION-scoped decrypt, keeps a keyless
    -- configuration LOUD instead of silently resolving zero devices.
    v_key := current_setting('app.encryption_key');
    IF v_key IS NULL OR v_key = '' THEN
        RAISE EXCEPTION
            'push_decrypt_token: app.encryption_key is not configured (empty) — token decryption refuses to fail silent'
            USING ERRCODE = '42704',
                  HINT = 'Set app.encryption_key on every pool connection (AfterConnect); an empty key is a configuration error, not an undecryptable token.';
    END IF;

    -- Per-token isolation: ONLY the undecryptable-token outcome (SQLSTATE
    -- 39000 with a nonempty configured key) becomes NULL; everything else —
    -- connection loss, cancellation, statement timeouts — propagates.
    BEGIN
        RETURN pgp_sym_decrypt(p_token_enc, v_key);
    EXCEPTION
        WHEN SQLSTATE '39000' THEN
            -- Wrong key or corrupt data (pgcrypto, ERRCODE external-routine-
            -- exception): exactly the "single undecryptable token" outcome the
            -- reader's skip contract covers. Report NULL; every other failure
            -- re-raises.
            RETURN NULL;
    END;
END;
$func$;

COMMENT ON FUNCTION public.push_decrypt_token(BYTEA) IS
  'V263 (D-6): decrypt one push_devices token under app.encryption_key, '
  'isolating the undecryptable-token failure (SQLSTATE 39000) as NULL so a '
  'single bad row can neither sink the resolve nor poison a caller''s '
  'transaction. An empty app.encryption_key is validated OUTSIDE the '
  'protected block and raises configuration error 42704 — pgcrypto would '
  'otherwise raise the same 39000 for it and the configuration error would '
  'be silently reported as "no devices". All other errors propagate.';

-- ── Schema migration record ──────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (263, now())
    ON CONFLICT (version) DO NOTHING;
