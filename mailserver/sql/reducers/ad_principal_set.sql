-- ad_principal_set.sql — the single sanctioned writer of users.krb5_principal.
--
-- SetPrincipal (POST /admin/ad/principal) is the ONLY intentional krb5_principal
-- change path: the Go always-local-only floor (ldaputil.alwaysLocalOnlyFields)
-- fences the directory-sync UPDATE writer and provision_account's existing-user
-- UPDATE branch excludes the column, so no sync/provisioning path can rewrite
-- the Kerberos/SPNEGO SSO identity of an existing account. This reducer owns the
-- committing security decision end to end in ONE transaction:
--
--   target row lock (FOR UPDATE) -> LIVE authority re-check INSIDE the lock ->
--   value-conditional UPDATE (compare-and-swap on the caller-observed principal)
--   -> audit_write old->new -> app_notify
--
-- Round-3 Astra correction: the previous gateway implementation evaluated
-- admin_can_reach BEFORE opening its transaction, then mutated under only ID +
-- old-principal value equality, so a revocation that committed while the
-- transaction waited on the user-row lock still permitted the change. Value
-- equality alone does not satisfy R3 — authorization must be LIVE at mutation
-- time. The authority re-check is therefore evaluated only after the lock is
-- held, against the assignment state current when the row is won. The gateway's
-- pre-check is fast-path UX only and never authorizes anything.
--
-- Round-4 Astra correction: the post-lock re-check used admin_can_reach alone,
-- which tests REACH but not PERMISSION. The route middleware (requireIdentityWrite)
-- reads JWT claims, so a live revocation of identity.write did not stop an actor
-- whose surviving directory.read assignment still reached the target: the in-lock
-- re-check passed and the SSO identity change went through. The re-check is now
-- admin_can_manage_with_permission(..., 'identity.write') — the same primitive
-- admin_reset_password uses — which requires ONE CURRENT assignment (expires_at
-- unexpired AND admin_assignment_active) that simultaneously carries
-- identity.write AND domain/OU reach to the target, with zero fail-open. Reach
-- from one assignment plus identity.write from another is NOT sufficient; both
-- axes must come from the same persisted assignment.
--
-- Error codes:
--   BZ040: NULL/blank new principal (defensive backstop; the gateway 400s first).
--   BZ060: target user not found.
--   BZ061: no CURRENT assignment granting BOTH identity.write AND reach to the
--          target — covers missing permission, out-of-scope target, and
--          revoked-while-waiting-on-the-row-lock.
--
-- Clock note: the re-check reads the assignment state committed as of the
-- statement snapshot taken after the lock is won (READ COMMITTED). Authority
-- expressed as a row delete or an eligibility/flag flip is always observed.
-- An expiry stamped at exactly the revocation-commit instant can still read as
-- future to this transaction, whose now() is frozen at its own earlier start —
-- the same now() semantics every post-lock admin re-check (e.g.
-- admin_reset_password) shares; the sanctioned revocation paths therefore
-- express revocation structurally (delete / eligible=false / past expiry).
--
-- Returns 'applied' or 'stale'. 'stale' is the compare-and-swap miss: the
-- caller's observed principal is no longer current under the lock, so NOTHING is
-- written, audited, or notified (no overwrite — R3); the gateway maps it to 409.
CREATE OR REPLACE FUNCTION ad_principal_set(
    p_actor_id       BIGINT,
    p_target_user_id BIGINT,
    p_new_principal  TEXT,
    p_old_principal  TEXT,
    p_ip             INET
) RETURNS TEXT
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_current_principal TEXT;
BEGIN
    IF p_actor_id IS NULL OR p_target_user_id IS NULL
       OR p_new_principal IS NULL OR btrim(p_new_principal) = '' THEN
        RAISE EXCEPTION 'ad principal change: invalid arguments'
            USING ERRCODE = 'BZ040',
                  HINT = '{"type":"ad_principal_invalid_arguments"}';
    END IF;

    -- Lock the target user row first; every decision below is made against the
    -- locked state, so no concurrent change can slip between observation and
    -- mutation.
    SELECT krb5_principal
      INTO v_current_principal
      FROM users
     WHERE id = p_target_user_id
     FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'ad principal change: target user not found'
            USING ERRCODE = 'BZ060',
                  HINT = '{"type":"ad_principal_target_not_found"}';
    END IF;

    -- LIVE authority AT MUTATION TIME. A revocation that committed while this
    -- transaction waited on the row lock is observed HERE, inside the lock.
    -- Requires identity.write AND target reach from ONE current assignment;
    -- the stale JWT claim cannot satisfy this — only live rows can.
    IF NOT admin_can_manage_with_permission(
                p_actor_id, p_target_user_id, 'identity.write'
            ) THEN
        RAISE EXCEPTION 'ad principal change: no current assignment granting identity.write over the target'
            USING ERRCODE = 'BZ061',
                  HINT = '{"type":"ad_principal_target_out_of_scope"}';
    END IF;

    -- Value-conditional UPDATE (R3): the caller-observed old principal must
    -- still be current. The WHERE carries the observation, so a stale view
    -- mechanically matches zero rows instead of overwriting.
    UPDATE users
       SET krb5_principal = p_new_principal,
           updated_at     = now()
     WHERE id = p_target_user_id
       AND krb5_principal IS NOT DISTINCT FROM p_old_principal;

    IF NOT FOUND THEN
        RETURN 'stale';
    END IF;

    -- Audit old->new and the notify fire in the SAME transaction as the write:
    -- an audit row exists for every committed change and none for a rolled-back
    -- one. app_notify is the single pg_notify choke point (capture-testable).
    PERFORM audit_write(
        p_actor_id, 'ad_krb5_principal_change', 'user', p_target_user_id,
        jsonb_build_object('krb5_principal', v_current_principal),
        jsonb_build_object('krb5_principal', p_new_principal),
        p_ip, NULL, 'core'
    );

    PERFORM app_notify('admin:alert', jsonb_build_object(
        'kind',          'ad_krb5_principal_change',
        'user_id',       p_target_user_id,
        'actor_id',      p_actor_id,
        'old_principal', v_current_principal,
        'new_principal', p_new_principal,
        'at',            now()
    )::text);

    RETURN 'applied';
END;
$$;

SELECT apply_worker_ownership(
    'ad_principal_set(bigint,bigint,text,text,inet)'::regprocedure
);
