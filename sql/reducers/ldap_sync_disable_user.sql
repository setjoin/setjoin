-- ldap_sync_disable_user — atomic, reducer-fenced deprovisioning for the
-- legacy LDAP sync engine (med-ldapsync-identity-001, Astra waves12 HOLD
-- items 1 and 3).
--
-- HOLD item 3: the engine previously committed users.enabled = FALSE in one
-- autocommit and deleted sessions/ws_subscriptions in two more, so a failure
-- between steps left a disabled account with live sessions while the next
-- absence sweep skipped it (enabled = FALSE). The whole mutation — state
-- flip, durable OAuth anchors, both runtime session stores, the gateway
-- denylist row, the audit entry, and the session_revoke notify — is now ONE
-- transaction through revoke_user_sessions(...,'all',...), the repo's single
-- revocation boundary ("callers must not reimplement only part of that
-- boundary"). There is no committed intermediate state left for a later
-- failure to strand.
--
-- HOLD item 1: authorization is re-decided HERE, transactionally, from the
-- authority inputs — never from the engine's earlier reads:
--   anchor authority  — an active 'legacy:ldap' link on an active source with
--                       the 'provision' purpose names this user; or
--   family authority  — users.sync_source = 'ldap' (the account this engine
--                       family provisioned) AND no OTHER identity source
--                       holds lifecycle authority over the account.
-- Anything else raises BZ233 (identity_lifecycle_conflict): a native account,
-- an account owned by another source, a guest, or an unknown id is never
-- disableable by this engine. p_expected_generation pins the catalog
-- generation for anchor-path callers (BZ229 on drift); state is always
-- re-checked under FOR SHARE inside this transaction.
--
-- Idempotent: an already-disabled, fence-passing user still has its
-- revocation effects (re)asserted in the same transaction and reports
-- alreadyDisabled so callers do not double-count a disable.
CREATE OR REPLACE FUNCTION ldap_sync_disable_user(
    p_user_id BIGINT,
    p_reason TEXT,
    p_expected_generation BIGINT DEFAULT NULL
) RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_user   users%ROWTYPE;
    v_source identity_sources%ROWTYPE;
    v_anchored BOOLEAN;
    v_other_owned BOOLEAN;
    v_already BOOLEAN;
    v_reason TEXT;
    v_source_found BOOLEAN;
BEGIN
    IF p_user_id IS NULL OR p_user_id <= 0 THEN
        RAISE EXCEPTION 'ldap disable requires a user id'
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid","field":"userId"}';
    END IF;
    v_reason := COALESCE(NULLIF(btrim(p_reason), ''),
                         'ldap_sync_disable');

    SELECT * INTO v_user
      FROM users
     WHERE id = p_user_id
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'ldap disable target % does not exist', p_user_id
            USING ERRCODE = 'BZ228',
                  HINT = '{"type":"identity_source_invalid","field":"userId"}';
    END IF;

    IF is_guest_account(p_user_id) THEN
        RAISE EXCEPTION 'account class is excluded from ldap lifecycle authority'
            USING ERRCODE = 'BZ239',
                  HINT = '{"type":"identity_account_class_excluded"}';
    END IF;

    SELECT * INTO v_source
      FROM identity_sources
     WHERE source_key = 'legacy:ldap'
       FOR SHARE;
    v_source_found := FOUND;

    v_already := NOT v_user.enabled;

    IF FOUND THEN
        IF p_expected_generation IS NOT NULL
           AND v_source.generation <> p_expected_generation THEN
            RAISE EXCEPTION 'ldap disable generation is stale'
                USING ERRCODE = 'BZ229',
                      HINT = jsonb_build_object(
                          'type', 'identity_generation_stale',
                          'expectedGeneration', p_expected_generation,
                          'actualGeneration', v_source.generation)::TEXT;
        END IF;

        v_anchored := v_source.state = 'active' AND EXISTS (
            SELECT 1
              FROM user_identity_links l
             WHERE l.source_id = v_source.id
               AND l.user_id = p_user_id
               AND l.state = 'active'
               AND 'provision' = ANY (l.purposes));
    END IF;

    IF NOT v_anchored THEN
        IF v_user.sync_source IS DISTINCT FROM 'ldap' THEN
            RAISE EXCEPTION 'ldap sync does not hold lifecycle authority over this account'
                USING ERRCODE = 'BZ233',
                      HINT = jsonb_build_object(
                          'type', 'identity_lifecycle_conflict',
                          'accountSyncSource', v_user.sync_source)::TEXT;
        END IF;

        SELECT EXISTS (
            SELECT 1
              FROM user_lifecycle_authorities a
              JOIN user_identity_links l2 ON l2.id = a.link_id
              JOIN identity_sources s2 ON s2.id = l2.source_id
             WHERE a.user_id = p_user_id
               AND a.authority_kind = 'source'
               AND s2.source_key <> 'legacy:ldap'
        ) INTO v_other_owned;
        IF v_other_owned THEN
            RAISE EXCEPTION 'another identity source holds lifecycle authority over this account'
                USING ERRCODE = 'BZ233',
                      HINT = '{"type":"identity_lifecycle_conflict"}';
        END IF;
    END IF;

    PERFORM pg_advisory_xact_lock(
        hashtextextended('identity-person:' || p_user_id::text, 0));

    -- One transaction: state flip + complete revocation boundary (oauth
    -- tokens, ws subscriptions, sessions, denylist row, audit, notify).
    UPDATE users SET enabled = FALSE WHERE id = p_user_id AND enabled;
    PERFORM revoke_user_sessions(p_user_id, 'all', v_reason, NULL, NULL, NULL);

    RETURN jsonb_build_object(
        'disabled', true,
        'alreadyDisabled', v_already,
        'userId', p_user_id,
        'anchorAuthority', COALESCE(v_anchored, false),
        'sourceGeneration', CASE WHEN v_source_found
                                 THEN v_source.generation END);
END;
$$;

SELECT apply_worker_ownership(
    'ldap_sync_disable_user(bigint,text,bigint)'::regprocedure
);
