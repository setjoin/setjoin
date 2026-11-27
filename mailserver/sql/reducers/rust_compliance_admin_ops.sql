-- Wave 1.8 Phase 546d: worker-only admin helpers for compliance (F04).
-- 1. rust_compliance_content_purge: p_actor-first wrapper around
--    content_purge_messages so AdminWriteTx::execute_audited_reducer_contract
--    (SqlAuditPosture::ReducerWritesCoreAudit) binds $1 = p_actor.
-- 2. rust_compliance_content_search_kql: STABLE worker-only KQL query executor
--    (mirroring rust_compliance_search_complete) so crates/domains/compliance
--    contains zero runtime format! SQL strings.

CREATE OR REPLACE FUNCTION rust_compliance_content_purge(
    p_actor      bigint,
    p_ids        bigint[],
    p_admin_user text,
    p_reason     text
) RETURNS TABLE(deleted_count integer, held_count integer, not_found_count integer)
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NOT public.rls_caller_is_privileged() THEN
        RAISE EXCEPTION 'insufficient privilege for worker-only reducer'
            USING ERRCODE = '42501';
    END IF;
    RETURN QUERY
        SELECT c.deleted_count, c.held_count, c.not_found_count
          FROM public.content_purge_messages(p_ids, p_admin_user, p_reason, p_actor) AS c;
END;
$$;

CREATE OR REPLACE FUNCTION rust_compliance_content_search_kql(
    p_predicate text,
    p_values    text[]
) RETURNS TABLE(
    id          bigint,
    subject     text,
    from_addr   text,
    received_at text,
    email       text
)
LANGUAGE plpgsql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF NOT public.rls_caller_is_privileged() THEN
        RAISE EXCEPTION 'insufficient privilege for worker-only reducer'
            USING ERRCODE = '42501';
    END IF;
    RETURN QUERY EXECUTE
        'SELECT m.id, m.subject, m.from_addr, '
        || 'to_char(m.received_at AT TIME ZONE ''UTC'', ''YYYY-MM-DD"T"HH24:MI:SS"Z"''), '
        || 'mb.email '
        || 'FROM public.messages m JOIN public.mailboxes mb ON mb.id = m.mailbox_id '
        || 'WHERE (' || p_predicate || ') '
        || 'ORDER BY m.received_at DESC LIMIT 500'
        USING p_values;
END;
$$;

REVOKE ALL ON FUNCTION public.rust_compliance_content_purge(bigint, bigint[], text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.rust_compliance_content_search_kql(text, text[]) FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
        REVOKE EXECUTE ON FUNCTION public.rust_compliance_content_purge(bigint, bigint[], text, text) FROM setjoin_app;
        REVOKE EXECUTE ON FUNCTION public.rust_compliance_content_search_kql(text, text[]) FROM setjoin_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        GRANT EXECUTE ON FUNCTION public.rust_compliance_content_purge(bigint, bigint[], text, text) TO setjoin_worker;
        GRANT EXECUTE ON FUNCTION public.rust_compliance_content_search_kql(text, text[]) TO setjoin_worker;
    END IF;
END;
$$;
