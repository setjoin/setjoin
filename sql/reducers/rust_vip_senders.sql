-- Frozen Go's GET/PUT /user/vip-senders call vip_senders_list/vip_sender_set on the request
-- pool without RunUserScoped. vip_senders is FORCE-RLS on app.current_user_id, so under
-- setjoin_app Go lists nothing and every add is refused (the delete is a silent no-op). Match
-- that missing user GUC even when the Rust executor scopes its transaction; the function-local
-- SET restores the caller's GUC on return and invoker rights never bypass RLS. Do not repair
-- the Go bug during the port (ARCH-029).
CREATE OR REPLACE FUNCTION rust_vip_sender_set(
    p_user_id bigint, p_email text, p_on boolean
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET app.current_user_id = '' AS $$
BEGIN
    RETURN public.vip_sender_set(p_user_id, p_email, p_on);
END;
$$;

CREATE OR REPLACE FUNCTION rust_vip_senders_list(p_user_id bigint)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY INVOKER
SET app.current_user_id = '' AS $$
BEGIN
    RETURN public.vip_senders_list(p_user_id);
END;
$$;
