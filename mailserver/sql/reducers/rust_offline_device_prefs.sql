-- Frozen Go's PUT /user/offline/sync-preferences calls offline_device_set_preferences through
-- CallScoped, which sets only app.current_mailbox_id. user_devices is FORCE-RLS on
-- app.current_user_id for writes, so under setjoin_app Go's UPDATE finds no row and the
-- reducer raises BZ100. Match that missing user GUC even when the Rust executor scopes its
-- transaction; the function-local SET restores the caller's GUC on return and invoker rights
-- never bypass RLS. Do not repair the Go bug during the port (ARCH-029).
CREATE OR REPLACE FUNCTION rust_offline_device_set_preferences(
    p_mailbox_id bigint, p_device_id bigint, p_opt_in boolean, p_window_days int,
    p_background boolean, p_network text, p_prefetch text
) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET app.current_user_id = '' AS $$
BEGIN
    PERFORM public.offline_device_set_preferences(p_mailbox_id, p_device_id, p_opt_in,
        p_window_days, p_background, p_network, p_prefetch);
END;
$$;
