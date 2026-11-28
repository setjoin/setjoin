CREATE OR REPLACE FUNCTION mail_recovery_has_global_permission(p_actor_user_id bigint)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT EXISTS(
        SELECT 1
          FROM admin_role_assignments ra
          JOIN admin_role_groups rg ON rg.id=ra.role_group_id
         WHERE ra.user_id=p_actor_user_id
           AND 'system.recovery'=ANY(rg.permissions)
           AND (ra.expires_at IS NULL OR ra.expires_at>statement_timestamp())
           AND admin_assignment_active(ra.eligible,ra.activated_until)
           AND ra.scope_type IS NULL
           AND COALESCE(ra.domain_override,rg.domain_scope) IS NULL
    )
$$;
SELECT apply_worker_ownership('mail_recovery_has_global_permission(bigint)'::regprocedure);

CREATE OR REPLACE FUNCTION mail_recovery_user_can_upload(
    p_user_id bigint,
    p_mailbox_id bigint
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT EXISTS(
        SELECT 1
	  FROM account_scope(p_mailbox_id) scope
	  JOIN mailboxes mb ON mb.id=scope.mailbox_id
	  JOIN users owner_user ON owner_user.id=scope.user_id
	 WHERE mb.enabled
	   AND owner_user.enabled
	   AND NOT is_guest_account(scope.user_id)
           AND (
               scope.user_id=p_user_id OR EXISTS(
                   SELECT 1 FROM mailbox_delegates delegate
                    WHERE delegate.mailbox_id=scope.mailbox_id
                      AND delegate.user_id=p_user_id
                      AND delegate.permission='full_access'
               )
           )
    )
$$;
SELECT apply_worker_ownership('mail_recovery_user_can_upload(bigint,bigint)'::regprocedure);

CREATE OR REPLACE FUNCTION mail_recovery_feature_enabled()
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT COALESCE((SELECT enabled FROM feature_toggles
                      WHERE key='feature.client_recovery_ingest'),false)
$$;
SELECT apply_worker_ownership('mail_recovery_feature_enabled()'::regprocedure);
