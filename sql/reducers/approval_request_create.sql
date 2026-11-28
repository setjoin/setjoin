-- approval_request_create: shared INSERT path for all approval consumers.
-- Inserts the request row, writes a core audit entry, fires app_notify.
-- Caller (consumer wrapper) calls approval_resolve_approver first, then passes
-- the resolved (approver_kind, approver_ref) here.
-- ponytail: mail-consumer approver email enqueued in Task 11 (approve-by-email)
--
-- p_domain_id (V093, TODOS.md "approval_requests.domain_id"): DEFAULT NULL so
-- every existing 8-arg call site (send.sql, admin_role_activate.sql) needs no
-- change — domain_id auto-derives from the requester's users.domain_id. Callers
-- with NO requester (group_moderation_hold: the sender is external) pass an
-- explicit override, since there is no users row to derive it from.
CREATE OR REPLACE FUNCTION approval_request_create(
  p_consumer_type text,
  p_requester     bigint,
  p_subject       text,
  p_payload       jsonb,
  p_policy_id     bigint,
  p_approver_kind text,
  p_approver_ref  bigint,
  p_ttl_minutes   int,
  p_domain_id     bigint DEFAULT NULL
) RETURNS bigint AS $$
DECLARE
  v_id        bigint;
  v_domain_id bigint;
BEGIN
  v_domain_id := COALESCE(p_domain_id, (SELECT domain_id FROM users WHERE id = p_requester));

  INSERT INTO approval_requests(
    consumer_type, requester_user_id, subject, payload,
    policy_id, approver_kind, approver_ref, expires_at, domain_id
  ) VALUES (
    p_consumer_type, p_requester, p_subject, p_payload,
    p_policy_id, p_approver_kind, p_approver_ref,
    now() + (p_ttl_minutes || ' minutes')::interval, v_domain_id
  ) RETURNING id INTO v_id;

  PERFORM audit_write(
    p_requester,
    'approval_created',
    'approval_request',
    v_id,
    NULL,
    jsonb_build_object('consumer_type', p_consumer_type, 'subject', p_subject),
    NULL,
    NULL,
    'core'
  );

  PERFORM app_notify('approval_created',
    json_build_object('request_id', v_id, 'consumer_type', p_consumer_type)::text);

  RETURN v_id;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY INVOKER;
