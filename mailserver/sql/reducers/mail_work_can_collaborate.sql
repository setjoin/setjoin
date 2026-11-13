-- Coarse shared-mail collaboration ceiling. Action-specific authority remains
-- in each mutator; this helper never grants send or mailbox-management rights.
CREATE OR REPLACE FUNCTION mail_work_can_collaborate(
  p_mailbox_id bigint,
  p_user_id bigint
) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public AS $$
  SELECT EXISTS(
    SELECT 1 FROM mailboxes m
     WHERE m.id=p_mailbox_id AND m.user_id IS NULL
       AND (
         EXISTS(
           SELECT 1 FROM mailbox_delegates d
            WHERE d.mailbox_id=m.id AND d.user_id=p_user_id
              AND d.permission IN ('send_as','send_on_behalf','full_access')
         )
       )
  )
$$;

ALTER FUNCTION mail_work_can_collaborate(bigint,bigint) OWNER TO setjoin_worker;
