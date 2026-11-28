-- mailbox_effective_type: derive admin-display role from satellite tables.
--
-- The mailboxes.type column is now personal-only (tightened by V076). The
-- effective role for admin display is derived from the satellite tables that
-- are the single source of truth for each role:
--
--   distribution  → distribution_groups row exists for this mailbox
--   room/equipment → mailboxes.resource_type IS NOT NULL
--   shared         → user_id IS NULL AND mailbox_delegates row exists
--   personal       → everything else (has an owning user, no satellite rows)
--
-- No p_mailbox_id required: this is an admin-display helper over non-message
-- metadata, called only from RequireAdmin / RequirePerm code paths, not from
-- user-scoped JMAP handlers. This is the documented exception to R1; it does
-- not touch user message data.
--
-- This function is STABLE (no side effects, result depends only on DB state
-- for the given mailbox_id within the current transaction).

CREATE OR REPLACE FUNCTION mailbox_effective_type(
    p_mailbox_id BIGINT
) RETURNS TEXT AS $$
DECLARE
    v_mailbox RECORD;
BEGIN
    SELECT id, user_id, resource_type
      INTO v_mailbox
      FROM mailboxes
     WHERE id = p_mailbox_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Mailbox % not found', p_mailbox_id
            USING ERRCODE = 'BZ001',
                  HINT    = jsonb_build_object(
                                'type',       'not_found',
                                'mailbox_id', p_mailbox_id
                            )::TEXT;
    END IF;

    -- Precedence: distribution > resource (room/equipment) > shared > personal

    -- 1. Distribution group: satellite distribution_groups row exists
    IF EXISTS (
        SELECT 1 FROM distribution_groups WHERE mailbox_id = p_mailbox_id
    ) THEN
        RETURN 'distribution';
    END IF;

    -- 2. Resource: resource_type column is set (room or equipment)
    IF v_mailbox.resource_type IS NOT NULL THEN
        RETURN v_mailbox.resource_type;
    END IF;

    -- 3. Shared: no owning user AND at least one delegate entry
    IF v_mailbox.user_id IS NULL AND EXISTS (
        SELECT 1 FROM mailbox_delegates WHERE mailbox_id = p_mailbox_id
    ) THEN
        RETURN 'shared';
    END IF;

    -- 4. Default: personal
    RETURN 'personal';
END;
$$ LANGUAGE plpgsql STABLE;
