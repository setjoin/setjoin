-- scheduled_actions_admin.sql: admin observability over the deferred-action queue
-- — "why didn't my scheduled mail send". failed_scheduled_actions() returns the
-- terminal-failed actions (most recent first), the published contract intended for
-- / awaiting the admin "failed scheduled actions" route. NOTE: that route does not
-- exist yet — admin_queue.go serves the OUTBOUND queue (Summary/List/ForceRetry/
-- Bounce), not the scheduled-action queue — so this reducer currently has no Go
-- caller (only scheduled_actions_retry.pg). It is kept as the spec'd seam
-- (specs/2026-06-16-scheduled-actions-design.md §"failed scheduled actions" view)
-- so the handler lands against a stable contract rather than re-deriving the shape.
--
-- Admin-scoped: this is a cross-mailbox operational read, gated by the Go
-- RequireAdmin / RequirePerm middleware at the route layer (same model as
-- mailbox_effective_type()). It takes no p_mailbox_id — it deliberately spans all
-- mailboxes for operators. It never mutates and exposes no message bodies, only
-- the action's own metadata.
CREATE OR REPLACE FUNCTION failed_scheduled_actions(p_limit INT DEFAULT 100)
RETURNS TABLE(action JSONB) AS $$
    SELECT jsonb_build_object(
        'id', sa.id::TEXT,
        'actionKind', sa.action_kind,
        'mailboxId', sa.mailbox_id,
        'attempts', sa.attempts,
        'fireAt', sa.fire_at,
        'lastError', sa.last_error,
        'updatedAt', sa.updated_at
    )
    FROM scheduled_actions sa
    WHERE sa.status = 'failed'
    ORDER BY sa.updated_at DESC
    LIMIT LEAST(GREATEST(p_limit, 1), 1000);
$$ LANGUAGE sql STABLE;
