-- chat_effective_retention.sql — Chat A4a Task 4: retention resolution.
--
-- Resolution order: per-channel override beats org policy; a kind-specific
-- org policy (applies_to matching chat_channels.kind) beats the 'all' org
-- policy; the shortest duration_days wins within a tier (deterministic,
-- most-conservative); disabled policies are ignored; a policy is inert until
-- now() >= effective_at (the 7-day undo window, V126 §G). NULL = never purge.
--
-- Used by the purge sweep ONLY for 'regular' channels (gate 2, Task 6) — a
-- gxp channel's retention_days is a WORM floor, never a destroy ceiling, and
-- the sweep never selects it. The admin console still calls this for gxp
-- channels to display the ORG policy that WOULD have applied; it must render
-- that under the floor label, not the ceiling label (V126 vocabulary block).
CREATE OR REPLACE FUNCTION chat_effective_retention(p_channel_id BIGINT)
RETURNS INTEGER LANGUAGE sql STABLE AS $$
  SELECT COALESCE(
    (SELECT retention_days FROM chat_channels WHERE id = p_channel_id),
    (SELECT MIN(p.duration_days) FROM chat_retention_policies p
      WHERE p.enabled AND p.effective_at <= now()
        AND p.applies_to = (SELECT kind FROM chat_channels WHERE id = p_channel_id)),
    (SELECT MIN(p.duration_days) FROM chat_retention_policies p
      WHERE p.enabled AND p.effective_at <= now() AND p.applies_to = 'all'))
$$;
