-- V032__admin_protection.sql
-- Last-Super-Admin trigger backstops.
--
-- Two BEFORE-row triggers that act as the authoritative count-invariant guard
-- defending every code path that can remove or disable a Super Admin, including
-- direct SQL and the FK ON DELETE CASCADE on users.
--
-- trigger 1: trg_protect_last_super_admin
--   BEFORE DELETE ON admin_role_assignments.
--   Fires for every deleted row; skips non-active or non-role-1 rows.
--   Advisory lock (table-oid, key2=1) — distinct from the audit-log lock.
--   Counts DISTINCT enabled active SAs EXCLUDING OLD.id; raises BZ064 at 0.
--   Returns OLD (allow the delete when not the last SA).
--
-- trigger 2: trg_protect_last_super_admin_suspend
--   BEFORE UPDATE OF enabled ON users.
--   Fires only when OLD.enabled AND NOT NEW.enabled (disabling a user).
--   Advisory lock (same key pair).
--   If the user holds an active role-1 assignment AND the count of OTHER
--   enabled active SAs (user_id <> OLD.id) is 0 → raises BZ064.
--   Returns NEW (allow the update otherwise).
--
-- Both triggers agree with admin_protection_check (Task 2): they exclude the
-- target/OLD and raise only when the remaining usable SA count reaches zero.
-- ════════════════════════════════════════════════════════════════════════════

-- ── Trigger 1: DELETE on admin_role_assignments ──────────────────────────────

CREATE OR REPLACE FUNCTION public.protect_last_super_admin() RETURNS trigger AS $$
DECLARE
    v_remaining INT;
BEGIN
    -- Only guard active Super Admin assignments (role_group_id = 1).
    -- An expired assignment cannot be "the last SA", so skip it.
    IF OLD.role_group_id <> 1
       OR NOT (OLD.expires_at IS NULL OR OLD.expires_at > now())
    THEN
        RETURN OLD;
    END IF;

    -- Serialize concurrent deletes on this role group (key2=1, distinct from
    -- the audit-log advisory lock which uses key2=0).
    PERFORM pg_advisory_xact_lock('admin_role_assignments'::regclass::int, 1);

    -- Count remaining DISTINCT enabled active Super Admins, EXCLUDING the row
    -- being deleted (OLD.id). This agrees with admin_protection_check which
    -- excludes user_id = p_target_id.
    SELECT count(DISTINCT ara.user_id) INTO v_remaining
      FROM public.admin_role_assignments ara
      JOIN public.users u ON u.id = ara.user_id
     WHERE ara.role_group_id = 1
       AND ara.id <> OLD.id
       AND (ara.expires_at IS NULL OR ara.expires_at > now())
       AND u.enabled;

    IF v_remaining = 0 THEN
        RAISE EXCEPTION 'the last Super Admin cannot be removed'
            USING ERRCODE = 'BZ064',
                  HINT = '{"type":"admin_protection_last_super_admin"}';
    END IF;

    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_protect_last_super_admin ON public.admin_role_assignments;

CREATE TRIGGER trg_protect_last_super_admin
    BEFORE DELETE ON public.admin_role_assignments
    FOR EACH ROW EXECUTE FUNCTION public.protect_last_super_admin();


-- ── Trigger 2: UPDATE OF enabled ON users (suspend guard) ───────────────────

CREATE OR REPLACE FUNCTION public.protect_last_super_admin_suspend() RETURNS trigger AS $$
DECLARE
    v_remaining INT;
BEGIN
    -- Only fire when a user is being DISABLED (enabled: TRUE → FALSE).
    IF NOT (OLD.enabled AND NOT NEW.enabled) THEN
        RETURN NEW;
    END IF;

    -- Serialize concurrent suspensions on the same lock key as the delete
    -- trigger so the two backstops are mutually exclusive.
    PERFORM pg_advisory_xact_lock('admin_role_assignments'::regclass::int, 1);

    -- If this user holds an active Super Admin assignment AND there are no
    -- OTHER enabled active SAs (user_id <> OLD.id), block the disable.
    IF EXISTS (
        SELECT 1
          FROM public.admin_role_assignments
         WHERE user_id = OLD.id
           AND role_group_id = 1
           AND (expires_at IS NULL OR expires_at > now())
    ) THEN
        SELECT count(DISTINCT ara.user_id) INTO v_remaining
          FROM public.admin_role_assignments ara
          JOIN public.users u ON u.id = ara.user_id
         WHERE ara.role_group_id = 1
           AND ara.user_id <> OLD.id
           AND (ara.expires_at IS NULL OR ara.expires_at > now())
           AND u.enabled;

        IF v_remaining = 0 THEN
            RAISE EXCEPTION 'the last Super Admin cannot be disabled'
                USING ERRCODE = 'BZ064',
                      HINT = '{"type":"admin_protection_last_super_admin"}';
        END IF;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_protect_last_super_admin_suspend ON public.users;

CREATE TRIGGER trg_protect_last_super_admin_suspend
    BEFORE UPDATE OF enabled ON public.users
    FOR EACH ROW EXECUTE FUNCTION public.protect_last_super_admin_suspend();


-- ── Schema migration record ──────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (35, now())
  ON CONFLICT (version) DO NOTHING;
