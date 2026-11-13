-- mailbox_delegate_grant.sql — grant a mailbox delegate (the §2.2 gap of
-- retired-docs:superpowers/specs/2026-06-27-sharing-delegation-design.md; D1/D8).
-- Populates the existing mailbox_delegates table that send.sql already
-- enforces; UNTOGGLED (D11 — pure additive wiring, no behavior change to any
-- current flow).
--
-- SECURITY (R1–R3): p_actor_user_id is ALWAYS claims.UserID from auth context,
-- never req.*. Ownership rides in the INSERT's own WHERE (INSERT..SELECT), so
-- a non-owner mutation matches zero rows; the loud BZ114 is picked afterward —
-- 404-indistinguishable from a missing mailbox.
--
-- Errors: BZ114 (not owner / grantee not found — notFound family, HINT type
-- disambiguates) · BZ115 (invalid permission level).
CREATE OR REPLACE FUNCTION mailbox_delegate_grant(
  p_actor_user_id BIGINT,
  p_mailbox_id    BIGINT,
  p_grantee_email TEXT,
  p_permission    TEXT
) RETURNS VOID AS $$
DECLARE
  v_grantee_uid BIGINT;
BEGIN
  -- Permission must be one of the existing mailbox_delegates levels (D1: the
  -- table's CHECK set is THE model; no new enum).
  IF p_permission IS NULL
     OR p_permission NOT IN ('read','send_as','send_on_behalf','full_access','manage_calendar') THEN
    RAISE EXCEPTION 'Invalid delegate permission level'
      USING ERRCODE = 'BZ115',
            HINT = jsonb_build_object('type','sharing_invalid_permission',
                                      'permission', COALESCE(p_permission,''))::TEXT;
  END IF;

  -- Grantee resolved address-aware (primary ∪ alias ∪ UPN) through the one
  -- seam (ADR-004), never a hand-join.
  SELECT user_id INTO v_grantee_uid FROM resolve_identity(p_grantee_email);
  IF v_grantee_uid IS NULL THEN
    RAISE EXCEPTION 'Grantee not found'
      USING ERRCODE = 'BZ114',
            HINT = jsonb_build_object('type','sharing_grantee_not_found')::TEXT;
  END IF;

  -- R3: ownership in the same statement as the mutation (no TOCTOU).
  -- ON CONFLICT DO NOTHING → idempotent re-grant (FOUND=false, no audit).
  INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by)
  SELECT p_mailbox_id, v_grantee_uid, p_permission, p_actor_user_id
  WHERE EXISTS (SELECT 1 FROM mailboxes
                 WHERE id = p_mailbox_id AND user_id = p_actor_user_id)
  ON CONFLICT (mailbox_id, user_id, permission) DO NOTHING;

  IF NOT FOUND THEN
    IF NOT EXISTS (SELECT 1 FROM mailboxes
                    WHERE id = p_mailbox_id AND user_id = p_actor_user_id) THEN
      RAISE EXCEPTION 'Mailbox not found'
        USING ERRCODE = 'BZ114',
              HINT = jsonb_build_object('type','sharing_not_owner',
                                        'mailbox_id', p_mailbox_id)::TEXT;
    END IF;
    RETURN;  -- owner re-granting an existing row: idempotent no-op
  END IF;

  -- D8: one immutable audit row per grant, tier core.
  PERFORM audit_write(
    p_actor_user_id, 'mailbox_delegate_granted', 'mailbox_delegate', p_mailbox_id,
    NULL,
    jsonb_build_object('mailbox_id', p_mailbox_id,
                       'grantee_user_id', v_grantee_uid,
                       'permission', p_permission),
    NULL, NULL, 'core');
END;
$$ LANGUAGE plpgsql;
