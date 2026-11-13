-- journal_op / journal_resync: the single deep write entry point the A4 datatype
-- triggers delegate to. Before this, all 7 per-datatype journal triggers (task,
-- addressbook, contact, calendar, calendar_event — across V095-V098) re-implemented
-- the SAME inner block verbatim: the TG_OP→op mapping, the bump_entity_state +
-- append_change pairing, the parent-join NULL-guard, and the load-bearing best-effort
-- `EXCEPTION WHEN insufficient_privilege` catch (the F5 RLS-flip fix — a cross-mailbox
-- or no-mailbox-GUC write on the FORCE'd app pool raises 42501, which must SKIP the
-- delta rather than break the mutation; SECURITY DEFINER can't help because
-- setjoin_owner is NOBYPASSRLS). Concentrating it here gives that behavior ONE home
-- (and one testable seam — see journal_op.pg, which drives it under setjoin_app) instead
-- of a canonical copy + three "see the note in V097" comment pointers that rot apart.
-- Each trigger now keeps only its genuinely-unique part: pick NEW/OLD, resolve the
-- mailbox (direct column vs parent-table join), and call journal_op.

-- journal_op: journal one created/updated/destroyed row for an entity mutation.
-- p_tg_op is the trigger's TG_OP ('INSERT'/'UPDATE'/'DELETE'). p_collection_id /
-- p_resource_uid carry the CalDAV/CardDAV per-collection delta (calendar_id+uid /
-- addressbook_id+vcard_uid) for the two collection datatypes; NULL for the rest.
-- A NULL p_mailbox_id (a parent-join that found nothing under a cascade) is a no-op.
CREATE OR REPLACE FUNCTION journal_op(
  p_mailbox_id    BIGINT,
  p_datatype      TEXT,
  p_entity_id     BIGINT,
  p_tg_op         TEXT,
  p_collection_id BIGINT DEFAULT NULL,
  p_resource_uid  TEXT   DEFAULT NULL
) RETURNS VOID AS $$
DECLARE
  v_op TEXT := CASE p_tg_op
                 WHEN 'DELETE' THEN 'destroyed'
                 WHEN 'INSERT' THEN 'created'
                 ELSE 'updated'
               END;
BEGIN
  IF p_mailbox_id IS NULL THEN
    RETURN;  -- parent-table join found nothing (cascade) — nothing to journal
  END IF;
  PERFORM append_change(p_mailbox_id, p_datatype,
                        bump_entity_state(p_mailbox_id, p_datatype),
                        p_entity_id, v_op, p_collection_id, p_resource_uid);
EXCEPTION WHEN insufficient_privilege THEN
  -- best-effort under FORCE RLS (F5): cross-mailbox / no-GUC write on the app pool
  -- can't write the mailbox-scoped journal — skip the delta, don't break the mutation.
  NULL;
END;
$$ LANGUAGE plpgsql;

-- journal_resync: append the coarse/bulk resync sentinel (entity_id=0) for a datatype,
-- best-effort. Used by the calendar-delete trigger (its cascaded events can't be named)
-- and the coarse-path reducers (ICS import overwrite, subscription-refresh full replace)
-- so a client syncing across them degrades to BZ011 (full resync) instead of dropping
-- changes. Same best-effort catch as journal_op.
CREATE OR REPLACE FUNCTION journal_resync(
  p_mailbox_id BIGINT,
  p_datatype   TEXT
) RETURNS VOID AS $$
BEGIN
  IF p_mailbox_id IS NULL THEN
    RETURN;
  END IF;
  PERFORM append_change(p_mailbox_id, p_datatype,
                        bump_entity_state(p_mailbox_id, p_datatype), NULL, 'resync');
EXCEPTION WHEN insufficient_privilege THEN
  NULL;
END;
$$ LANGUAGE plpgsql;
