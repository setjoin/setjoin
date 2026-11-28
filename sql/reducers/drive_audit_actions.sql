-- mailserver/sql/reducers/drive_audit_actions.sql
-- Single source of truth for the closed §9.3 audit event catalog (the 37-action
-- set previously triplicated: this file, a Go copy in audit.go, and a TS copy
-- in AdminAuditPanel.svelte — Tasks 7/8 delete those copies). drive_access_audit's
-- own inline ARRAY[...] validation is refactored below to read from here instead
-- of carrying a second copy. Invoker-rights, STABLE: no table access, no RLS
-- concern, just a constant.
CREATE OR REPLACE FUNCTION drive_audit_actions() RETURNS JSONB
LANGUAGE sql STABLE AS $$
  -- The MEET Drive-History emitter (drive_meet_history_emit.sql): the three
  -- frozen lifecycle points meet contributes into Drive's §9.3 chain through
  -- THIS Drive-owned ingest — meet never appends directly.
  SELECT '[
    "space.create","classification.change","policy.change","quota.change",
    "member.grant","member.revoke","share.requested","share.approved","share.denied",
    "node.create","node.rename","node.move","node.trash","node.restore","node.destroy",
    "version.create","view","preview",
    "export.request","export.approve","export.deny","export.download","export.print",
    "branch.create","branch.rename","branch.review","branch.merge","branch.discard",
    "label.set","label.remove","lock.acquire","lock.release","lock.break",
    "folderadmin.grant","folderadmin.revoke","trash.adminRestore","alarm.fire",
    "acl.grant","acl.revoke","acl.expire","acl.inheritance.break",
    "acl.inheritance.resume","acl.emergency.grant","acl.emergency.revoke",
    "acl.request","acl.approve","acl.deny","acl.lease.consume",
    "office.launch","office.revoke","office.lock","office.unlock",
    "office.save","office.save.reject","office.cohort.finish","office.provider.policy",
	"office.local_open","office.provider.remove",
    "meet.recording.stopped","meet.annotation.committed","meet.presentation.pinned"
  ]'::jsonb;
$$;
