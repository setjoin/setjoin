-- V093__approval_requests_domain_id.sql — TODOS.md "approval_requests.domain_id"
-- follow-up (post approval-engine T1–T14, spec §11).
--
-- Today an admin with approvals.view/approvals.manage can see EVERY domain's
-- approval requests (GET /admin/approval-requests/audit) — the RLS policy on
-- approval_requests keys on app.current_user_id (a single user), not a domain,
-- so a domain-scoped admin gets no domain isolation at all (over-disclosure,
-- not under — hence why this was safe to defer past the initial ship).
--
-- domain_id is nullable: populated by the consumer at create time
-- (approval_request_create derives it from the requester's users.domain_id
-- when the caller doesn't pass an explicit override; group_moderation_hold has
-- no requester — an external sender — so it passes the target group's
-- mailbox's domain_id explicitly). Existing/historical rows stay NULL; a
-- domain-scoped admin simply won't see those (same conservative
-- over-disclosure-safe direction the deferral note called out).
ALTER TABLE public.approval_requests
  ADD COLUMN domain_id BIGINT REFERENCES public.domains(id);

-- Domain-scoped admin audit reads filter `WHERE domain_id = $N` (see
-- admin_approvals.go ListAudit, mirroring admin_users.go's domain scoping) —
-- index it the same way other domain-filtered admin lists do.
CREATE INDEX approval_requests_domain_idx ON public.approval_requests (domain_id);

INSERT INTO public.schema_migrations (version, applied_at) VALUES (93, now())
  ON CONFLICT (version) DO NOTHING;
