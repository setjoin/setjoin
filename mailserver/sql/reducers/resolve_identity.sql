-- resolve_identity.sql — the address-aware identity resolution seam (ADR-004 §3,
-- docs/adr/ARCH-004-directory-org-scope.md). The reducer-layer twin of
-- authserver's connector.ResolveIdentitySQL: resolve a PERSON by ANY of their
-- addresses — `users.email` (primary) ∪ `aliases.email` (every alias on a mailbox
-- the person owns) ∪ `users.ad_upn` (AD userPrincipalName) — case-insensitive.
--
-- WHY THIS EXISTS (the bug class it closes): a setjoin deployment is exactly ONE
-- organization, and a person is one identity with a FULL address set. Mail already
-- resolves a person by their full set (the SMTP alias join); the directory was
-- converged onto it by ADR-004 Half B. The calendar reducers, however, still
-- resolved an owner/delegate/attendee by `users.email` ONLY — so a person addressed
-- by an alias on a sister domain, or by their UPN (which frequently differs from the
-- primary SMTP address), failed to resolve: a shared-calendar open returned empty, a
-- delegate-create was rejected as "delegator not found", an inbound iMIP REPLY was
-- refused as "attendee not authorized". This is the same bug class as ADR-004 Half A
-- (federated SP-mode matched the primary only and JIT-duplicated the person). Routing
-- the calendar person-lookups through this one seam fixes all of them and stops them
-- re-deriving "which person is this address?" their own (divergent) way.
--
-- RESOLUTION CONTRACT (V249 admission/backfill, med-identity-resolution-001): the
-- authoritative anchor is THE enabled users row that legitimately owns the address.
-- Returns ONE row — the single claimant (`identity_address_claim_count(...) = 1`) —
-- or ZERO rows. ZERO rows covers the unknown / disabled case AND the fail-closed
-- cases: an address claimed by 2+ enabled persons (cross-person ambiguity, which
-- admission control makes unwritable and the one-time backfill
-- `identity_address_overlap_backfill()` quarantines with an operator report) or a
-- quarantined address resolves for NO ONE — never an ORDER-BY-id pick, which would
-- silently rebind the address to whichever person sorts first. The trailing
-- ORDER BY/LIMIT is defense only: after the single-claim guarantee at most one row
-- can match.
--
-- The quarantine exclusion goes through the SECURITY DEFINER helper
-- `identity_address_quarantined(...)` (worker-owned, ARCH-018 recipe), NOT the
-- ledger table: the ledger is FORCE RLS with zero policies, so under the runtime
-- role (setjoin_app, NOBYPASSRLS) a direct `NOT EXISTS (... FROM
-- identity_address_quarantine)` probe is vacuously empty and resolution would
-- silently resume once one competing claim is removed — without any operator
-- release. The helper returns the quarantine fact identically to owner and
-- runtime connections.
-- Columns:
--   user_id          — the resolved person (users.id)
--   primary_mailbox  — that person's primary mailbox id (the calendar/ownership key;
--                      NULL only if the person has no primary mailbox, which the
--                      provisioning seam prevents). Callers needing "the owner's
--                      mailbox" use this instead of `mailboxes JOIN users ON email`.
--   domain_id        — the person's home domain (users.domain_id).
--
-- Only ENABLED users resolve (u.enabled = TRUE) — identical to the auth seam and to
-- the directory visibility rule; a disabled person is not addressable.
--
-- CO-EVOLVING TWIN of authserver/internal/connector/connector.go:ResolveIdentitySQL.
-- The matching predicate below (the WHERE: enabled ∧ email ∪ ad_upn ∪ alias, all
-- case-folded, ∧ single-claim ∧ not quarantined) MUST stay structurally identical to
-- that twin — if the two rules drift you get split-brain identity (auth resolves a
-- person the mailserver can't: silent lockout / duplicate JIT).
-- scripts/check-identity-predicate.sh enforces it (extracts + normalizes + diffs
-- both WHERE clauses; shared/identity plan, 2026-06-18). The PROJECTION is allowed
-- to differ (this reducer returns 3 columns; the Go twin returns the full Identity
-- row). A change to the matching RULE here is the documented trigger to merge the
-- union into a single resolvable_identity view.
--
CREATE OR REPLACE FUNCTION resolve_identity(
  p_address TEXT
) RETURNS TABLE(
  user_id          BIGINT,
  primary_mailbox  BIGINT,
  domain_id        BIGINT
) AS $$
  SELECT
    u.id,
    (SELECT mb.id FROM mailboxes mb
       WHERE mb.user_id = u.id AND mb.is_primary
       ORDER BY mb.id LIMIT 1),
    u.domain_id
  FROM users u
  WHERE u.enabled = TRUE
    AND p_address IS NOT NULL
    AND (
      lower(u.email) = lower(p_address)
      OR lower(u.ad_upn) = lower(p_address)
      OR EXISTS (
        SELECT 1 FROM aliases a
        JOIN mailboxes m ON m.id = a.mailbox_id
        WHERE m.user_id = u.id AND lower(a.email) = lower(p_address)
      )
    )
    AND identity_address_claim_count(lower(p_address)) = 1
    AND NOT identity_address_quarantined(lower(p_address))
  ORDER BY u.id
  LIMIT 1;
$$ LANGUAGE sql STABLE;

COMMENT ON FUNCTION resolve_identity(TEXT) IS
  'Address-aware identity seam (ADR-004 §3): resolve a person by ANY of their '
  'addresses — users.email ∪ aliases.email ∪ users.ad_upn (case-insensitive, '
  'enabled users only). V247 admission contract: fails closed (zero rows) for '
  'cross-person ambiguous or quarantined addresses — exactly one enabled '
  'claimant or nothing. Returns (user_id, primary_mailbox, domain_id). '
  'The reducer-layer twin of connector.ResolveIdentitySQL; calendar owner/delegate/'
  'attendee lookups call this instead of matching users.email only.';
