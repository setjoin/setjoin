-- V249: One address-to-person admission and backfill contract (med-identity-
-- resolution-001, ADR-004 seam).
--
-- The resolve_identity seam resolves a person by ANY of their addresses —
-- `users.email` ∪ `users.ad_upn` ∪ `aliases.email` (owner via mailboxes.user_id),
-- case-insensitive — and is executed live by BOTH co-evolving twins
-- (mailserver/sql/reducers/resolve_identity.sql and
-- authserver/internal/connector/connector.go:ResolveIdentitySQL, guarded by
-- scripts/check-identity-predicate.sh). Before this migration the match space
-- had no cross-table exclusion: `users.ad_upn` had no unique index at all and
-- no relation prevented one address from being claimed by TWO enabled persons
-- (e.g. person A's UPN simultaneously person B's email). Both resolvers ended
-- in a bare LIMIT 1 over that ambiguous match set, so the row returned depended
-- on plan order: auth and mail could resolve DIFFERENT people for the same
-- address on the live SP-mode federated-auth path. A deterministic-looking
-- ORDER BY pick is not a fix — it silently rebinds an address from one person
-- to another.
--
-- The contract settled here (authoritative anchor: the enabled `users` row —
-- users.id — owner of the full address set per ADR-004):
--
--   1. An address is admissible to exactly ONE enabled person. Same-person
--      overlap (a UPN differing from the primary email, plus aliases on
--      mailboxes the person owns) is legitimate and resolves to that one
--      users row from every address. Cross-person overlap (one address
--      reachable from two enabled users rows through any union member) is
--      unresolved ambiguity, never a pick.
--   2. ONE-TIME BACKFILL: identity_address_overlap_backfill() enumerates
--      every existing cross-person overlap and QUARANTINES the address
--      (excluded from resolution by both twins) with an operator-visible
--      report instead of silently rebinding. The function is re-runnable and
--      must reach an EMPTY second run (admission control below stops new
--      overlaps from materializing). Quarantined rows are durable operator
--      work: disposition of identities already mis-bound by prior
--      non-deterministic resolution (quarantine-plus-notify vs rebind) is an
--      explicitly OPEN policy decision — this migration only makes the
--      address resolve for no one and records the competing owners.
--   3. ADMISSION CONTROL: BEFORE-row triggers on the three address relations
--      (users.email, users.ad_upn, aliases.email — plus mailboxes.user_id
--      reassignment, which would materialize an alias-claim silently) make a
--      NEW cross-person overlap inadmissible at write time: a duplicate
--      insert FAILS (ERRCODE BZ328) rather than resolves. The users trigger
--      validates the COMPLETE prospective address set — the row's own email
--      and UPN PLUS every live alias on a mailbox the row owns — because
--      (re-)enabling a person revives their aliases' claims without touching
--      aliases.email in the same statement (disable A, hand A's alias address
--      to B as B's UPN, re-enable A ⇒ two enabled claimants). Disabled
--      persons never block (they are not addressable) — but re-enabling into
--      an existing claim is itself refused.
--   4. FAIL-CLOSED RESOLUTION: both twins gained two predicate clauses —
--      `identity_address_claim_count(lower(ADDR)) = 1` (live ambiguity ⇒
--      zero rows, never an ORDER-BY-id pick) and a quarantine exclusion
--      (`identity_address_quarantine`). A deterministic tie-break may remain
--      downstream of the single-claim guarantee as defense only.
--
-- Isolation posture mirrors the identity substrate (V156/V158, V246): the
-- quarantine ledger is ENABLE+FORCE RLS with zero permissive policies —
-- fail-closed deny for every runtime role. Writes flow through
-- identity_address_overlap_backfill(), which the deploy ownership step hands
-- to setjoin_worker (BYPASSRLS) via apply_worker_ownership(); the one runtime
-- READ the contract needs (the twins' quarantine exclusion) flows through the
-- worker-owned SECURITY DEFINER point lookup identity_address_quarantined(),
-- so the exclusion binds under setjoin_app even though the ledger itself
-- stays invisible. Denial is proved by tests/identity_address_admission.pg.

-- ── Quarantine ledger ─────────────────────────────────────────────────────
-- One row per quarantined address. `owners` records EVERY enabled person the
-- address was reachable from at quarantine time — the operator-visible
-- evidence an operator needs to re-home or release the address (deleting the
-- row after fixing the underlying claims is the release path).
CREATE TABLE public.identity_address_quarantine (
    address         TEXT PRIMARY KEY,
    owners          BIGINT[] NOT NULL,
    reason          TEXT NOT NULL DEFAULT 'cross_person_overlap',
    quarantined_at  TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    last_report_at  TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    CONSTRAINT identity_address_quarantine_reason_check CHECK (
        reason ~ '^[a-z_]{1,64}$'
    )
);

COMMENT ON TABLE public.identity_address_quarantine IS
  'Addresses quarantined by the ADR-004 admission contract (V249): the address '
  'was claimed by 2+ enabled persons, so it resolves for NO ONE until an '
  'operator fixes the underlying claims and deletes the row. owners[] records '
  'the competing users.ids at quarantine time.';

-- ── Claim substrate ────────────────────────────────────────────────────────
-- THE one definition of "which enabled persons claim this address" (the ADR-004
-- union predicate, case-folded). The admission triggers, the backfill and both
-- resolution twins all read through this — the union must not be re-derived
-- per caller.
CREATE OR REPLACE FUNCTION public.identity_address_claims(p_address TEXT)
RETURNS TABLE (user_id BIGINT)
LANGUAGE sql STABLE
SET search_path = pg_catalog, public
AS $$
  SELECT u.id
    FROM users u
   WHERE u.enabled = TRUE
     AND (
       lower(u.email) = lower(p_address)
       OR lower(u.ad_upn) = lower(p_address)
       OR EXISTS (
         SELECT 1 FROM aliases a
         JOIN mailboxes m ON m.id = a.mailbox_id
         WHERE m.user_id = u.id AND lower(a.email) = lower(p_address)
       )
     )
$$;

COMMENT ON FUNCTION public.identity_address_claims(TEXT) IS
  'ADR-004 admission substrate (V249): the enabled users.rows claiming an '
  'address through users.email ∪ users.ad_upn ∪ aliases.email. 0 = '
  'unclaimed, 1 = the single anchor (resolution is bound to that row), '
  '2+ = cross-person ambiguity.';

CREATE OR REPLACE FUNCTION public.identity_address_claim_count(p_address TEXT)
RETURNS BIGINT
LANGUAGE sql STABLE
SET search_path = pg_catalog, public
AS $$
  SELECT count(*)::bigint FROM identity_address_claims(p_address)
$$;

COMMENT ON FUNCTION public.identity_address_claim_count(TEXT) IS
  'ADR-004 admission substrate (V249): how many enabled persons claim the '
  'address. Both resolve_identity twins require = 1 — an ambiguous address '
  'resolves to ZERO rows (fail closed) instead of an arbitrary LIMIT-1 pick.';

-- ── One-time backfill (operator-runnable report) ──────────────────────────
-- Enumerates every UNQUARANTINED cross-person overlap and quarantines it,
-- returning the report. Re-runnable: already-quarantined addresses are
-- skipped, so a healthy system reaches an EMPTY second run. SECURITY DEFINER
-- + worker ownership below: the ledger is FORCE RLS with zero policies, so
-- only this function (owned by setjoin_worker post-deploy) can write it.
CREATE OR REPLACE FUNCTION public.identity_address_overlap_backfill()
RETURNS TABLE (quarantined_address TEXT, owner_ids BIGINT[], action TEXT)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_rec    RECORD;
  v_owners BIGINT[];
BEGIN
  FOR v_rec IN
    SELECT DISTINCT cand.addr AS overlap_address
      FROM (
        SELECT lower(u.email) AS addr FROM users u
         WHERE u.enabled = TRUE
        UNION
        SELECT lower(u.ad_upn) FROM users u
         WHERE u.enabled = TRUE AND u.ad_upn IS NOT NULL
        UNION
        SELECT lower(a.email) FROM aliases a
         JOIN mailboxes m ON m.id = a.mailbox_id
         WHERE m.user_id IS NOT NULL
      ) cand
     WHERE identity_address_claim_count(cand.addr) > 1
       AND NOT EXISTS (
         SELECT 1 FROM identity_address_quarantine q
          WHERE q.address = cand.addr
       )
  LOOP
    SELECT array_agg(c.user_id ORDER BY c.user_id) INTO v_owners
      FROM identity_address_claims(v_rec.overlap_address) c;

    INSERT INTO identity_address_quarantine AS q (address, owners, reason)
      VALUES (v_rec.overlap_address, v_owners, 'cross_person_overlap')
      ON CONFLICT (address) DO UPDATE
        SET owners = EXCLUDED.owners,
            last_report_at = statement_timestamp();

    quarantined_address := v_rec.overlap_address;
    owner_ids           := v_owners;
    action              := 'quarantined';
    RETURN NEXT;
  END LOOP;
END $$;

COMMENT ON FUNCTION public.identity_address_overlap_backfill() IS
  'ADR-004 one-time backfill (V249): quarantine every cross-person address '
  'overlap with an operator-visible report (address, competing owners, '
  'action). Re-runnable; an EMPTY result proves the admission contract has '
  'reached convergence.';

-- ── Initial sweep (operator-visible report, runs in this migration) ───────
-- Runs while the ledger still has no RLS (below) and before the EXECUTE
-- privilege narrows, so any executor that can apply this migration prints the
-- report. Empty output ⇒ zero existing cross-person overlaps.
SELECT * FROM public.identity_address_overlap_backfill();

-- Ownership: the FORCE-RLS ledger is writable only through this function, and
-- only by the BYPASSRLS worker/owner connections (see V118 applicator).
SELECT apply_worker_ownership('identity_address_overlap_backfill()'::regprocedure);

-- ── Runtime-role visibility for the resolver twins ────────────────────────
-- The ledger itself stays invisible to every non-bypass role (FORCE RLS, zero
-- policies — the isolation posture above). But the resolution contract needs
-- the quarantine FACT under the runtime role: both twins exclude a quarantined
-- address from resolution, and a twin that cannot see the ledger at all makes
-- that exclusion vacuous — remove ONE competing claim and resolution would
-- silently resume without an operator release. Per the FORCE-RLS scope-helper
-- recipe (ARCH-018, same as the V246 quarantine-ledger write path): the fact
-- flows through a SECURITY DEFINER STABLE helper owned by setjoin_worker
-- (BYPASSRLS) via apply_worker_ownership(), with the search_path pinned
-- (the SECURITY DEFINER escalation foot-gun belt) and EXECUTE granted to the
-- app/owner/worker trio only. A point lookup returns only the boolean fact —
-- the app still cannot enumerate the ledger.
CREATE OR REPLACE FUNCTION public.identity_address_quarantined(p_address TEXT)
RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
  SELECT EXISTS (
    SELECT 1
      FROM public.identity_address_quarantine q
     WHERE q.address = lower(p_address)
  )
$$;

COMMENT ON FUNCTION public.identity_address_quarantined(TEXT) IS
  'ADR-004 quarantine fact (V249): is this address quarantined? SECURITY '
  'DEFINER (worker-owned, BYPASSRLS) so the resolve_identity twins'' '
  'exclusion binds for the runtime role too — the FORCE-RLS ledger itself '
  'stays invisible and unwritable to every non-bypass role.';

SELECT apply_worker_ownership('identity_address_quarantined(text)'::regprocedure);

-- ── Admission control (write-time, all three address relations) ───────────
-- BZ328: the write would give ONE address a second enabled claimant. Raised
-- BEFORE the row lands so a duplicate insert fails rather than resolves.
--
-- The users trigger validates the COMPLETE prospective address set: the row's
-- own email + UPN, plus every alias already live on a mailbox the row owns.
-- The alias arm is what makes RE-ENABLE safe: re-enabling person A revives
-- A's alias claims without touching aliases.email, so checking only
-- NEW.email/NEW.ad_upn would admit "disable A, assign A's alias address as
-- B's UPN, re-enable A" — two enabled claimants, exactly the ambiguity the
-- contract forbids. The BEFORE-row timing is load-bearing: identity_address_
-- claims() still sees the OLD (disabled) row, so the revived claim is not
-- self-counted and the competing claimant is detected.
CREATE OR REPLACE FUNCTION public.identity_address_admission_users()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_addresses TEXT[];
  v_addr      TEXT;
  v_other     BIGINT;
BEGIN
  IF NEW.enabled THEN
    SELECT array_agg(DISTINCT s.addr) INTO v_addresses
      FROM (
        SELECT lower(NEW.email) AS addr
        UNION ALL
        SELECT lower(NEW.ad_upn) WHERE NEW.ad_upn IS NOT NULL
        UNION ALL
        SELECT lower(a.email)
          FROM aliases a
          JOIN mailboxes m ON m.id = a.mailbox_id
         WHERE m.user_id = NEW.id
      ) s
     WHERE s.addr IS NOT NULL;
    FOREACH v_addr IN ARRAY v_addresses LOOP
      SELECT c.user_id INTO v_other
        FROM identity_address_claims(v_addr) c
       WHERE c.user_id <> NEW.id
       LIMIT 1;
      IF v_other IS NOT NULL THEN
        RAISE EXCEPTION 'identity address admission: % is already claimed by enabled user %',
                        v_addr, v_other
          USING ERRCODE = 'BZ328',
                HINT = '{"type":"identity_address_admission_conflict"}';
      END IF;
    END LOOP;
  END IF;
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION public.identity_address_admission_aliases()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_addr  TEXT;
  v_owner BIGINT;
  v_other BIGINT;
BEGIN
  v_addr := lower(NEW.email);
  SELECT m.user_id INTO v_owner
    FROM mailboxes m
   WHERE m.id = NEW.mailbox_id;
  IF v_owner IS NOT NULL THEN
    SELECT c.user_id INTO v_other
      FROM identity_address_claims(v_addr) c
     WHERE c.user_id <> v_owner
     LIMIT 1;
    IF v_other IS NOT NULL THEN
      RAISE EXCEPTION 'identity address admission: % is already claimed by enabled user %',
                      v_addr, v_other
        USING ERRCODE = 'BZ328',
              HINT = '{"type":"identity_address_admission_conflict"}';
    END IF;
  END IF;
  RETURN NEW;
END $$;

-- Assigning a mailbox to a person silently makes every alias on that mailbox
-- a claim of theirs — the fourth way a cross-person overlap can materialize
-- without touching users.email/ad_upn or aliases.email directly.
CREATE OR REPLACE FUNCTION public.identity_address_admission_mailboxes()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_addr TEXT;
BEGIN
  IF NEW.user_id IS NOT NULL AND NEW.user_id IS DISTINCT FROM OLD.user_id THEN
    SELECT lower(a.email) INTO v_addr
      FROM aliases a
     WHERE a.mailbox_id = NEW.id
       AND EXISTS (
         SELECT 1 FROM identity_address_claims(lower(a.email)) c
          WHERE c.user_id <> NEW.user_id
       )
     LIMIT 1;
    IF v_addr IS NOT NULL THEN
      RAISE EXCEPTION 'identity address admission: % (alias on mailbox %) is already claimed by another enabled user',
                      v_addr, NEW.id
        USING ERRCODE = 'BZ328',
              HINT = '{"type":"identity_address_admission_conflict"}';
    END IF;
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER trg_identity_address_admission_users
  BEFORE INSERT OR UPDATE ON public.users
  FOR EACH ROW EXECUTE FUNCTION public.identity_address_admission_users();

CREATE TRIGGER trg_identity_address_admission_aliases
  BEFORE INSERT OR UPDATE ON public.aliases
  FOR EACH ROW EXECUTE FUNCTION public.identity_address_admission_aliases();

CREATE TRIGGER trg_identity_address_admission_mailboxes
  BEFORE UPDATE OF user_id ON public.mailboxes
  FOR EACH ROW EXECUTE FUNCTION public.identity_address_admission_mailboxes();

-- Lookup index for the previously unindexed union member (the match space had
-- "no unique index on lower(ad_upn)"; uniqueness itself is cross-table and is
-- enforced by the admission triggers above — a plain unique index could not be
-- created over pre-contract data without failing the migration).
CREATE INDEX users_ad_upn_lower_idx
    ON public.users USING btree (lower(ad_upn))
    WHERE ad_upn IS NOT NULL;

-- ── Isolation posture (mirrors V156/V158 + V246 identity substrate) ───────
ALTER TABLE public.identity_address_quarantine ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.identity_address_quarantine FORCE ROW LEVEL SECURITY;
ALTER TABLE public.identity_address_quarantine OWNER TO setjoin_owner;

INSERT INTO public.schema_migrations (version, applied_at)
VALUES (249, now());
