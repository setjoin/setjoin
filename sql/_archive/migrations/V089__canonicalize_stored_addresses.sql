-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.
-- V089 — ONE-TIME backfill of pre-canonical stored identity addresses.
--
-- ⚠️ SUNSET / RE-RUN GATE (2026-06-18, AD/LDAP-writer-canonical wave — plan
-- docs/superpowers/plans/archive/2026-06-18-ad-writer-canonical-retire-fold-twin.md):
-- The WRITER is now Go-canonical. Every address writer (AD create + UPDATE, LDAP
-- create + UPDATE, admin create, admin CSV) routes through
-- shared/identity.CanonicalizeAddress at the seam — enforced at COMPILE TIME by
-- the identity.CanonicalAddress newtype (a raw u.Email/u.UPN/operator string
-- fails to compile at the write boundary). So new rows are canonical by
-- construction; this migration only ever has to fold the FINITE set of legacy
-- pre-wave rows. It is a one-time backfill, NOT the thing that makes the input
-- canonicalizer safe (the writer does that now).
--
-- DO NOT re-run this migration after CanonicalizeAddress evolves: a restore-
-- replay would fold the stored rows with the OLD rule while live writes use the
-- NEW rule — a split-brain. fold_stored_address() is finally DELETED once a prod
-- audit confirms every stored row is already canonical (x = fold_stored_address(x)).
--
-- ── Original rationale (preserved) ───────────────────────────────────────────
-- The Go-side INPUT canonicalizer (shared/identity.CanonicalizeAddress: trim +
-- ASCII-fold lower + RFC-5322 display-name strip) is only provably behavior-
-- preserving once the STORED rows are already canonical. Uniqueness on
-- users/aliases is `lower(email)` (users_email_lower_idx / aliases_email_lower_idx),
-- NOT a column constraint, so the columns MAY hold untrimmed or mixed-case
-- values that the lower() index never caught. This migration canonicalizes the
-- stored values so the input canonicalizer cannot start match-MISSING a row whose
-- raw column form differed from its canonical input form.
--
-- Canonicalizes: users.email, aliases.email, users.ad_upn.
--
-- ── The stored fold is NOT the full input canonicalizer ──────────────────────
-- The Go input canonicalizer does THREE things: trim + ASCII-A-Z fold + an
-- RFC-5322 display-name strip. The display-name strip is INPUT-only: a SAML
-- NameID can arrive as `"Name" <a@b>` and must be reduced to `a@b` for matching.
-- STORED values never carry a display-name wrapper:
--   · users.email / aliases.email are V054 ASCII-CHECK'd bare addresses, and
--   · users.ad_upn is a raw UPN / Kerberos principal from AD sync (e.g.
--     `host/server.corp@REALM`, `alice@corp.local`) — NOT an RFC-5322 mailbox.
-- Applying the display-name strip to a stored value is therefore DATA LOSS, not
-- canonicalization: a blind `<...>` extract turns `host/server.corp@REALM <x@y>`
-- into `x@y` (Kerberos principal discarded) and `alice@corp.local <weird>` into
-- `weird` (UPN destroyed) — silent and irreversible on ad_upn (no CHECK, no
-- unique index), and the BZ089 collision guard would never even fire.
--
-- So the canonical form for a STORED value is EXACTLY the casing/whitespace half
-- of the Go canonicalizer: trim + ASCII-A-Z fold (A–Z → a–z ONLY), nothing else.
-- It uses translate(), NOT lower(): lower() folds non-ASCII runes (İ→i, the
-- Turkish dotted-I hazard) and would then DISAGREE with Go's asciiFoldLower
-- (A–Z only), re-introducing the exact match-miss this migration exists to
-- prevent. `İstanbul@corp.com` must stay `İstanbul@corp.com` (only the ASCII
-- tail folds). Unicode/IDN normalization is DEFERRED (CONTEXT.md identity-
-- resolution boundary; shared/identity.CanonicalizeAddress is the future seam).
--
-- This stored fold is published as a permanent IMMUTABLE function,
-- fold_stored_address(text), so it is the TESTED named twin of the Go casing/
-- whitespace fold (the display-strip-free half of CanonicalizeAddress). The
-- Go cross-check shared/identity.TestFoldStoredAddress_MatchesGo (DB-gated)
-- feeds a no-display-name corpus to BOTH halves and asserts byte-equality, so
-- the twin cannot silently drift.
--
-- COLLISION SAFETY (the load-bearing rule): two distinct stored rows that
-- canonicalize to the SAME value are a real data-quality finding — NEVER silently
-- merged or dropped. The migration ABORTS (RAISE EXCEPTION) and reports the
-- offending rows so an operator resolves them by hand before re-running.
--
-- IDEMPOTENT: on an already-canonical DB (test DB audit = 0) every UPDATE matches
-- zero rows and no collision can exist, so it is a no-op. Safe to re-run.
--
-- This is a DEPLOY-GATE: run the stored-row audit against PROD before deploy; if
-- nonzero, this migration is what makes the input canonicalizer safe there. The
-- audit must flag any row where x <> fold_stored_address(x):
--
--   SELECT 'users.email' AS col, id, email AS raw, fold_stored_address(email) AS canon
--     FROM users  WHERE email   IS NOT NULL AND email   <> fold_stored_address(email)
--   UNION ALL
--   SELECT 'aliases.email', id, email, fold_stored_address(email)
--     FROM aliases WHERE email  IS NOT NULL AND email   <> fold_stored_address(email)
--   UNION ALL
--   SELECT 'users.ad_upn', id, ad_upn, fold_stored_address(ad_upn)
--     FROM users  WHERE ad_upn  IS NOT NULL AND btrim(ad_upn) <> ''
--                   AND ad_upn  <> fold_stored_address(ad_upn);
--
-- (A btrim/lower-only audit would read display/fold-form ad_upn as clean and let
-- a non-canonical row slip past the deploy gate — fold_stored_address closes that.)

-- ── The permanent stored-address fold (the guarded SQL twin) ─────────────────
-- trim + ASCII-A-Z fold ONLY. No display-name regex strip (input-only). No
-- lower() (would fold non-ASCII). Pinned to the Go casing/whitespace fold by
-- shared/identity.TestFoldStoredAddress_MatchesGo.
--
-- The trim MUST mirror Go's strings.TrimSpace EXACTLY. Single-arg btrim(text)
-- uses a DEFAULT cutset that does NOT include TAB (U+0009) or LF (U+000A), so a
-- default trim would leave `\thost@realm` while Go yields `host@realm` — a real
-- writer-vs-matcher drift on ad_upn (a silent-lockout class).
-- Go's strings.TrimSpace strips every char where unicode.IsSpace is true:
--   U+0009 U+000A U+000B U+000C U+000D U+0020 U+0085 U+00A0 U+1680
--   U+2000..U+200A U+2028 U+2029 U+202F U+205F U+3000   (25 codepoints).
-- We pass that full set as an explicit U&'…' cutset literal so the SQL fold and
-- the Go fold agree on EVERY whitespace axis (\t, \n, NEL, NBSP, ideographic
-- space, …), not merely on the space-padded cases. translate() only rewrites
-- A–Z, so its order relative to btrim is irrelevant.
CREATE OR REPLACE FUNCTION fold_stored_address(p_raw TEXT) RETURNS TEXT AS $f$
  SELECT CASE
    WHEN p_raw IS NULL THEN NULL
    ELSE btrim(translate(p_raw,
                         'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
                         'abcdefghijklmnopqrstuvwxyz'),
               -- Go's strings.TrimSpace / unicode.IsSpace whitespace set:
               U&'\0009\000A\000B\000C\000D\0020\0085\00A0\1680'
                 '\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A'
                 '\2028\2029\202F\205F\3000')
  END
$f$ LANGUAGE sql IMMUTABLE;

COMMENT ON FUNCTION fold_stored_address(TEXT) IS
  'Canonical form for a STORED identity address (users.email, aliases.email, '
  'users.ad_upn): trim (Go strings.TrimSpace / unicode.IsSpace whitespace set — '
  'U+0009,000A,000B,000C,000D,0020,0085,00A0,1680,2000-200A,2028,2029,202F,205F,'
  '3000) + ASCII-A-Z fold ONLY. The display-strip-free twin of '
  'shared/identity.CanonicalizeAddress (the display-name strip is INPUT-only). '
  'Pinned by shared/identity.TestFoldStoredAddress_MatchesGo. IDN deferred.';

DO $V089$
DECLARE
  v_dup   RECORD;
  v_msg   TEXT;
BEGIN
  -- ── Collision detection (BEFORE any write) ──────────────────────────────
  -- users.email: two distinct users whose email canonicalizes to one value.
  FOR v_dup IN
    SELECT fold_stored_address(email) AS canon, array_agg(id ORDER BY id) AS ids,
           array_agg(email ORDER BY id) AS raws
    FROM users
    WHERE email IS NOT NULL
    GROUP BY fold_stored_address(email)
    HAVING count(*) > 1
  LOOP
    v_msg := format('users.email collision: canonical %L is shared by user ids %s (raw values %s)',
                    v_dup.canon, v_dup.ids, v_dup.raws);
    RAISE EXCEPTION 'V089 ABORT — %', v_msg
      USING ERRCODE = 'BZ089', HINT = 'Resolve the duplicate identities by hand, then re-run V089.';
  END LOOP;

  -- aliases.email collision.
  FOR v_dup IN
    SELECT fold_stored_address(email) AS canon, array_agg(id ORDER BY id) AS ids,
           array_agg(email ORDER BY id) AS raws
    FROM aliases
    WHERE email IS NOT NULL
    GROUP BY fold_stored_address(email)
    HAVING count(*) > 1
  LOOP
    v_msg := format('aliases.email collision: canonical %L is shared by alias ids %s (raw values %s)',
                    v_dup.canon, v_dup.ids, v_dup.raws);
    RAISE EXCEPTION 'V089 ABORT — %', v_msg
      USING ERRCODE = 'BZ089', HINT = 'Resolve the duplicate aliases by hand, then re-run V089.';
  END LOOP;

  -- users.ad_upn collision (only over rows that actually carry a UPN).
  FOR v_dup IN
    SELECT fold_stored_address(ad_upn) AS canon, array_agg(id ORDER BY id) AS ids,
           array_agg(ad_upn ORDER BY id) AS raws
    FROM users
    WHERE ad_upn IS NOT NULL AND btrim(ad_upn) <> ''
    GROUP BY fold_stored_address(ad_upn)
    HAVING count(*) > 1
  LOOP
    v_msg := format('users.ad_upn collision: canonical %L is shared by user ids %s (raw values %s)',
                    v_dup.canon, v_dup.ids, v_dup.raws);
    RAISE EXCEPTION 'V089 ABORT — %', v_msg
      USING ERRCODE = 'BZ089', HINT = 'Resolve the duplicate UPNs by hand, then re-run V089.';
  END LOOP;

  -- ── Writes (only the non-canonical rows; idempotent) ────────────────────
  UPDATE users
     SET email = fold_stored_address(email)
   WHERE email IS NOT NULL AND email <> fold_stored_address(email);

  UPDATE aliases
     SET email = fold_stored_address(email)
   WHERE email IS NOT NULL AND email <> fold_stored_address(email);

  UPDATE users
     SET ad_upn = fold_stored_address(ad_upn)
   WHERE ad_upn IS NOT NULL AND ad_upn <> fold_stored_address(ad_upn);
END
$V089$;
