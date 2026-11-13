-- V069__push_mfa_approved_at.sql
--
-- C10 push-MFA out-of-band completion: add approved_at, DISTINCT from verified_at.
--
-- Number-match push MFA is verified ONLY on the device-authenticated channel
-- (POST /auth/mfa/approve). The browser / webpush login flow cannot complete
-- in-band (the correct code rides only the enrolled device), so it polls
-- /auth/push/status, which issues the login session ONLY once the device has
-- approved.
--
-- approved_at must be its OWN column, NOT reused from verified_at: the shared
-- VerifyChallenge primitive ALSO stamps verified_at on a 3-strike lockout (to
-- burn the challenge) and on a wrong-answer exhaustion. Reading verified_at as
-- the approval signal would let a lockout masquerade as an approval and hand a
-- session to whoever is polling. approved_at is set ONLY on a genuine device
-- approval (a correct answer on /auth/mfa/approve) and is the sole gate the
-- status poll trusts before issuing tokens.

ALTER TABLE public.push_mfa_challenges
  ADD COLUMN IF NOT EXISTS approved_at timestamp with time zone;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (69, now());
