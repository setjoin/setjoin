-- V239: device HMAC single-use nonce store (deployment-wide replay binding).
--
-- Security remediation (D-AUTHSERVER-INTERNAL-DEVICE-001/002, med-shard2-006):
-- the device HMAC proof was bound only to "{device_id}:{timestamp}" with a ±5
-- minute freshness window, so one captured header pair could be replayed
-- freely inside the window — including concurrently against two verifier
-- replicas, and against the second authenticated endpoint (checkin ⇄ policy).
--
-- Fix (paired with the Go seam change in shared/device/verify.go in the same
-- change-set): the device proof now also carries a per-request single-use
-- nonce. This table is the DEPLOYMENT-WIDE claim store: PRIMARY KEY
-- (device_id, nonce) makes the claim atomic across every replica sharing the
-- database — two concurrent INSERTs of one captured nonce let exactly one
-- transaction commit (unique_violation); the loser is a replay and is
-- rejected. The Go seam claims the nonce (via device_nonce_claim) only after
-- the HMAC verifies and BEFORE the request is accepted, so the claim is
-- committed before acceptance.
--
-- Nonce rows expire: a proof can only be accepted while its timestamp is
-- within MaxClockSkew (±5 min), so a claimed nonce can never be replayed once
-- its expiry has passed (the Go seam claims with a window of 2*MaxClockSkew +
-- 1 minute). device_nonce_claim purges this device's expired rows on every
-- claim, which bounds the table without a cron dependency.
--
-- No RLS: like the canonical devices row it guards, this is pre-authentication
-- security plumbing (the device HMAC IS the authentication being evaluated);
-- there is no user/tenant identity to scope a policy to. It contains no user
-- data — only the device id, the opaque nonce, and the claim timestamps.

CREATE TABLE IF NOT EXISTS public.device_auth_nonces (
  device_id  bigint      NOT NULL REFERENCES public.devices(id) ON DELETE CASCADE,
  nonce      text        NOT NULL,
  expires_at timestamptz NOT NULL,
  claimed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (device_id, nonce)
);

-- Expiry-scan support (device_id prefix is the PK; this covers claim-side
-- purges and any future full-gc sweep by expires_at alone).
CREATE INDEX IF NOT EXISTS device_auth_nonces_expires_idx
  ON public.device_auth_nonces (expires_at);

INSERT INTO public.schema_migrations (version, applied_at) VALUES (239, now())
ON CONFLICT (version) DO NOTHING;
