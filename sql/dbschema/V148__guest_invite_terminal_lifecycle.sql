-- V148__guest_invite_terminal_lifecycle.sql — exact per-invite terminal
-- observability for Guest Accounts release readiness.
--
-- `used_at` remains the compatibility terminal timestamp. terminal_reason
-- records why the invite stopped being usable. A naturally elapsed row may
-- remain open until the next locked mutation; read paths derive `expired`
-- immediately from expires_at and that mutation stamps used_at=expires_at.

ALTER TABLE public.guest_invites
    ADD COLUMN terminal_reason text;

-- An invite cannot outlive the guest account it would activate. Older rows
-- were minted from the invite TTL alone, so cap every still-open link at the
-- account's own expiry before classifying terminal state.
UPDATE public.guest_invites gi
   SET expires_at = LEAST(gi.expires_at, ga.expires_at)
  FROM public.guest_accounts ga
 WHERE ga.user_id = gi.guest_user_id
   AND gi.used_at IS NULL
   AND ga.expires_at IS NOT NULL
   AND ga.expires_at < gi.expires_at;

-- disclosure_accepted_at was always written in the same transaction as
-- used_at. If an older deployment contains the otherwise-impossible partial
-- shape, the accepted timestamp is sufficient evidence to repair it exactly.
UPDATE public.guest_invites
   SET used_at = disclosure_accepted_at,
       terminal_reason = 'accepted'
 WHERE used_at IS NULL
   AND disclosure_accepted_at IS NOT NULL;

-- Accepted rows are provable. Other pre-V148 terminal rows cannot be
-- distinguished honestly between replacement and revocation.
UPDATE public.guest_invites
   SET terminal_reason = CASE
       WHEN disclosure_accepted_at IS NOT NULL THEN 'accepted'
       ELSE 'legacy_unknown'
   END
 WHERE used_at IS NOT NULL
   AND terminal_reason IS NULL;

ALTER TABLE public.guest_invites
    ADD CONSTRAINT guest_invites_terminal_reason_check CHECK (
        (used_at IS NULL AND terminal_reason IS NULL)
        OR
        (used_at IS NOT NULL AND terminal_reason IN (
            'accepted', 'superseded', 'revoked', 'expired', 'legacy_unknown'
        ))
    );

CREATE INDEX guest_invites_history_idx
    ON public.guest_invites (guest_user_id, created_at DESC, id DESC);

INSERT INTO public.schema_migrations (version, applied_at) VALUES (148, now())
    ON CONFLICT (version) DO NOTHING;
