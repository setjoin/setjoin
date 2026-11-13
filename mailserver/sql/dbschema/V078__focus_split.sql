-- V078__focus_split.sql — Focused / Other inbox split (deterministic classifier).
--
-- Focused/Other is modelled as a single system tag `Other` (exclusive_group NULL,
-- imap_expose FALSE — exactly like `Muted`). A message is "Other" iff it carries
-- the Other tag; absence = Focused. Focused = in Inbox AND no Other tag; Other =
-- in Inbox AND Other tag. The message_tags counter triggers give the Other tag
-- total/unread counters for free.
--
-- focus_sender_overrides remembers a per-sender Focused/Other preference the
-- classifier (classify_focus reducer) consults first.

-- ── Per-sender override table ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.focus_sender_overrides (
    user_id    BIGINT      NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    sender     TEXT        NOT NULL,
    focused    BOOLEAN     NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, sender)
);

-- R4 backstop: per-user RLS (mirrors V060 devices_self). App-layer scoping in the
-- reducer (account_scope + the R1-scoped message read) is the primary guard; this
-- is the fail-closed defense-in-depth once the runtime DSN switches to setjoin_app.
-- Latent until then (superuser/owner bypasses FORCE), so it is a no-op for the
-- dev/test connection + pgTAP suite.
ALTER TABLE public.focus_sender_overrides ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.focus_sender_overrides FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS focus_sender_overrides_self ON public.focus_sender_overrides;
CREATE POLICY focus_sender_overrides_self ON public.focus_sender_overrides
    FOR ALL
    TO public
    USING (
        user_id = (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint)
    )
    WITH CHECK (
        user_id = (SELECT NULLIF(current_setting('app.current_user_id', TRUE), '')::bigint)
    );

-- ── create_system_tags: NEW mailboxes get the Other tag (mirrors the Muted row) ──
CREATE OR REPLACE FUNCTION public.create_system_tags(p_mailbox_id bigint) RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_uid_validity BIGINT := EXTRACT(EPOCH FROM now())::BIGINT;
    v_type         TEXT;
    v_inbox_id     BIGINT;
BEGIN
    SELECT type INTO v_type FROM mailboxes WHERE id = p_mailbox_id;

    IF v_type = 'journal' THEN
        INSERT INTO tags (mailbox_id, name, tag_type, exclusive_group, is_default, sort_order,
                          imap_uid_validity, imap_expose)
        VALUES (p_mailbox_id, 'Inbox', 'system', 'location', TRUE, 0, v_uid_validity, TRUE)
        ON CONFLICT (mailbox_id, name) DO NOTHING;
        RETURN;
    END IF;

    INSERT INTO tags (mailbox_id, name, tag_type, exclusive_group, is_default,
                      icon, color, sort_order, imap_uid_validity, imap_expose, imap_name)
    VALUES
        (p_mailbox_id, 'Inbox',     'system', 'location', TRUE,
         'inbox',    '#7C8DB5', 0,  v_uid_validity, TRUE,  NULL)
    ON CONFLICT (mailbox_id, name) DO NOTHING
    RETURNING id INTO v_inbox_id;

    INSERT INTO tags (mailbox_id, name, tag_type, exclusive_group,
                      icon, color, sort_order, imap_uid_validity, imap_expose, imap_name)
    VALUES
        (p_mailbox_id, 'Sent',      'system', 'location',
         'send',     '#5CB85C', 10, v_uid_validity, TRUE,  NULL),
        (p_mailbox_id, 'Drafts',    'system', 'location',
         'edit',     '#F0AD4E', 20, v_uid_validity, TRUE,  NULL),
        (p_mailbox_id, 'Trash',     'system', 'location',
         'delete',   '#D9534F', 30, v_uid_validity, TRUE,  '[Gmail]/Trash'),
        (p_mailbox_id, 'Spam',      'system', 'location',
         'warning',  '#D9534F', 40, v_uid_validity, TRUE,  '[Gmail]/Spam'),
        (p_mailbox_id, 'Starred',   'system', NULL,
         'star',     '#F5A623', 50, v_uid_validity, TRUE,  NULL),
        (p_mailbox_id, 'Snoozed',   'system', 'snooze',
         'clock',    '#9B59B6', 60, v_uid_validity, FALSE, NULL),
        (p_mailbox_id, 'Scheduled', 'system', 'snooze',
         'calendar', '#3498DB', 70, v_uid_validity, TRUE,  '[Gmail]/Scheduled'),
        (p_mailbox_id, 'Important', 'system', NULL,
         'priority', '#E74C3C', 80, v_uid_validity, FALSE, NULL),
        (p_mailbox_id, 'Muted',     'system', NULL,
         'volume_off', '#888888', 90, v_uid_validity, FALSE, NULL),
        (p_mailbox_id, 'Other',     'system', NULL,
         'inbox',    '#888888', 100, v_uid_validity, FALSE, NULL)
    ON CONFLICT (mailbox_id, name) DO NOTHING;
END;
$$;

-- ── Backfill existing mailboxes (same column set create_system_tags uses) ──────
INSERT INTO public.tags (mailbox_id, name, tag_type, exclusive_group,
                         icon, color, sort_order, imap_uid_validity, imap_expose, imap_name)
SELECT id, 'Other', 'system', NULL,
       'inbox', '#888888', 100, EXTRACT(EPOCH FROM now())::BIGINT, FALSE, NULL
FROM public.mailboxes
ON CONFLICT (mailbox_id, name) DO NOTHING;

-- ── Schema migration record ───────────────────────────────────────────────────
INSERT INTO public.schema_migrations (version, applied_at) VALUES (78, now())
  ON CONFLICT (version) DO NOTHING;
