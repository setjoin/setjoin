-- V160: activate source-scoped attribute authority and normalized entitlement
-- evidence. The global normalized read/transition toggle remains OFF.

ALTER TABLE public.identity_link_events
    DROP CONSTRAINT identity_link_events_action_check;
ALTER TABLE public.identity_link_events
    ADD CONSTRAINT identity_link_events_action_check CHECK (
        action IN (
            'source_created','source_updated','source_entry_applied',
            'source_entry_quarantined','source_cursor_committed',
            'candidate_recorded','link_activated','link_suspended',
            'link_detached','link_relinked','auth_resolved','auth_jit_created',
            'attribute_authority_applied','entitlements_reconciled',
            'authority_changed','conflict_decided','legacy_backfilled'
        )
    );

INSERT INTO public.schema_migrations (version, applied_at)
VALUES (160, now());
