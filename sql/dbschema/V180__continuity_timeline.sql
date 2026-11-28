-- V180: signed external rollback witness substrate. All feature gates stay OFF.

ALTER TABLE public.upgrade_control_state
    ADD COLUMN timeline_generation bigint NOT NULL DEFAULT 1 CHECK (timeline_generation > 0),
    ADD COLUMN continuity_last_wall_clock timestamptz,
    ADD COLUMN continuity_last_boot_epoch uuid,
    ADD COLUMN continuity_last_boot_at timestamptz,
    ADD COLUMN continuity_restore_declared_at timestamptz,
    ADD COLUMN continuity_restore_reason text CHECK (
        continuity_restore_reason IS NULL OR
        (length(continuity_restore_reason) BETWEEN 8 AND 512 AND continuity_restore_reason !~ '[\r\n]')
    );

CREATE TABLE public.continuity_client_witnesses (
    id                    bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    mailbox_id            bigint NOT NULL REFERENCES public.mailboxes(id) ON DELETE CASCADE,
    token_sha256          bytea NOT NULL CHECK (octet_length(token_sha256)=32),
    installation_id       uuid NOT NULL,
    timeline_generation   bigint NOT NULL CHECK (timeline_generation > 0),
    state_watermark       bigint NOT NULL CHECK (state_watermark >= 0),
    issued_at             timestamptz NOT NULL,
    boot_epoch            uuid NOT NULL,
    signal_class          text NOT NULL CHECK (signal_class IN ('none','client_observed_newer_timeline')),
    observed_at           timestamptz NOT NULL DEFAULT statement_timestamp(),
    UNIQUE(mailbox_id,token_sha256)
);
CREATE INDEX continuity_client_witness_signal_idx
    ON public.continuity_client_witnesses(mailbox_id,observed_at DESC)
    WHERE signal_class='client_observed_newer_timeline';

ALTER TABLE public.continuity_client_witnesses ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.continuity_client_witnesses FORCE ROW LEVEL SECURITY;
CREATE POLICY continuity_client_witness_owner ON public.continuity_client_witnesses
    USING (mailbox_id=(SELECT NULLIF(current_setting('app.current_mailbox_id',true),'')::bigint))
    WITH CHECK (mailbox_id=(SELECT NULLIF(current_setting('app.current_mailbox_id',true),'')::bigint));
ALTER TABLE public.continuity_client_witnesses OWNER TO setjoin_owner;

INSERT INTO public.schema_migrations(version,applied_at) VALUES (180,now())
ON CONFLICT (version) DO NOTHING;
