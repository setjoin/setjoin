-- V170__federation_config_notifications.sql — authoritative live federation
-- configuration convergence.
--
-- PostgreSQL NOTIFY is only an acceleration signal; authserver listeners also
-- reload after first LISTEN and every reconnect. These triggers ensure steady
-- state OIDC and SAML writes emit a canonical config_changed signal in the
-- mutation transaction, including deletion.

CREATE OR REPLACE FUNCTION public.trg_system_config_notify()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_row public.system_config%ROWTYPE;
BEGIN
    v_row := COALESCE(NEW, OLD);
    PERFORM pg_notify(
        'config_changed',
        json_build_object(
            'key', v_row.key,
            'encrypted', v_row.encrypted,
            'operation', lower(TG_OP)
        )::text
    );
    RETURN COALESCE(NEW, OLD);
END;
$$;

DROP TRIGGER IF EXISTS trg_system_config_notify ON public.system_config;
CREATE TRIGGER trg_system_config_notify
AFTER INSERT OR UPDATE OR DELETE ON public.system_config
FOR EACH ROW EXECUTE FUNCTION public.trg_system_config_notify();

CREATE OR REPLACE FUNCTION public.trg_saml_sp_config_notify()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_notify(
        'config_changed',
        json_build_object(
            'key', 'saml_sp',
            'operation', lower(TG_OP)
        )::text
    );
    RETURN COALESCE(NEW, OLD);
END;
$$;

DROP TRIGGER IF EXISTS trg_saml_sp_config_notify
    ON public.saml_sp_registrations;
CREATE TRIGGER trg_saml_sp_config_notify
AFTER INSERT OR UPDATE OR DELETE ON public.saml_sp_registrations
FOR EACH ROW EXECUTE FUNCTION public.trg_saml_sp_config_notify();

INSERT INTO public.schema_migrations(version, applied_at)
VALUES (170, now()) ON CONFLICT (version) DO NOTHING;
