-- V155: fail-closed completeness for stable federation identity pairs.
--
-- Existing installations may contain legacy rows where only one half of an
-- OIDC or SAML pair is populated. Snapshot those rows for operator inventory,
-- but do not add a NOT VALID CHECK: PostgreSQL would still reject unrelated
-- updates to a legacy row. The column-specific trigger instead requires every
-- new row and every future pair mutation to finish in a complete-or-cleared
-- state.

CREATE TABLE public.identity_legacy_federation_pair_inventory (
    user_id                  BIGINT PRIMARY KEY
                             REFERENCES public.users(id) ON DELETE CASCADE,
    oidc_subject_missing     BOOLEAN NOT NULL,
    oidc_issuer_missing      BOOLEAN NOT NULL,
    saml_name_id_missing     BOOLEAN NOT NULL,
    saml_idp_entity_missing  BOOLEAN NOT NULL,
    observed_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT identity_legacy_federation_pair_inventory_incomplete_check
        CHECK (
            (oidc_subject_missing <> oidc_issuer_missing)
            OR (saml_name_id_missing <> saml_idp_entity_missing)
        )
);

INSERT INTO public.identity_legacy_federation_pair_inventory (
    user_id,
    oidc_subject_missing,
    oidc_issuer_missing,
    saml_name_id_missing,
    saml_idp_entity_missing
)
SELECT
    id,
    oidc_subject IS NULL,
    oidc_issuer IS NULL,
    saml_name_id IS NULL,
    saml_idp_entity_id IS NULL
FROM public.users
WHERE (oidc_subject IS NULL) <> (oidc_issuer IS NULL)
   OR (saml_name_id IS NULL) <> (saml_idp_entity_id IS NULL);

COMMENT ON TABLE public.identity_legacy_federation_pair_inventory IS
    'V155 snapshot of users whose pre-existing OIDC or SAML stable identity was only partially populated. Contains booleans and user ids only; operators must explicitly repair or clear each pair.';

CREATE FUNCTION public.enforce_federation_identity_pair_completeness()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF (NEW.oidc_subject IS NULL) <> (NEW.oidc_issuer IS NULL)
       OR (NEW.saml_name_id IS NULL) <> (NEW.saml_idp_entity_id IS NULL) THEN
        RAISE EXCEPTION 'federation identity pairs must be written or cleared together'
            USING ERRCODE = 'BZ227',
                  HINT = '{"type":"identity_pair_incomplete"}';
    END IF;
    RETURN NEW;
END;
$$;

SELECT public.apply_worker_ownership(
    'public.enforce_federation_identity_pair_completeness()'::regprocedure
);

CREATE TRIGGER trg_users_federation_identity_pair_completeness
    BEFORE INSERT OR UPDATE OF
        oidc_subject,
        oidc_issuer,
        saml_name_id,
        saml_idp_entity_id
    ON public.users
    FOR EACH ROW
    EXECUTE FUNCTION public.enforce_federation_identity_pair_completeness();

INSERT INTO public.schema_migrations (version, applied_at) VALUES (155, now())
ON CONFLICT (version) DO NOTHING;
