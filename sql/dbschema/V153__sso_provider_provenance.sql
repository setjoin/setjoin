-- V153: release-zero identity safety floor.
--
-- SSO group reconciliation used to sweep every SSO-managed effective grant for
-- a user before re-applying the current provider's mappings. A login through
-- provider B could therefore delete provider A's distribution-group membership
-- or governed admin role. Keep effective rows unique, but record every exact
-- provider that currently supports them.
--
-- Existing rows cannot be attributed safely. Inventory them explicitly and
-- keep that ambiguity durable: a provider-specific sweep must never delete an
-- effective row while a legacy-inventory marker remains.

INSERT INTO public.feature_toggles (key, enabled, description)
VALUES (
    'feature.identity_model_v2',
    FALSE,
    'Identity source/link modernization; remains off until its rollout gate is approved'
)
ON CONFLICT (key) DO NOTHING;

CREATE TABLE public.sso_distribution_group_provenance (
    provider_key text NOT NULL,
    group_id bigint NOT NULL,
    mailbox_id bigint NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT sso_distribution_group_provenance_pkey
        PRIMARY KEY (provider_key, group_id, mailbox_id),
    CONSTRAINT sso_distribution_group_provenance_member_fk
        FOREIGN KEY (group_id, mailbox_id)
        REFERENCES public.distribution_group_members (group_id, mailbox_id)
        ON DELETE CASCADE,
    CONSTRAINT sso_distribution_group_provenance_provider_key_chk
        CHECK (
            provider_key = btrim(provider_key)
            AND octet_length(provider_key) BETWEEN 3 AND 255
            AND provider_key !~ '[[:cntrl:]]'
        )
);

CREATE INDEX sso_distribution_group_provenance_sweep_idx
    ON public.sso_distribution_group_provenance (provider_key, mailbox_id, group_id);

CREATE INDEX sso_distribution_group_provenance_member_idx
    ON public.sso_distribution_group_provenance (group_id, mailbox_id);

CREATE TABLE public.sso_admin_role_provenance (
    provider_key text NOT NULL,
    assignment_id bigint NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT sso_admin_role_provenance_pkey
        PRIMARY KEY (provider_key, assignment_id),
    CONSTRAINT sso_admin_role_provenance_assignment_fk
        FOREIGN KEY (assignment_id)
        REFERENCES public.admin_role_assignments (id)
        ON DELETE CASCADE,
    CONSTRAINT sso_admin_role_provenance_provider_key_chk
        CHECK (
            provider_key = btrim(provider_key)
            AND octet_length(provider_key) BETWEEN 3 AND 255
            AND provider_key !~ '[[:cntrl:]]'
        )
);

CREATE INDEX sso_admin_role_provenance_assignment_idx
    ON public.sso_admin_role_provenance (assignment_id);

CREATE TABLE public.sso_distribution_group_legacy_inventory (
    group_id bigint NOT NULL,
    mailbox_id bigint NOT NULL,
    discovered_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT sso_distribution_group_legacy_inventory_pkey
        PRIMARY KEY (group_id, mailbox_id),
    CONSTRAINT sso_distribution_group_legacy_inventory_member_fk
        FOREIGN KEY (group_id, mailbox_id)
        REFERENCES public.distribution_group_members (group_id, mailbox_id)
        ON DELETE CASCADE
);

INSERT INTO public.sso_distribution_group_legacy_inventory (group_id, mailbox_id)
SELECT group_id, mailbox_id
  FROM public.distribution_group_members
 WHERE source = 'sso'
ON CONFLICT DO NOTHING;

CREATE TABLE public.sso_admin_role_legacy_inventory (
    assignment_id bigint PRIMARY KEY
        REFERENCES public.admin_role_assignments (id) ON DELETE CASCADE,
    discovered_at timestamptz NOT NULL DEFAULT now()
);

-- NULL granted_by historically meant "system" rather than one named provider.
-- Inventory the superset: retaining an ambiguous automated grant is safer than
-- allowing an unrelated IdP login to remove it.
INSERT INTO public.sso_admin_role_legacy_inventory (assignment_id)
SELECT id
  FROM public.admin_role_assignments
 WHERE granted_by IS NULL
ON CONFLICT DO NOTHING;

COMMENT ON TABLE public.sso_distribution_group_legacy_inventory IS
    'V153 snapshot of pre-provenance SSO memberships. Rows require explicit attribution or disposition before provider-scoped reconciliation may remove the effective membership.';
COMMENT ON TABLE public.sso_admin_role_legacy_inventory IS
    'V153 snapshot of pre-provenance system admin grants. Rows require explicit attribution or disposition before provider-scoped reconciliation may remove the effective assignment.';

INSERT INTO public.schema_migrations (version, applied_at) VALUES (153, now())
ON CONFLICT (version) DO NOTHING;
