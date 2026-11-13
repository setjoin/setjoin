-- V244__ediscovery_result_binding_sso_grant_authority.sql — med-shard3-007
-- (Astra waves34 HOLD items 2 and 3). Two independent authority fences that
-- both need one schema/seed change each:
--
-- 1. eDiscovery case binding (HOLD item 3): a completed search previously
--    persisted only a COUNT; the result message ids were recomputed from the
--    stored query on every read, so an export under an authorized case could
--    stream ARBITRARY supplied message ids and GetSearch served results for
--    searches bound to no case at all. ediscovery_search_results persists the
--    bound result set at completion time (the Go search executor fills it in
--    the same transaction that flips status to 'complete'); reads and exports
--    are then confined to exactly those rows. No user-owned data (rows are
--    search-scoped compliance evidence, reached only through the worker pool
--    behind mail.export) → no RLS, the smime_cert_revocations posture.
--    The bound set is capped by the executor at the same 500-row ceiling the
--    fetchResults read path already enforced; result_count keeps reporting the
--    full match count.
--
-- 2. SSO login-time minting authority (HOLD item 2): applyGroupMappings
--    minted admin_role_assignments at login with no grant-authority check.
--    The fence: a governed role label may only be minted while the
--    system_config record 'sso_admin_role_grant_authority' carries for that
--    label an authorized_perms set that still covers the role group's CURRENT
--    permissions (Rule A — grant-only-what-you-hold — evaluated at mint
--    time; a role widened past its authorization stops minting). The seed
--    below records the four governed labels with their permission set as of
--    install (authorized_by NULL = legacy/system authority), so mappings that
--    predate this fence ("legacy mappings") keep minting, while authority
--    loss (record removed, or role widened beyond the snapshot) refuses the
--    mint. The mailserver console write boundary (UpdateGroupMappings) is the
--    roles.manage-side refresher of these records.
--    ON CONFLICT DO NOTHING: a re-applied load must never resurrect an
--    authority an operator deliberately deleted.

-- ── 1. Case-bound search results ─────────────────────────────────────────────

CREATE TABLE public.ediscovery_search_results (
    search_id  bigint NOT NULL,
    message_id bigint NOT NULL,
    bound_at   timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ediscovery_search_results_pkey PRIMARY KEY (search_id, message_id),
    CONSTRAINT ediscovery_search_results_search_id_fkey
        FOREIGN KEY (search_id) REFERENCES public.ediscovery_searches(id)
        ON DELETE CASCADE
);

CREATE INDEX ediscovery_search_results_message_idx
    ON public.ediscovery_search_results (message_id);

-- ── 2. SSO login-time minting authority seed (legacy labels) ─────────────────

INSERT INTO public.system_config (key, value, description, updated_at)
SELECT 'sso_admin_role_grant_authority',
       COALESCE(jsonb_object_agg(
           g.label,
           jsonb_build_object(
               'authorized_by', NULL::bigint,
               'authorized_at', to_char(now() AT TIME ZONE 'UTC',
                                        'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
               'authorized_perms', to_jsonb(rg.permissions),
               'legacy', TRUE)
       ), '{}'::jsonb),
       'med-shard3-007 F-004: per-role SSO login-time minting authority; '
           || 'authorized_perms is the ceiling the role group''s live '
           || 'permissions must stay within (Rule A at mint time)',
       now()
FROM (VALUES
         ('super_admin'::text, 1::bigint),
         ('user_admin'::text,  2::bigint),
         ('auditor'::text,     4::bigint),
         ('read_only'::text,   8::bigint)
     ) AS g(label, gid)
JOIN public.admin_role_groups rg ON rg.id = g.gid
ON CONFLICT (key) DO NOTHING;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (244, now())
    ON CONFLICT (version) DO NOTHING;
