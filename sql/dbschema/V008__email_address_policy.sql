-- V008__email_address_policy.sql
-- Conditional Email Address Policy: CJK transliteration tables + curated surnames.
-- Spec: docs/superpowers/specs/2026-06-21-conditional-email-address-policy-design.md
-- (The email_address_policies table + users.address_policy_enabled column are
--  appended to this file in Phase 2, Task 6.)

-- Per-character toneless pinyin, generated from Unihan kMandarin (seed: V009).
CREATE TABLE public.cjk_pinyin (
    codepoint integer PRIMARY KEY,
    pinyin    text NOT NULL
);

-- Curated authoritative surname readings (polyphonic + compound), longest-match.
CREATE TABLE public.cjk_surname (
    seq    text PRIMARY KEY,
    pinyin text NOT NULL
);

INSERT INTO public.cjk_surname (seq, pinyin) VALUES
    ('单','shan'), ('解','xie'), ('仇','qiu'), ('区','ou'), ('曾','zeng'),
    ('查','zha'), ('朴','piao'), ('翟','zhai'), ('盖','ge'), ('乐','yue'),
    ('欧阳','ouyang'), ('司马','sima'), ('诸葛','zhuge'), ('尉迟','yuchi'),
    ('长孙','zhangsun'), ('万俟','moqi'), ('慕容','murong'), ('轩辕','xuanyuan'),
    ('皇甫','huangfu'), ('端木','duanmu'), ('上官','shangguan'), ('夏侯','xiahou'),
    ('公孙','gongsun'), ('南宫','nangong'), ('令狐','linghu')
ON CONFLICT (seq) DO NOTHING;

-- ── Conditional Email Address Policy (org-global config; secured like
--    conditional_access_policies: BIGSERIAL PK, NO RLS) ───────────────────────
CREATE TABLE public.email_address_policies (
    id                          bigint NOT NULL,
    priority                    integer NOT NULL,
    name                        text NOT NULL,
    enabled                     boolean DEFAULT true NOT NULL,
    overwrite_directory_address boolean DEFAULT false NOT NULL,
    -- ANDed conditions; NULL = "any"
    cond_department             text[],
    cond_domain_ids             bigint[],
    -- NOTE: on the create-time path this is effectively 'personal'-only;
    -- shared/resource/distribution satellite tables are empty for a new mailbox.
    -- Type matching against those roles is bulk-apply-only.
    cond_mailbox_type           text[],
    cond_ad_ou                  text[],
    primary_template            text NOT NULL,
    additional_templates        text[],
    duplicate_resolution        text DEFAULT 'numeric_suffix' NOT NULL,
    created_at                  timestamp with time zone DEFAULT now() NOT NULL,
    updated_at                  timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT eap_dupres_check CHECK (duplicate_resolution = ANY (ARRAY['numeric_suffix'::text])),
    CONSTRAINT eap_primary_template_check CHECK (primary_template ~ '@' AND primary_template ~ '\{[a-z_]+\}')
);

CREATE SEQUENCE public.email_address_policies_id_seq
    START WITH 1 INCREMENT BY 1 NO MINVALUE NO MAXVALUE CACHE 1;
ALTER TABLE ONLY public.email_address_policies
    ALTER COLUMN id SET DEFAULT nextval('public.email_address_policies_id_seq'::regclass);
ALTER TABLE ONLY public.email_address_policies
    ADD CONSTRAINT email_address_policies_pkey PRIMARY KEY (id);

CREATE INDEX eap_priority_idx ON public.email_address_policies USING btree (priority);
CREATE UNIQUE INDEX eap_priority_unique_idx ON public.email_address_policies USING btree (priority) WHERE enabled;

-- Per-recipient opt-out (spec: EmailAddressPolicyEnabled parity)
ALTER TABLE public.users ADD COLUMN address_policy_enabled boolean NOT NULL DEFAULT true;

-- R8: Feature toggle kill switch — seeded OFF so the engine is inert until
-- explicitly enabled by an admin.
INSERT INTO public.feature_toggles (key, enabled, description)
    VALUES ('feature.email_address_policy', false, 'Conditional Email Address Policy engine')
    ON CONFLICT (key) DO NOTHING;

-- R10: Async bulk-apply job table (tracks background policy application runs)
CREATE TABLE public.eap_apply_jobs (
    id         bigserial PRIMARY KEY,
    policy_id  bigint,
    status     text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','done','error')),
    total      integer,
    applied    integer NOT NULL DEFAULT 0,
    error      text,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    updated_at timestamp with time zone NOT NULL DEFAULT now()
);

INSERT INTO public.schema_migrations (version, applied_at) VALUES (8, now())
    ON CONFLICT (version) DO NOTHING;
