-- V171__identity_link_session_security.sql — one-use identity-link
-- authorization and durable runtime-session eviction after unlink.

CREATE TABLE public.identity_auth_link_elevations (
    flow_id        UUID PRIMARY KEY,
    user_id        BIGINT NOT NULL
                       REFERENCES public.users(id) ON DELETE CASCADE,
    session_jti    TEXT NOT NULL CHECK (
        octet_length(session_jti) BETWEEN 1 AND 255
        AND session_jti !~ '[[:cntrl:]]'
    ),
    session_hash   BYTEA NOT NULL CHECK (octet_length(session_hash)=32),
    kind           TEXT NOT NULL CHECK (kind IN ('oidc','saml')),
    provider_key   TEXT NOT NULL CHECK (
        octet_length(provider_key) BETWEEN 3 AND 255
        AND provider_key=btrim(provider_key)
        AND provider_key !~ '[[:cntrl:]]'
    ),
    expires_at     TIMESTAMPTZ NOT NULL,
    consumed_at    TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    CHECK (
        expires_at>created_at
        AND expires_at<=created_at+interval '10 minutes 5 seconds'
    ),
    CHECK (consumed_at IS NULL OR consumed_at>=created_at)
);
CREATE INDEX identity_auth_link_elevations_user_idx
    ON public.identity_auth_link_elevations(user_id,expires_at);
ALTER TABLE public.identity_auth_link_elevations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.identity_auth_link_elevations FORCE ROW LEVEL SECURITY;
ALTER TABLE public.identity_auth_link_elevations OWNER TO setjoin_owner;

-- Exact LiveKit targets captured in the unlink transaction. A successful or
-- not-found removal remains nonterminal until retry_until because a token
-- minted immediately before unlink may connect after the first removal.
CREATE TABLE public.identity_session_eviction_intents (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id        UUID NOT NULL,
    user_id         BIGINT NOT NULL
                        REFERENCES public.users(id) ON DELETE CASCADE,
    reason          TEXT NOT NULL CHECK (
        octet_length(reason) BETWEEN 1 AND 128
        AND reason !~ '[[:cntrl:]]'
    ),
    room_name       TEXT NOT NULL CHECK (
        octet_length(room_name) BETWEEN 1 AND 255
        AND room_name !~ '[[:cntrl:]]'
    ),
    identity        TEXT NOT NULL CHECK (
        octet_length(identity) BETWEEN 3 AND 255
        AND identity !~ '[[:cntrl:]]'
    ),
    transition_at   TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    retry_until     TIMESTAMPTZ NOT NULL
                        DEFAULT statement_timestamp()+interval '5 minutes',
    attempt_count   INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count>=0),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    last_attempt_at TIMESTAMPTZ,
    last_error      TEXT CHECK (
        last_error IS NULL OR octet_length(last_error)<=2048
    ),
    completed_at    TIMESTAMPTZ,
    UNIQUE(event_id,room_name,identity),
    CHECK (identity='u:'||user_id::text),
    CHECK (retry_until>transition_at)
);
CREATE INDEX identity_session_eviction_due_idx
    ON public.identity_session_eviction_intents(next_attempt_at,id)
    WHERE completed_at IS NULL;
CREATE INDEX identity_session_eviction_user_idx
    ON public.identity_session_eviction_intents(user_id,id);
ALTER TABLE public.identity_session_eviction_intents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.identity_session_eviction_intents FORCE ROW LEVEL SECURITY;
ALTER TABLE public.identity_session_eviction_intents OWNER TO setjoin_owner;

INSERT INTO public.schema_migrations(version, applied_at)
VALUES (171, now()) ON CONFLICT (version) DO NOTHING;
