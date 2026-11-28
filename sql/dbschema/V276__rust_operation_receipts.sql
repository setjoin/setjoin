-- Rust command commit observations (#257/#265). No payload, actor, mailbox or
-- resource identity is stored: these are system metadata, exempt from RLS.
-- Only the owner performs DDL. Runtime credentials can insert and look up an
-- opaque operation ID; the authority helper holds its transaction lock.
CREATE TABLE IF NOT EXISTS public.rust_operation_receipts (
    operation_id uuid PRIMARY KEY,
    family text NOT NULL,
    command text NOT NULL,
    committed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
COMMENT ON TABLE public.rust_operation_receipts IS
    'RLS exempt: Rust-owned opaque operation commit metadata; no user data or payload';
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_owner') THEN
        ALTER TABLE public.rust_operation_receipts OWNER TO setjoin_owner;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_app') THEN
        GRANT SELECT, INSERT ON public.rust_operation_receipts TO setjoin_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'setjoin_worker') THEN
        GRANT SELECT, INSERT ON public.rust_operation_receipts TO setjoin_worker;
    END IF;
END $$;
INSERT INTO public.schema_migrations (version, applied_at)
VALUES (276, now()) ON CONFLICT (version) DO NOTHING;
