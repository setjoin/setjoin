-- V164: every newly provisioned mailbox-backed person receives an explicit
-- lifecycle authority row. The primary personal mailbox is the stable member
-- boundary: guests never have one, while every supported local, directory, and
-- federated-JIT person does.

-- A lifecycle-authority row is person metadata and must disappear with an
-- explicitly erased person. Retained external links and append-only events keep
-- their own RESTRICT fences, so this does not make linked-person deletion
-- implicit; it only preserves the existing hard-delete behavior for a purely
-- local person.
ALTER TABLE public.user_lifecycle_authorities
    DROP CONSTRAINT user_lifecycle_authorities_user_id_fkey,
    ADD CONSTRAINT user_lifecycle_authorities_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

CREATE OR REPLACE FUNCTION public.identity_primary_mailbox_authority_init()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    INSERT INTO public.user_lifecycle_authorities (
        user_id, authority_kind
    ) VALUES (
        NEW.user_id, 'local'
    )
    ON CONFLICT (user_id) DO NOTHING;
    RETURN NEW;
END;
$$;

SELECT apply_worker_ownership(
    'identity_primary_mailbox_authority_init()'::regprocedure
);

CREATE TRIGGER identity_primary_mailbox_authority_init
AFTER INSERT ON public.mailboxes
FOR EACH ROW
WHEN (NEW.is_primary AND NEW.type = 'personal')
EXECUTE FUNCTION public.identity_primary_mailbox_authority_init();

INSERT INTO public.schema_migrations (version, applied_at)
VALUES (164, now());
