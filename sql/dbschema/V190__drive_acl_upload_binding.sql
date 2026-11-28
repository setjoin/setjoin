-- V190__drive_acl_upload_binding.sql
-- ACL-mode chunk claims bind bytes to one target node and ACL epoch.  Legacy
-- claims remain readable only for legacy/shadow spaces and old clients.

CREATE TABLE public.drive_upload_authorizations (
  scope_key      text NOT NULL,
  sha256         text NOT NULL,
  user_id        bigint NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  space_id       bigint NOT NULL REFERENCES public.drive_spaces(id) ON DELETE CASCADE,
  target_node_id bigint NOT NULL,
  acl_epoch      bigint NOT NULL CHECK(acl_epoch>=0),
  created_at     timestamptz NOT NULL DEFAULT now(),
  expires_at     timestamptz NOT NULL DEFAULT (now()+interval '24 hours'),
  PRIMARY KEY(scope_key,sha256,user_id,target_node_id),
  FOREIGN KEY(scope_key,sha256) REFERENCES public.drive_chunks(scope_key,sha256)
    ON DELETE CASCADE,
  FOREIGN KEY(space_id,target_node_id) REFERENCES public.drive_nodes(space_id,id)
    ON DELETE CASCADE,
  CHECK(sha256~'^[0-9a-f]{64}$'),
  CHECK(expires_at>created_at AND expires_at<=created_at+interval '24 hours')
);
CREATE INDEX drive_upload_authorizations_expiry_idx
  ON public.drive_upload_authorizations(expires_at,scope_key,sha256);
ALTER TABLE public.drive_upload_authorizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.drive_upload_authorizations FORCE ROW LEVEL SECURITY;
CREATE POLICY drive_upload_authorizations_self
  ON public.drive_upload_authorizations FOR SELECT TO public
  USING(user_id=(SELECT NULLIF(current_setting('app.current_user_id',true),'')::bigint));

INSERT INTO public.schema_migrations (version, applied_at) VALUES (190, now())
ON CONFLICT(version) DO NOTHING;
