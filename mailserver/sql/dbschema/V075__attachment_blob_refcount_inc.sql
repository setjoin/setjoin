-- V075: symmetric AFTER INSERT ref_count trigger for message_attachments.
--
-- The baseline ships only the DECREMENT half (attachment_blob_refcount, AFTER DELETE
-- → trg_attachment_deleted, ref_count - 1). Outbound attachments (the first real
-- inserter of message_attachments — inbound never populated it) need the matching
-- INCREMENT so a blob's ref_count reflects its live attachments. Compose's PUT /blobs
-- now creates the blobs row at ref_count = 0 (an uploaded-but-unsent orphan); the
-- first message_attachments insert bumps 0 → 1 here, and the DELETE trigger restores
-- it, so blob_refcount_cleanup (AFTER UPDATE OF ref_count) GCs a truly-unreferenced blob.

CREATE FUNCTION public.trg_attachment_inserted() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  UPDATE blobs SET ref_count = ref_count + 1 WHERE sha256 = NEW.blob_sha256;
  RETURN NEW;
END;
$$;

CREATE TRIGGER attachment_blob_refcount_inc AFTER INSERT ON public.message_attachments
  FOR EACH ROW EXECUTE FUNCTION public.trg_attachment_inserted();

INSERT INTO public.schema_migrations (version, applied_at) VALUES (75, now())
  ON CONFLICT (version) DO NOTHING;
