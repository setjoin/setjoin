-- Rust JMAP2 (#316): frozen Go dispatchSet's create -> update -> destroy
-- transaction. Each existing reducer remains the effect authority. Later
-- phases overwrite envelope keys exactly as Go's mergeSetResults does.
CREATE OR REPLACE FUNCTION jmap_identity_set_batch(
  p_mailbox_id BIGINT,
  p_create JSONB DEFAULT NULL,
  p_update JSONB DEFAULT NULL,
  p_destroy BIGINT[] DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
  v_result JSONB := '{}'::JSONB;
BEGIN
  IF jsonb_typeof(p_create) = 'object' THEN
    v_result := v_result || jmap_identity_set_create(p_mailbox_id, p_create);
  END IF;
  IF jsonb_typeof(p_update) = 'object' THEN
    v_result := v_result || jmap_identity_set_update(p_mailbox_id, p_update);
  END IF;
  IF p_destroy IS NOT NULL THEN
    v_result := v_result || jmap_identity_set_destroy(p_mailbox_id, p_destroy);
  END IF;
  RETURN v_result;
END;
$$ LANGUAGE plpgsql;
