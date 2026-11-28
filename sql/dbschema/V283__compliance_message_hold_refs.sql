-- Partition-safe hold/release returning (id, received_at) references for S3 object-lock lookup
-- on existing databases upgraded via `mailctl schema apply`.
CREATE OR REPLACE FUNCTION rust_compliance_message_hold(
 p_actor bigint,p_ids bigint[],p_on boolean,p_ip text,p_with_refs boolean
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_refs jsonb := '[]'::jsonb;
BEGIN
 IF p_actor IS NULL OR p_actor<=0 THEN RETURN v_refs; END IF;
 BEGIN
  WITH changed AS (
   UPDATE messages SET held=p_on
   WHERE id=ANY(p_ids) AND held=NOT p_on AND p_actor>0 RETURNING id,received_at
  ) SELECT COALESCE(jsonb_agg(jsonb_build_object('id',id,'received_at',received_at)),'[]'::jsonb)
  INTO v_refs FROM changed;
 EXCEPTION WHEN OTHERS THEN
  -- Go swallows Query failure and still attempts the audit and a 200 response.
  v_refs := '[]'::jsonb;
 END;
 BEGIN
  PERFORM audit_write(p_actor,CASE WHEN p_on THEN 'ediscovery_hold' ELSE 'ediscovery_release' END,
   'message',NULL,COALESCE(to_jsonb(p_ids),'null'::jsonb),NULL,NULLIF(p_ip,'')::inet,'','core');
 EXCEPTION WHEN OTHERS THEN
  -- The frozen handler also ignores audit.Write failure.
  NULL;
 END;
 -- Go does not bump JMAP state, journal, or notify for this legacy flag write.
 RETURN v_refs;
END;
$$;

INSERT INTO public.schema_migrations (version, applied_at) VALUES (283, now())
    ON CONFLICT (version) DO NOTHING;
