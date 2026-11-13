-- Frozen-Go litigation hold/release plus the unconditional best-effort audit.
-- Organization-wide verified grants are admitted at the HTTP boundary. This
-- function runs only on the explicitly configured worker credential, like Go.
CREATE OR REPLACE FUNCTION rust_compliance_message_hold(
 p_actor bigint,p_ids bigint[],p_on boolean,p_ip text
) RETURNS bigint[] LANGUAGE plpgsql VOLATILE SECURITY INVOKER AS $$
DECLARE v_ids bigint[] := '{}'::bigint[];
BEGIN
 IF p_actor IS NULL OR p_actor<=0 THEN RETURN v_ids; END IF;
 BEGIN
  WITH changed AS (
   UPDATE messages SET held=p_on
   WHERE id=ANY(p_ids) AND held=NOT p_on AND p_actor>0 RETURNING id
  ) SELECT COALESCE(array_agg(id),'{}'::bigint[]) INTO v_ids FROM changed;
 EXCEPTION WHEN OTHERS THEN
  -- Go swallows Query failure and still attempts the audit and a 200 response.
  v_ids := '{}'::bigint[];
 END;
 BEGIN
  PERFORM audit_write(p_actor,CASE WHEN p_on THEN 'ediscovery_hold' ELSE 'ediscovery_release' END,
   'message',NULL,COALESCE(to_jsonb(p_ids),'null'::jsonb),NULL,NULLIF(p_ip,'')::inet,'','core');
 EXCEPTION WHEN OTHERS THEN
  -- The frozen handler also ignores audit.Write failure.
  NULL;
 END;
 -- Go does not bump JMAP state, journal, or notify for this legacy flag write.
 RETURN v_ids;
END;
$$;
