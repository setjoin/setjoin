-- mailserver/sql/reducers/drive_export_consume.sql
-- Single-use consume: one UPDATE matches grantee+unconsumed+unexpired (+ not
-- WORM-pending on gxp) and flips consumed_at atomically (no TOCTOU). SECURITY
-- INVOKER: the grantee consumes their OWN grant row under RLS
-- (drive_export_grants_consume: grantee = current user) — no escalation
-- needed, unlike the decide wrapper. ALL failure modes are the opaque BZ146
-- (unknown/expired/consumed/wrong-grantee — deliberately indistinguishable),
-- EXCEPT the transient WORM-pending case, distinguished as retryable BZ145
-- (G1 belt-and-braces: a grant approved BEFORE a WORM apply failure surfaced
-- still may not release bytes while the version's lock is pending — the
-- grant stays unconsumed and the caller retries after the worker clears it).
CREATE OR REPLACE FUNCTION drive_export_consume(
  p_user_id    bigint,
  p_token_hash text
) RETURNS jsonb AS $$
DECLARE
  v_grant record;
BEGIN
  IF p_token_hash !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'export grant invalid' USING ERRCODE = 'BZ146',
      HINT = '{"type":"invalidGrant","detail":"token malformed"}';
  END IF;

  SELECT g.id, g.version_id, g.space_id, g.action INTO v_grant
    FROM drive_export_grants g
    JOIN drive_spaces s ON s.id = g.space_id
    JOIN drive_file_versions v ON v.id=g.version_id
   WHERE g.token_hash = p_token_hash AND g.grantee = p_user_id
     AND g.consumed_at IS NULL AND g.revoked_at IS NULL AND g.expires_at > now()
     AND public.drive_runtime_has_node_capability(
           p_user_id,v.file_node_id,'download')
     AND (s.classification <> 'gxp' OR NOT EXISTS (
            SELECT 1 FROM drive_version_chunks vc
              JOIN drive_chunks c ON (c.scope_key, c.sha256) = (vc.scope_key, vc.chunk_sha256)
             WHERE vc.version_id = g.version_id AND vc.stream = 'content'
               AND c.worm_pending))
     FOR UPDATE OF g;
  IF NOT FOUND THEN
    -- Distinguish ONLY the transient worm-pending case (retryable 409),
    -- opaquely BZ146 otherwise. Re-probe without the pending clause:
    IF EXISTS (SELECT 1 FROM drive_export_grants g
                JOIN drive_file_versions v ON v.id=g.version_id
                WHERE g.token_hash = p_token_hash AND g.grantee = p_user_id
                  AND g.consumed_at IS NULL AND g.revoked_at IS NULL AND g.expires_at > now()
                  AND public.drive_runtime_has_node_capability(
                    p_user_id,v.file_node_id,'download')) THEN
      RAISE EXCEPTION 'version WORM lock pending' USING ERRCODE = 'BZ145',
        HINT = '{"type":"immutable","detail":"export blocked until the retention lock is applied"}';
    END IF;
    RAISE EXCEPTION 'export grant invalid' USING ERRCODE = 'BZ146',
      HINT = '{"type":"invalidGrant","detail":"grant unknown, expired, consumed, or not yours"}';
  END IF;

  UPDATE drive_export_grants SET consumed_at = now() WHERE id = v_grant.id;

  PERFORM drive_access_audit(p_user_id, v_grant.space_id,
                             CASE v_grant.action WHEN 'print' THEN 'export.print' ELSE 'export.download' END,
                             'version', v_grant.version_id, NULL,
                             jsonb_build_object('grant_id', v_grant.id), NULL, NULL);
  RETURN jsonb_build_object('versionId', v_grant.version_id, 'action', v_grant.action,
                            'spaceId', v_grant.space_id);
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY INVOKER;
