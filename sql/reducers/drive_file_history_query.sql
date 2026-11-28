-- Drive-owned H0 History over existing immutable facts. This is a read model,
-- never an authority for compare/restore/resolve. Mixed-direction ordering is
-- occurred_at DESC, source_rank ASC, source_id DESC.
CREATE OR REPLACE FUNCTION drive_file_history_query(
  p_user_id BIGINT,
  p_file_node_id BIGINT,
  p_limit INTEGER DEFAULT 100,
  p_before_at TIMESTAMPTZ DEFAULT NULL,
  p_before_rank INTEGER DEFAULT NULL,
  p_before_id BIGINT DEFAULT NULL
) RETURNS JSONB AS $$
DECLARE
  v_space_id BIGINT;
  v_limit INTEGER := LEAST(GREATEST(COALESCE(p_limit,100),1),100);
  v_items JSONB;
  v_has_more BOOLEAN;
  v_next_at TIMESTAMPTZ;
  v_next_rank INTEGER;
  v_next_id BIGINT;
  v_view_audit BOOLEAN := false;
BEGIN
  SELECT n.space_id INTO v_space_id
    FROM drive_nodes n
   WHERE n.id=p_file_node_id AND n.kind='file'
     AND drive_runtime_has_node_capability(p_user_id,n.id,'read_metadata');
  IF v_space_id IS NULL THEN
    RAISE EXCEPTION 'file not found' USING ERRCODE='BZ139',
      HINT='{"type":"notFound","detail":"file not found"}';
  END IF;
  v_view_audit := public.drive_runtime_has_node_capability(
    p_user_id,p_file_node_id,'view_audit');

  WITH source_events AS (
    SELECT v.created_at AS occurred_at, 10 AS source_rank, v.id AS source_id,
           'version'::text AS source, 'version.accepted'::text AS kind,
           jsonb_build_object('versionId',v.id,'parentVersionId',v.parent_version_id,
             'conflictOf',v.conflict_of,'branchId',v.branch_id,'authorUserId',v.author_user_id,
             'deviceLabel',v.device_label,'note',v.note,'sha256',v.content_sha256,
             'size',v.size_bytes,'previewStatus',v.preview_status) AS details
      FROM drive_file_versions v
     WHERE v.file_node_id=p_file_node_id
    UNION ALL
    SELECT b.created_at,20,b.id,'branch','branch.created',
           jsonb_build_object('branchId',b.id,'name',b.name,'status',b.status,
             'headVersionId',b.head_version_id,'forkedFromVersionId',b.forked_from_version_id,
             'autoCreated',b.auto_created,'createdBy',b.created_by)
      FROM drive_file_branches b WHERE b.file_node_id=p_file_node_id
    UNION ALL
    SELECT b.resolved_at,21,b.id,'branch','branch.resolved',
           jsonb_build_object('branchId',b.id,'name',b.name,'status',b.status,
             'headVersionId',b.head_version_id,'resolvedBy',b.resolved_by)
      FROM drive_file_branches b
     WHERE b.file_node_id=p_file_node_id AND b.resolved_at IS NOT NULL
    UNION ALL
    SELECT a.occurred_at,30,a.id,'audit',a.action,
           jsonb_build_object('eventId',a.id,'actorUserId',a.user_id,
             'targetType',a.target_type,'targetId',a.target_id,
             'before',CASE WHEN v_view_audit THEN a.before_state ELSE NULL END,
             'after',CASE WHEN v_view_audit THEN a.after_state-'_checksum' ELSE NULL END,
             'notes',a.notes)
      FROM drive_audit_log a
     WHERE a.space_id=v_space_id AND (
       (a.target_type='node' AND a.target_id=p_file_node_id)
       OR (a.target_type='version' AND EXISTS (
             SELECT 1 FROM drive_file_versions v WHERE v.id=a.target_id AND v.file_node_id=p_file_node_id))
       OR (a.target_type='branch' AND EXISTS (
             SELECT 1 FROM drive_file_branches b WHERE b.id=a.target_id AND b.file_node_id=p_file_node_id))
       OR (v_view_audit AND a.target_type='space' AND a.target_id=v_space_id
           AND a.action IN ('classification.change','policy.change')))
    UNION ALL
    SELECT c.at,40,c.seq,'change',c.op,
           jsonb_build_object('seq',c.seq,'nodeId',c.node_id,'operation',c.op)
      FROM drive_changes c
     WHERE c.space_id=v_space_id AND c.node_id=p_file_node_id
    UNION ALL
    SELECT r.created_at,50,r.id,'office',
           CASE r.response_class WHEN 'accepted' THEN 'office.save'
             WHEN 'branched' THEN 'office.save.branch' ELSE 'office.save.reject' END,
           jsonb_build_object('receiptId',r.id,'providerId',r.provider_id,
             'expectedBaseVersionId',r.expected_base_id,'resultVersionId',r.result_version_id,
             'resultBranchId',r.result_branch_id,'responseClass',r.response_class,
             'sha256',r.content_sha256,'rejectionFacts',r.rejection_facts)
      FROM office_save_receipts r WHERE r.file_node_id=p_file_node_id
  ), bounded AS (
    SELECT * FROM source_events e
     WHERE p_before_at IS NULL
        OR e.occurred_at < p_before_at
        OR (e.occurred_at=p_before_at AND e.source_rank > p_before_rank)
        OR (e.occurred_at=p_before_at AND e.source_rank=p_before_rank AND e.source_id < p_before_id)
     ORDER BY occurred_at DESC, source_rank ASC, source_id DESC
     LIMIT v_limit+1
  ), numbered AS (
    SELECT *,row_number() OVER (ORDER BY occurred_at DESC,source_rank ASC,source_id DESC) AS rn
      FROM bounded
  )
  SELECT COALESCE(jsonb_agg(jsonb_build_object(
           'occurredAt',occurred_at,'sourceRank',source_rank,'sourceId',source_id,
           'source',source,'kind',kind,'details',details)
           ORDER BY occurred_at DESC,source_rank ASC,source_id DESC)
           FILTER (WHERE rn<=v_limit),'[]'::jsonb),
         bool_or(rn>v_limit),
         max(occurred_at) FILTER (WHERE rn=v_limit),
         max(source_rank) FILTER (WHERE rn=v_limit),
         max(source_id) FILTER (WHERE rn=v_limit)
    INTO v_items,v_has_more,v_next_at,v_next_rank,v_next_id
    FROM numbered;

  RETURN jsonb_build_object(
    'items',COALESCE(v_items,'[]'::jsonb),
    'hasMore',COALESCE(v_has_more,false),
    'next',CASE WHEN COALESCE(v_has_more,false) THEN jsonb_build_object(
      'occurredAt',v_next_at,'sourceRank',v_next_rank,'sourceId',v_next_id) ELSE NULL END,
    'coverage',jsonb_build_object(
      'mode','direct','freshnessSeconds',0,
      'coveredSources',jsonb_build_array('version','branch','audit','change','office'),
      'omissions',jsonb_build_array('provider callbacks before Office receipts are enabled')),
    'generatedAt',now());
END;
$$ LANGUAGE plpgsql STABLE;
