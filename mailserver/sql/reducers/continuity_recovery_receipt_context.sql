-- deps: continuity_context_issue
CREATE OR REPLACE FUNCTION continuity_recovery_receipt_context(
    p_mailbox_id bigint,
    p_message_ids bigint[],
    p_boot_epoch uuid
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public
AS $$
DECLARE
    v_context jsonb;
    v_list jsonb;
BEGIN
    IF p_mailbox_id IS NULL OR p_boot_epoch IS NULL OR p_message_ids IS NULL OR
       cardinality(p_message_ids)=0 OR cardinality(p_message_ids)>64 OR
       NULLIF(current_setting('app.current_mailbox_id',true),'')::bigint IS DISTINCT FROM p_mailbox_id THEN
        RAISE EXCEPTION 'recovery receipt request is invalid'
            USING ERRCODE='BZ251',HINT='{"type":"continuity_receipt_invalid"}';
    END IF;
    v_context := continuity_context_issue(p_mailbox_id,p_boot_epoch);
    SELECT COALESCE(jsonb_agg(jsonb_build_object(
        'id',m.id::text,
        'rawRef',m.raw_ref,
        'receivedAt',m.received_at,
        'eligibility',CASE WHEN loc.name='Sent' THEN 'sent-terminal' ELSE 'received' END,
        'attachments',COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                'blobId',ma.blob_sha256,'sha256',ma.blob_sha256,
                'size',ma.size_bytes::text,'role',ma.disposition
            ) ORDER BY ma.id)
            FROM message_attachments ma
            WHERE ma.message_id=m.id AND ma.received_at=m.received_at
        ),'[]'::jsonb)
    ) ORDER BY requested.ordinality),'[]'::jsonb)
      INTO v_list
      FROM unnest(p_message_ids) WITH ORDINALITY AS requested(id,ordinality)
      JOIN messages m ON m.id=requested.id AND m.mailbox_id=p_mailbox_id
      LEFT JOIN LATERAL (
          SELECT t.name
          FROM message_tags mt JOIN tags t ON t.id=mt.tag_id
          WHERE mt.message_id=m.id AND mt.received_at=m.received_at
            AND t.mailbox_id=p_mailbox_id AND t.exclusive_group='location'
          LIMIT 1
      ) loc ON true
     WHERE COALESCE(loc.name,'') NOT IN ('Drafts','Scheduled')
       AND NOT EXISTS (
           SELECT 1 FROM scheduled_actions sa
           WHERE sa.mailbox_id=p_mailbox_id
             AND sa.status IN ('pending','processing')
             AND sa.payload @> jsonb_build_object('message_id',m.id)
       )
       AND (loc.name IS DISTINCT FROM 'Sent' OR NOT EXISTS (
           SELECT 1 FROM outbound_queue q
           WHERE q.mailbox_id=p_mailbox_id AND q.raw_ref=m.raw_ref
             AND q.status IN ('pending','sending','deferred')
       ));
    RETURN jsonb_build_object('context',v_context,'list',v_list);
END;
$$;

REVOKE ALL ON FUNCTION continuity_recovery_receipt_context(bigint,bigint[],uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION continuity_recovery_receipt_context(bigint,bigint[],uuid) TO setjoin_app,setjoin_worker;
SELECT apply_worker_ownership('continuity_recovery_receipt_context(bigint,bigint[],uuid)'::regprocedure);
