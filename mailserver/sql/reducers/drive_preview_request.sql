-- mailserver/sql/reducers/drive_preview_request.sql
-- drive_preview_request: member asks for an office rendition; lazy 'none'→'pending'
-- flip (spec §8.3). Returns the (possibly updated) preview_status. User-pool,
-- RLS-scoped (R1-R3: the membership join is in every statement — same shape
-- as every other drive_* user reducer, no DEFINER needed).
CREATE OR REPLACE FUNCTION drive_preview_request(p_user_id bigint, p_version_id bigint)
RETURNS text LANGUAGE plpgsql AS $$
DECLARE
    v_status text;
    v_ct     text;
BEGIN
    SELECT v.preview_status, v.content_type INTO v_status, v_ct
    FROM drive_file_versions v
    WHERE v.id = p_version_id
      AND public.drive_runtime_has_node_capability(
        p_user_id,v.file_node_id,'preview');
    IF NOT FOUND THEN
        RAISE EXCEPTION 'drive object not found' USING ERRCODE = 'BZ139',
          HINT = '{"type":"notFound","detail":"drive object not found"}';
    END IF;
    IF v_status <> 'none' THEN
        RETURN v_status;
    END IF;
    IF v_ct IS NULL OR v_ct NOT IN (
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'application/msword', 'application/vnd.ms-excel', 'application/vnd.ms-powerpoint',
        'application/vnd.oasis.opendocument.text', 'application/vnd.oasis.opendocument.spreadsheet',
        'application/vnd.oasis.opendocument.presentation'
    ) THEN
        IF NOT EXISTS(SELECT 1 FROM drive_file_versions v WHERE v.id=p_version_id
          AND public.drive_runtime_has_node_capability(
            p_user_id,v.file_node_id,'download')) THEN
          RAISE EXCEPTION 'download capability required for unsupported preview'
            USING ERRCODE='BZ253',HINT='{"type":"drive_acl_forbidden"}';
        END IF;
        UPDATE drive_file_versions v SET preview_status = 'unsupported'
        WHERE v.id = p_version_id;
        RETURN 'unsupported';
    END IF;
    UPDATE drive_file_versions v SET preview_status = 'pending'
    WHERE v.id = p_version_id;
    RETURN 'pending';
END;
$$;
