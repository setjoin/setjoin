-- Organization Chart: reporting structure for org chart visualization.
CREATE OR REPLACE FUNCTION org_chart_managers(
  p_user_id BIGINT
) RETURNS JSONB AS $$
DECLARE
  v_result JSONB := '[]'::JSONB;
  v_row    RECORD;
BEGIN
  FOR v_row IN
    WITH RECURSIVE chain AS (
      SELECT id, email, display_name, first_name, last_name, job_title, department_id, manager_id, avatar_sha256, 0 AS depth
      FROM users WHERE id = p_user_id AND enabled = TRUE
      UNION ALL
      SELECT u.id, u.email, u.display_name, u.first_name, u.last_name, u.job_title, u.department_id, u.manager_id, u.avatar_sha256, c.depth + 1
      FROM users u
      JOIN chain c ON u.id = c.manager_id
      WHERE u.enabled = TRUE AND c.depth < 10
    )
    SELECT c.*, d.name AS dept_name
    FROM chain c
    LEFT JOIN departments d ON d.id = c.department_id
    WHERE c.id != p_user_id
    ORDER BY c.depth DESC
  LOOP
    v_result := v_result || jsonb_build_object(
      'id', v_row.id::TEXT,
      'email', v_row.email,
      'displayName', v_row.display_name,
      'firstName', v_row.first_name,
      'lastName', v_row.last_name,
      'jobTitle', v_row.job_title,
      'department', v_row.dept_name,
      'avatar', CASE WHEN v_row.avatar_sha256 IS NOT NULL
        THEN jsonb_build_object('blobId', v_row.avatar_sha256) END
    );
  END LOOP;
  RETURN v_result;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION org_chart_reports(
  p_user_id BIGINT,
  p_max_depth INT DEFAULT 3
) RETURNS JSONB AS $$
DECLARE
  v_result JSONB := '[]'::JSONB;
  v_row    RECORD;
BEGIN
  FOR v_row IN
    WITH RECURSIVE reports AS (
      SELECT u.id, u.email, u.display_name, u.first_name, u.last_name, u.job_title, u.department_id, u.manager_id, u.avatar_sha256, 0 AS depth,
             ARRAY[u.id] AS path_ids
      FROM users u WHERE u.manager_id = p_user_id AND u.enabled = TRUE
      UNION ALL
      SELECT u.id, u.email, u.display_name, u.first_name, u.last_name, u.job_title, u.department_id, u.manager_id, u.avatar_sha256, r.depth + 1,
             r.path_ids || u.id
      FROM users u
      JOIN reports r ON u.manager_id = r.id
      WHERE u.enabled = TRUE AND r.depth < p_max_depth
    )
    SELECT r.*, d.name AS dept_name
    FROM reports r
    LEFT JOIN departments d ON d.id = r.department_id
    ORDER BY r.manager_id, r.display_name
  LOOP
    v_result := v_result || jsonb_build_object(
      'id', v_row.id::TEXT,
      'email', v_row.email,
      'displayName', v_row.display_name,
      'firstName', v_row.first_name,
      'lastName', v_row.last_name,
      'jobTitle', v_row.job_title,
      'department', v_row.dept_name,
      'managerId', v_row.manager_id::TEXT,
      'depth', v_row.depth,
      'hasReports', EXISTS(SELECT 1 FROM users WHERE manager_id = v_row.id AND enabled = TRUE),
      'avatar', CASE WHEN v_row.avatar_sha256 IS NOT NULL
        THEN jsonb_build_object('blobId', v_row.avatar_sha256) END
    );
  END LOOP;
  RETURN v_result;
END;
$$ LANGUAGE plpgsql;
