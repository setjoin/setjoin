-- mailserver/sql/reducers/drive_policy_resolve.sql
-- §9.2 single source of truth: classification defaults ← stored export_policy
-- ← gxp hard floor (stored JSON may never weaken gxp). STABLE, pure read.
CREATE OR REPLACE FUNCTION drive_policy_resolve(p_space_id BIGINT) RETURNS JSONB AS $$
  SELECT CASE s.classification
           WHEN 'regular' THEN '{"export":"allow","print":"allow","share":"direct","audit_reads":false,"watermark":false,"edit_lock":"soft"}'::jsonb
           WHEN 'secure'  THEN '{"export":"allow","print":"allow","share":"direct","audit_reads":true,"watermark":false,"edit_lock":"soft"}'::jsonb
           ELSE                '{"export":"allow","print":"allow","share":"direct","audit_reads":true,"watermark":false,"edit_lock":"soft"}'::jsonb
         END
         || s.export_policy
         || CASE WHEN s.classification = 'gxp'
              THEN '{"export":"approval","print":"approval","share":"approval","audit_reads":true}'::jsonb
              ELSE '{}'::jsonb END
    FROM drive_spaces s WHERE s.id = p_space_id;
$$ LANGUAGE sql STABLE;
