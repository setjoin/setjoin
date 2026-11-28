-- Reducer: detect_spray — detects password spray attacks.
-- Counts distinct usernames with failed auth from the same IP within a time window.
CREATE OR REPLACE FUNCTION detect_spray(
    p_source_ip      INET,
    p_window_sec     INT DEFAULT 300,
    p_threshold      INT DEFAULT 5
) RETURNS BOOL AS $$
DECLARE
    v_unique_users INT;
BEGIN
    SELECT COUNT(DISTINCT target_username)
    INTO v_unique_users
    FROM auth_attempts
    WHERE source_ip = p_source_ip
      AND outcome = 'failure'
      AND occurred_at > now() - (p_window_sec || ' seconds')::INTERVAL;

    RETURN v_unique_users >= p_threshold;
END;
$$ LANGUAGE plpgsql VOLATILE;
