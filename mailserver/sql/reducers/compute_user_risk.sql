-- compute_user_risk.sql — deterministic local user-risk scorer (Entra ID-Protection
-- local-alt). Runs from setjoin_worker (cross-user -> DB_WORKER_DSN / BYPASSRLS). Two
-- signals over a 24h window of auth_attempts:
--   * failed_auth_velocity: >= 6 'failure' outcomes for the user's email.
--   * impossible_travel: two 'success' sign-ins from DIFFERENT countries closer in
--     time than the configured A->B minimum. Sourced from auth_attempts.geo_country
--     (one row PER sign-in), NOT device_registry (which overwrites a single country
--     per device and cannot represent two locations in a window). Country-pair +
--     static min-time only; NO coordinates / great-circle distance.
-- On a transition INTO level='high', revoke the user's live sessions (CAE risk
-- spike): app_notify('session_revoke', …). Self-data writes go to user_risk for the
-- one user. Errors: BZ103.
CREATE OR REPLACE FUNCTION compute_user_risk(p_user_id bigint)
RETURNS void AS $$
DECLARE
  v_email          text;
  v_fail_count     int;
  v_impossible     boolean := FALSE;
  v_signals        jsonb := '[]'::jsonb;
  v_score          smallint := 0;
  v_level          text := 'none';
  v_prev_level     text;
  -- Minimum minutes between two countries to be physically plausible. A coarse,
  -- honest floor (no GPS, no great-circle): any distinct-country pair closer than
  -- this threshold is flagged. ponytail: per-pair table when needed.
  v_min_minutes    int := 120;
BEGIN
  SELECT email INTO v_email FROM public.users WHERE id = p_user_id;
  IF v_email IS NULL THEN
    RAISE EXCEPTION 'user % not found', p_user_id
      USING ERRCODE = 'BZ103',
            HINT = 'compute_user_risk requires an existing user id';
  END IF;

  -- Failed-auth velocity over the trailing 24h window (R1: scoped by target_username = email).
  SELECT count(*) INTO v_fail_count
    FROM public.auth_attempts
   WHERE target_username = v_email
     AND outcome = 'failure'
     AND occurred_at > now() - interval '24 hours';

  IF v_fail_count >= 6 THEN
    v_signals := v_signals || '["failed_auth_velocity"]'::jsonb;
    v_score   := v_score + 50;
  END IF;

  -- Impossible-travel: any consecutive success pair (by time) from distinct countries
  -- whose gap < v_min_minutes. No false-lockout: same-country pairs are never flagged;
  -- the threshold is conservative (120 min) so a legit VPN/proxy trip doesn't trigger.
  SELECT TRUE INTO v_impossible
  FROM (
    SELECT geo_country,
           occurred_at,
           lag(geo_country) OVER (ORDER BY occurred_at) AS prev_country,
           lag(occurred_at) OVER (ORDER BY occurred_at) AS prev_at
      FROM public.auth_attempts
     WHERE target_username = v_email
       AND outcome = 'success'
       AND geo_country IS NOT NULL
       AND occurred_at > now() - interval '24 hours'
  ) pairs
  WHERE prev_country IS NOT NULL
    AND geo_country <> prev_country
    AND EXTRACT(EPOCH FROM (occurred_at - prev_at)) / 60.0 < v_min_minutes
  LIMIT 1;

  IF v_impossible THEN
    v_signals := v_signals || '["impossible_travel"]'::jsonb;
    v_score   := v_score + 60;
  END IF;

  -- Cap at 100 (user_risk.score CHECK constraint).
  v_score := LEAST(v_score, 100);

  IF    v_score >= 90 THEN v_level := 'high';
  ELSIF v_score >= 60 THEN v_level := 'medium';
  ELSIF v_score >= 30 THEN v_level := 'low';
  ELSE                      v_level := 'none';
  END IF;

  -- Capture previous level for the CAE spike check (NULL → no prior row).
  SELECT level INTO v_prev_level FROM public.user_risk WHERE user_id = p_user_id;

  -- R2/R3: upsert scoped to p_user_id (no request-supplied id).
  INSERT INTO public.user_risk (user_id, score, level, signals, updated_at)
  VALUES (p_user_id, v_score, v_level, v_signals, now())
  ON CONFLICT (user_id)
  DO UPDATE SET score      = EXCLUDED.score,
                level      = EXCLUDED.level,
                signals    = EXCLUDED.signals,
                updated_at = EXCLUDED.updated_at;

  -- CAE risk spike: transition INTO high revokes the user's live sessions.
  IF v_level = 'high' AND coalesce(v_prev_level, 'none') <> 'high' THEN
    PERFORM app_notify('session_revoke',
      json_build_object('user_id', p_user_id, 'scope', 'all',
                        'not_before', now(), 'reason', 'risk_spike')::text);
  END IF;
END;
$$ LANGUAGE plpgsql VOLATILE;
