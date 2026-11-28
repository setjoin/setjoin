-- hr_request_create: HR consumer create wrapper (hr.leave | hr.expense).
-- Validates the form (BZ124/BZ126), builds the match context, routes through the
-- shared engine seam (match → resolve → create), records expense receipts.
-- Returns the request id; NULL when no policy matched (Go maps to 422) or a
-- skip policy won (audited, no request row).
-- ponytail: apply-on-approve is record-keeping only (no HRIS/balance write) —
-- see plan Open Decisions (retired-docs:superpowers/plans/archive/2026-07-08-hr-approval-templates.md).
CREATE OR REPLACE FUNCTION hr_request_create(
  p_requester bigint,
  p_kind      text,      -- 'hr.leave' | 'hr.expense'
  p_form      jsonb
) RETURNS bigint AS $$
DECLARE
  v_ctx      jsonb;
  v_subject  text;
  v_match    record;
  v_resolved record;
  v_id       bigint;
  v_ttl      int;
  v_start    date;
  v_end      date;
  v_days     int;
  v_currency text;
  v_total    bigint;
  v_sum      bigint := 0;
  v_item     jsonb;
  v_n        int := 0;
BEGIN
  IF p_kind = 'hr.leave' THEN
    IF p_form->>'leave_type' IS NULL OR p_form->>'leave_type' NOT IN
       ('annual','sick','personal','marriage','maternity','paternity','bereavement','other')
    THEN RAISE EXCEPTION 'invalid leave_type' USING ERRCODE='BZ124', HINT='{"type":"hr_invalid_form","field":"leave_type"}'; END IF;

    BEGIN
      v_start := (p_form->>'start_date')::date;
      v_end   := (p_form->>'end_date')::date;
    EXCEPTION WHEN others THEN
      RAISE EXCEPTION 'invalid start_date/end_date' USING ERRCODE='BZ124', HINT='{"type":"hr_invalid_form","field":"start_date"}';
    END;
    IF v_start IS NULL OR v_end IS NULL OR v_end < v_start THEN
      RAISE EXCEPTION 'end_date before start_date' USING ERRCODE='BZ124', HINT='{"type":"hr_invalid_form","field":"end_date"}';
    END IF;
    v_days := v_end - v_start + 1;
    IF (p_form->>'days') IS NULL OR (p_form->>'days')::int IS DISTINCT FROM v_days OR v_days > 366
      THEN RAISE EXCEPTION 'days does not match date range' USING ERRCODE='BZ124', HINT='{"type":"hr_invalid_form","field":"days"}'; END IF;
    IF length(trim(coalesce(p_form->>'reason',''))) NOT BETWEEN 1 AND 2000
      THEN RAISE EXCEPTION 'reason required (1..2000 chars)' USING ERRCODE='BZ124', HINT='{"type":"hr_invalid_form","field":"reason"}'; END IF;

    v_ctx := jsonb_build_object('leave_type', p_form->>'leave_type',
      'long_leave', v_days > coalesce((SELECT (value)::int FROM system_config WHERE key='approval.hr_long_leave_days'), 3));
    v_subject := format('Leave: %s %s → %s (%sd)', p_form->>'leave_type', p_form->>'start_date', p_form->>'end_date', v_days);

  ELSIF p_kind = 'hr.expense' THEN
    v_currency := p_form->>'currency';
    IF v_currency IS NULL OR v_currency !~ '^[A-Z]{3}$'
      THEN RAISE EXCEPTION 'invalid currency' USING ERRCODE='BZ124', HINT='{"type":"hr_invalid_form","field":"currency"}'; END IF;

    IF (p_form->>'total_cents') IS NULL THEN
      RAISE EXCEPTION 'total_cents required' USING ERRCODE='BZ124', HINT='{"type":"hr_invalid_form","field":"total_cents"}';
    END IF;
    v_total := (p_form->>'total_cents')::bigint;

    IF jsonb_typeof(coalesce(p_form->'line_items', 'null'::jsonb)) IS DISTINCT FROM 'array' THEN
      RAISE EXCEPTION 'line_items must be an array' USING ERRCODE='BZ124', HINT='{"type":"hr_invalid_form","field":"line_items"}';
    END IF;

    FOR v_item IN SELECT value FROM jsonb_array_elements(p_form->'line_items') LOOP
      v_n := v_n + 1;
      IF (v_item->>'amount_cents') IS NULL OR (v_item->>'amount_cents')::bigint <= 0
         OR length(trim(coalesce(v_item->>'description',''))) NOT BETWEEN 1 AND 500
         OR v_item->>'category' NOT IN ('travel','meals','lodging','supplies','other')
        THEN RAISE EXCEPTION 'invalid line item %', v_n USING ERRCODE='BZ124', HINT='{"type":"hr_invalid_form","field":"line_items"}'; END IF;
      v_sum := v_sum + (v_item->>'amount_cents')::bigint;
      IF v_item ? 'receipt_sha256' AND NOT EXISTS (SELECT 1 FROM blobs WHERE sha256 = v_item->>'receipt_sha256')
        THEN RAISE EXCEPTION 'receipt blob not found (line %)', v_n USING ERRCODE='BZ126', HINT='{"type":"hr_receipt_missing"}'; END IF;
    END LOOP;
    IF v_n NOT BETWEEN 1 AND 50 OR v_total IS DISTINCT FROM v_sum OR v_total <= 0
      THEN RAISE EXCEPTION 'line items / total mismatch' USING ERRCODE='BZ124', HINT='{"type":"hr_invalid_form","field":"total_cents"}'; END IF;

    v_ctx := jsonb_build_object('currency', v_currency,
      'over_tier', v_total > coalesce((SELECT (value)::bigint FROM system_config WHERE key='approval.hr_expense_tier_cents'), 500000));
    v_subject := format('Expense: %s %s (%s items)', v_currency, to_char(v_total / 100.0, 'FM999999990.00'), v_n);

  ELSE
    RAISE EXCEPTION 'unknown hr kind' USING ERRCODE='BZ124', HINT='{"type":"hr_invalid_form","field":"kind"}';
  END IF;

  SELECT * INTO v_match FROM approval_match_policies(p_kind, v_ctx);
  IF NOT v_match.required THEN RETURN NULL; END IF;   -- no policy demands approval (Go maps to 422)

  SELECT * INTO v_resolved FROM approval_resolve_approver(p_requester, v_match.approver_spec);
  IF v_resolved.skip THEN
    PERFORM audit_write(p_requester, 'approval_skipped', 'approval_request', NULL, NULL,
      jsonb_build_object('consumer_type', p_kind), NULL, NULL, 'core');
    RETURN NULL;
  END IF;

  v_ttl := coalesce((SELECT (value)::int FROM system_config WHERE key='approval.request_ttl_minutes'), 2880);
  v_id  := approval_request_create(p_kind, p_requester, v_subject, p_form,
             v_match.winner_policy_id, v_resolved.kind, v_resolved.ref, v_ttl);

  IF p_kind = 'hr.expense' THEN
    INSERT INTO hr_expense_receipts (approval_request_id, line_index, blob_sha256, filename)
    SELECT v_id, (ord - 1)::int, item->>'receipt_sha256',
           coalesce(item->>'receipt_filename', 'receipt-' || ord)
      FROM jsonb_array_elements(p_form->'line_items') WITH ORDINALITY AS t(item, ord)
     WHERE item ? 'receipt_sha256';
  END IF;
  RETURN v_id;
END;
$$ LANGUAGE plpgsql VOLATILE SECURITY INVOKER;
