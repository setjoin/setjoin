-- link_protect_check_and_audit.sql: C — verdict rules + audit-before-redirect.
-- Single source of truth for the click verdict (all-errors passthrough, strict_mode
-- unknown→malicious) AND the audit insert, in ONE transaction. Fixes the TOCTOU in
-- handler.go where audit was best-effort *after* the redirect decision, so a user
-- could be sent to a malicious/unknown link with no durable audit record. Go keeps
-- only the HMAC verify and the third-party scanner HTTP calls; on a reducer error
-- the gateway now FAILS CLOSED to a warn interstitial (no redirect without audit).
--
-- Ownership (R1/R3): the audit FKs (message_id, mailbox_id) are taken from the
-- VERIFIED token claims passed by the gateway, never from request query input.
-- url_hash is computed in SQL (encode(digest(...,'sha256'),'hex'); pgcrypto is in
-- the baseline) so the audited hash and the decision are produced together.
--
-- message_id resolution (logic where the data is): p_rfc_message_id is the RFC
-- Message-ID *header* string from the token claim — NOT the numeric DB id. The
-- numeric link_protect_audit.message_id FK is resolved here, mailbox-scoped
-- (messages_message_id_idx), against the VERIFIED mailbox: a message can only
-- match if it belongs to p_mailbox_id (R1). No row matches (message deleted, or
-- the id never landed in this mailbox) → message_id is left NULL; the audit row
-- still records mailbox_id / verdict / url_hash / client_ip. This replaces the
-- old Go strconv.ParseInt(claims.MessageID) which produced 0 for every real
-- (non-numeric) RFC id, silently severing the audit→message linkage.
CREATE OR REPLACE FUNCTION link_protect_check_and_audit(
    p_url            TEXT,
    p_rfc_message_id TEXT,
    p_mailbox_id     BIGINT,
    p_base_verdict   TEXT,
    p_scanner_json   JSONB,
    p_all_errors     BOOLEAN,
    p_strict_mode    BOOLEAN,
    p_client_ip      TEXT
) RETURNS JSONB AS $$
DECLARE
    v_verdict    TEXT;
    v_scanner    TEXT := 'pipeline';
    v_name       TEXT;
    v_val        TEXT;
    v_message_id BIGINT;
BEGIN
    IF p_base_verdict NOT IN ('safe','malicious','unknown') THEN
        RAISE EXCEPTION 'Invalid base verdict'
            USING ERRCODE='BZ055', HINT=jsonb_build_object('type','invalid_verdict','verdict',p_base_verdict)::text;
    END IF;

    -- Rule 1: third-party outage → passthrough (never block on outage).
    IF COALESCE(p_all_errors,FALSE) THEN
        v_verdict := 'unknown';
    -- Rule 2: strict_mode upgrades unknown → malicious.
    ELSIF p_base_verdict='unknown' AND COALESCE(p_strict_mode,FALSE) THEN
        v_verdict := 'malicious';
    ELSE
        v_verdict := p_base_verdict;
    END IF;

    -- Attribute a scanner name: first whose result equals the final verdict, else any, else 'pipeline'.
    IF p_scanner_json IS NOT NULL AND p_scanner_json <> '{}'::jsonb THEN
        FOR v_name, v_val IN SELECT key, value FROM jsonb_each_text(p_scanner_json) LOOP
            IF v_val = v_verdict THEN v_scanner := v_name; EXIT; END IF;
        END LOOP;
        IF v_scanner = 'pipeline' THEN
            SELECT key INTO v_scanner FROM jsonb_each_text(p_scanner_json) LIMIT 1;
        END IF;
    END IF;

    -- Resolve the RFC Message-ID header to the numeric messages.id, scoped to the
    -- VERIFIED mailbox (R1). NULL when no row matches (deleted / cross-mailbox).
    IF p_rfc_message_id IS NOT NULL AND p_rfc_message_id <> '' THEN
        SELECT id INTO v_message_id
        FROM messages
        WHERE message_id = p_rfc_message_id AND mailbox_id = p_mailbox_id
        LIMIT 1;
    END IF;

    -- Rule 4: record audit BEFORE returning (same txn → durable before redirect).
    INSERT INTO link_protect_audit (url_hash, verdict, scanner, message_id, mailbox_id, client_ip)
    VALUES (encode(digest(p_url,'sha256'),'hex'), v_verdict, v_scanner,
            v_message_id, p_mailbox_id, p_client_ip);

    RETURN jsonb_build_object('verdict', v_verdict, 'scanner', v_scanner);
END;
$$ LANGUAGE plpgsql;
