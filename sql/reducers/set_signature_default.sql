-- set_signature_default(): make one signature the default for new and/or reply
-- mail, clearing the same role from the caller's other signatures so at most one
-- signature holds each role. p_role is 'new' | 'reply' | 'both' | 'none'.
--
-- Ownership (R3): every statement is scoped to p_user_id; a signature the caller
-- does not own is rejected (BZ071) before any write. user_signatures is not a
-- JMAP-stateful object, so no jmap_*_state bump is required.
CREATE OR REPLACE FUNCTION set_signature_default(
    p_user_id   BIGINT,
    p_sig_id    BIGINT,
    p_role      TEXT DEFAULT 'new'
) RETURNS VOID AS $$
DECLARE
    v_owned BOOL;
BEGIN
    IF p_role NOT IN ('new', 'reply', 'both', 'none') THEN
        RAISE EXCEPTION 'invalid signature role: %', p_role
            USING ERRCODE = 'BZ070',
                  HINT = '{"type":"invalid_signature_role"}';
    END IF;

    SELECT EXISTS (
        SELECT 1 FROM user_signatures
        WHERE id = p_sig_id AND user_id = p_user_id
    ) INTO v_owned;
    IF NOT v_owned THEN
        RAISE EXCEPTION 'signature % not owned by user %', p_sig_id, p_user_id
            USING ERRCODE = 'BZ071',
                  HINT = '{"type":"signature_not_owned"}';
    END IF;

    -- Clear the affected role(s) from this user's OTHER signatures (R3: scoped to
    -- p_user_id). 'both' degrades to the role it keeps; the exact role clears.
    IF p_role IN ('new', 'both') THEN
        UPDATE user_signatures
           SET default_for = CASE WHEN default_for = 'both' THEN 'reply'
                                  WHEN default_for = 'new'  THEN 'none'
                                  ELSE default_for END,
               updated_at = now()
         WHERE user_id = p_user_id AND id <> p_sig_id;
    END IF;
    IF p_role IN ('reply', 'both') THEN
        UPDATE user_signatures
           SET default_for = CASE WHEN default_for = 'both' THEN 'new'
                                  WHEN default_for = 'reply' THEN 'none'
                                  ELSE default_for END,
               updated_at = now()
         WHERE user_id = p_user_id AND id <> p_sig_id;
    END IF;

    UPDATE user_signatures
       SET default_for = p_role, updated_at = now()
     WHERE id = p_sig_id AND user_id = p_user_id;
END;
$$ LANGUAGE plpgsql;
