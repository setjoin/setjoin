-- #420: frozen Go refreshOnce's transaction, worker-only global feed authority.
CREATE OR REPLACE FUNCTION rust_threat_feed_replace(p_cidrs text[])
RETURNS void LANGUAGE plpgsql AS $$
DECLARE v_cidr text;
BEGIN
    IF cardinality(p_cidrs) = 0 THEN RETURN; END IF;
    DELETE FROM threat_feed_blocks;
    FOREACH v_cidr IN ARRAY p_cidrs LOOP
        INSERT INTO threat_feed_blocks(cidr,source,added_at)
        VALUES(v_cidr::inet,'spamhaus-drop',date_trunc('second',now()))
        ON CONFLICT(cidr) DO NOTHING;
    END LOOP;
END;
$$;
REVOKE ALL ON FUNCTION rust_threat_feed_replace(text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION rust_threat_feed_replace(text[]) TO setjoin_worker;
