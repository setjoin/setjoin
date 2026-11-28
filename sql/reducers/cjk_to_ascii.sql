-- cjk_to_ascii: transliterate a name to toneless ASCII pinyin.
-- Longest-match surname (2 chars then 1) against cjk_surname, then per-character
-- cjk_pinyin lookup, else pass the character through unchanged (Latin/punct).
-- STABLE (reads cjk_surname/cjk_pinyin tables, so NOT immutable); STRICT so NULL -> NULL.
-- Called only at provision/render time, so STABLE is sufficient.
-- No BZ codes: pure, total function.
CREATE OR REPLACE FUNCTION cjk_to_ascii(p_in TEXT)
RETURNS TEXT LANGUAGE plpgsql STABLE STRICT AS $$
DECLARE
  v_result TEXT := '';
  v_pos    INT  := 1;
  v_len    INT  := length(p_in);
  v_one    TEXT;
  v_two    TEXT;
  v_py     TEXT;
BEGIN
  IF p_in = '' THEN RETURN ''; END IF;

  WHILE v_pos <= v_len LOOP
    -- 2-char compound surname (only meaningful at the start, but cheap to check)
    IF v_pos + 1 <= v_len THEN
      v_two := substr(p_in, v_pos, 2);
      SELECT pinyin INTO v_py FROM cjk_surname WHERE seq = v_two;
      IF v_py IS NOT NULL THEN
        v_result := v_result || v_py;
        v_pos := v_pos + 2;
        CONTINUE;
      END IF;
    END IF;

    v_one := substr(p_in, v_pos, 1);

    -- 1-char surname override
    SELECT pinyin INTO v_py FROM cjk_surname WHERE seq = v_one;
    IF v_py IS NOT NULL THEN
      v_result := v_result || v_py;
      v_pos := v_pos + 1;
      CONTINUE;
    END IF;

    -- per-character pinyin (ascii() returns the Unicode codepoint of the first char)
    SELECT pinyin INTO v_py FROM cjk_pinyin WHERE codepoint = ascii(v_one);
    IF v_py IS NOT NULL THEN
      v_result := v_result || v_py;
    ELSE
      v_result := v_result || v_one;   -- non-CJK passthrough
    END IF;
    v_pos := v_pos + 1;
  END LOOP;

  RETURN v_result;
END;
$$;
