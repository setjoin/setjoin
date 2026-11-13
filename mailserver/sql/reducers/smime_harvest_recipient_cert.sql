-- smime_harvest_recipient_cert.sql — SP1 Phase-2 harvest UPSERT (logic where the data is).
--
-- Called by the inbound delivery harvest hook (internal/smtp/smime_harvest.go) when an
-- inbound message grades S/MIME-`valid`: stores the verified signer's leaf cert for the
-- RECEIVING user so future encrypted replies can target it.
--
-- One UPSERT into recipient_smime_certs keyed on the table's
-- UNIQUE(owner_user_id, email, fingerprint). On conflict it bumps last_seen only —
-- first_seen is preserved (the same cert seen across 50 messages stays one row, with
-- a "first seen" anchor and a "last seen" recency). Email is lower-cased + trimmed on
-- write so address-keyed resolution is case-insensitive. source is fixed to 'harvested'
-- (the imported path uses a separate admin reducer). Returns the inserted-or-existing id.
--
-- This is a write reducer but NOT a jmap_*_state mutator: recipient_smime_certs is not a
-- JMAP-synced collection (cert store, not a mail object), so no state bump / pg_notify.
-- owner_user_id is set by the CALLER from the resolved receiving-user id (never req.*).

CREATE OR REPLACE FUNCTION smime_harvest_recipient_cert(
    p_owner_user_id BIGINT,
    p_email         TEXT,
    p_cert_pem      TEXT,
    p_fingerprint   TEXT,
    p_not_before    TIMESTAMPTZ,
    p_not_after     TIMESTAMPTZ
) RETURNS BIGINT
LANGUAGE plpgsql AS $$
DECLARE
    v_id BIGINT;
BEGIN
    INSERT INTO recipient_smime_certs
        (owner_user_id, email, cert_pem, fingerprint,
         not_before, not_after, source, first_seen, last_seen)
    VALUES
        (p_owner_user_id, lower(btrim(p_email)), p_cert_pem, p_fingerprint,
         p_not_before, p_not_after, 'harvested', now(), now())
    ON CONFLICT (owner_user_id, email, fingerprint) DO UPDATE
        SET last_seen = now()
    RETURNING id INTO v_id;

    RETURN v_id;
END;
$$;
