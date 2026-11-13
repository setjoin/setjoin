-- JMAP Identity/* reducers (RFC 8620 §4)

-- jmap_identity_set_create: no-op — identities cannot be created via JMAP.
CREATE OR REPLACE FUNCTION jmap_identity_set_create(
    p_mailbox_id BIGINT,
    p_creates    JSONB
) RETURNS JSONB AS $$
BEGIN
    RETURN jsonb_build_object(
        'notCreated', (SELECT jsonb_object_agg(key,
            jsonb_build_object('type', 'forbidden', 'description', 'Identities cannot be created via JMAP'))
            FROM jsonb_object_keys(p_creates) AS key)
    );
END;
$$ LANGUAGE plpgsql;

-- jmap_identity_set_update: update per-identity properties (signature, replyTo, displayName).
-- p_updates is a JSONB object keyed by identity id:
--   { "a123": { "signature": "...", "replyTo": "bcc@co.com", "name": "Display Name" } }
-- Identity IDs starting with "a" are aliases; "i" are primary user identities.
CREATE OR REPLACE FUNCTION jmap_identity_set_update(
    p_mailbox_id BIGINT,
    p_updates    JSONB
) RETURNS JSONB AS $$
DECLARE
    v_updated     JSONB := '{}'::JSONB;
    v_notUpdated  JSONB := '{}'::JSONB;
    v_key         TEXT;
    v_update      JSONB;
    v_alias_id    BIGINT;
    v_new_sig     TEXT;
    v_new_reply   TEXT;
    v_new_name    TEXT;
BEGIN
    FOR v_key, v_update IN SELECT * FROM jsonb_each(p_updates)
    LOOP
        BEGIN
            -- Only alias identities can be updated (keys starting with "a")
            IF v_key NOT LIKE 'a%' THEN
                v_notUpdated := v_notUpdated || jsonb_build_object(v_key,
                    jsonb_build_object('type', 'forbidden',
                      'description', 'Only alias identities can be updated'));
                CONTINUE;
            END IF;

            v_alias_id := substring(v_key FROM 2)::BIGINT;
            IF v_alias_id IS NULL THEN
                v_notUpdated := v_notUpdated || jsonb_build_object(v_key,
                    jsonb_build_object('type', 'invalidArguments',
                      'description', 'Invalid identity id'));
                CONTINUE;
            END IF;

            v_new_sig   := v_update->>'signature';
            v_new_reply := v_update->>'replyTo';
            v_new_name  := v_update->>'name';

            -- TOCTOU fix: ownership check embedded in UPDATE WHERE clause.
            -- This prevents a concurrent transaction from changing aliases.mailbox_id
            -- between a separate EXISTS check and the UPDATE.
            UPDATE aliases SET
                signature    = COALESCE(v_new_sig, signature),
                reply_to     = COALESCE(v_new_reply, reply_to),
                display_name = COALESCE(NULLIF(v_new_name, ''), display_name),
                updated_at   = now()
            WHERE id = v_alias_id
              AND EXISTS (
                -- p_mailbox_id is the caller's primary mailbox id (parseAccountID); the alias
                -- must belong to THAT mailbox, so scope by m.id, not the divergent user_id.
                SELECT 1 FROM mailboxes m
                WHERE m.id = aliases.mailbox_id AND m.id = p_mailbox_id
              );

            IF NOT FOUND THEN
                v_notUpdated := v_notUpdated || jsonb_build_object(v_key,
                    jsonb_build_object('type', 'notFound',
                      'description', 'Alias not found or not owned by this account'));
                CONTINUE;
            END IF;

            v_updated := v_updated || jsonb_build_object(v_key, jsonb_build_object('id', v_key));
        EXCEPTION WHEN OTHERS THEN
            v_notUpdated := v_notUpdated || jsonb_build_object(v_key,
                jsonb_build_object('type', 'serverFail', 'description', SQLERRM));
        END;
    END LOOP;

    -- State bump for Identity/changes. The Identity family has no jmap_*_state
    -- counter (unlike email/mailbox/tag); Identity/changes (internal/jmap/identity.go)
    -- derives its delta token from users.updated_at of the authenticated user.
    -- p_mailbox_id is that user's PRIMARY mailbox, so bump the owner's
    -- users.updated_at in-txn whenever an alias identity actually changed —
    -- otherwise an alias edit (signature / replyTo / displayName) never advances
    -- the token and Identity/changes can never report the delta. Guarded on a real
    -- mutation so no-op / notFound calls leave the token untouched.
    IF v_updated <> '{}'::JSONB THEN
        UPDATE users SET updated_at = now()
        WHERE id = (SELECT user_id FROM mailboxes WHERE id = p_mailbox_id);
    END IF;

    RETURN jsonb_build_object(
        'updated', v_updated,
        'notUpdated', v_notUpdated
    );
END;
$$ LANGUAGE plpgsql;

-- jmap_identity_set_destroy: no-op — identities cannot be deleted via JMAP.
CREATE OR REPLACE FUNCTION jmap_identity_set_destroy(
    p_mailbox_id BIGINT,
    p_ids        BIGINT[]
) RETURNS JSONB AS $$
BEGIN
    RETURN jsonb_build_object(
        'notDestroyed', (SELECT jsonb_object_agg(id::TEXT,
            jsonb_build_object('type', 'forbidden', 'description', 'Identities cannot be deleted via JMAP'))
            FROM unnest(p_ids) AS id)
    );
END;
$$ LANGUAGE plpgsql;
