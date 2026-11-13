-- deliver_json.sql: thin jsonb-keyed wrapper over deliver(). The live Go inbound
-- path and the group-moderation replay both package the deliver() args as a jsonb
-- object keyed by parameter name (see deliverParamNames in internal/smtp/inbound.go).
-- This unpacks exactly those 32 keys positionally so there is ONE place that knows
-- the key->position mapping, instead of a hand-numbered `SELECT deliver($1..$32)`
-- string in Go and a duplicate 32-line unpack in group_moderation_approval_decide.
-- Keys 33-35 of deliver() (p_is_encrypted / p_source_message_id / p_source_received_at)
-- are intentionally omitted and left to their DEFAULTs, matching today's behavior.
CREATE OR REPLACE FUNCTION deliver_json(p_params JSONB) RETURNS BIGINT
LANGUAGE sql AS $$
  SELECT deliver(
    p_params->>'p_raw_ref',
    p_params->>'p_message_id',
    p_params->>'p_from_addr',
    p_params->>'p_from_name',
    p_params->>'p_rcpt_addr',
    p_params->'p_to_addrs',
    p_params->'p_cc_addrs',
    p_params->'p_bcc_addrs',
    p_params->>'p_subject',
    p_params->>'p_in_reply_to',
    p_params->>'p_references_hdr',
    p_params->>'p_body_text',
    p_params->>'p_body_html',
    (p_params->>'p_size_bytes')::bigint,
    (p_params->>'p_has_attachments')::boolean,
    (p_params->>'p_sent_at')::timestamptz,
    p_params->>'p_spf_result',
    p_params->>'p_dkim_result',
    p_params->>'p_dmarc_result',
    (p_params->>'p_spam_score')::real,
    p_params->'p_spam_headers',
    p_params->>'p_vote_response',
    p_params->>'p_crypto_type',
    (p_params->>'p_is_external')::boolean,
    p_params->>'p_sender_display_name',
    (p_params->>'p_is_name_spoof')::boolean,
    (p_params->>'p_depth')::int,
    p_params->>'p_list_id',
    p_params->>'p_smime_status',
    p_params->>'p_smime_signer_email',
    p_params->>'p_smime_signer_cn',
    p_params->>'p_smime_issuer_cn'
  );
$$;
