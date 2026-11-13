SELECT coalesce(jsonb_agg(to_jsonb(x)), '[]'::jsonb)::text FROM (
 SELECT mailbox_id,message_id,is_external,is_name_spoof,spam_score,spam_headers,smime_status,smime_signer_email,smime_signer_cn,smime_issuer_cn
 FROM messages WHERE mailbox_id BETWEEN 9348021 AND 9348023 ORDER BY mailbox_id,message_id
) x;
