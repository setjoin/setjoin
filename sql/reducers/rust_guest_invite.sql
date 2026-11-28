-- F11 wrappers preserve frozen Go's multi-statement invite transactions.
-- Callers generate entropy in memory and bind ONLY its SHA-256 digest.
-- Metadata validation in the Rust command decoder may reject and roll back all
-- effects before the foundation writes a receipt or commits.
CREATE OR REPLACE FUNCTION rust_guest_invite_prepare(p_creator bigint,p_guest bigint,p_hash text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE AS $$
DECLARE
 v_host bigint; v_guest_expiry timestamptz; v_email text; v_org text;
 v_from text; v_base text; v_raw_ttl text; v_ttl bigint:=7;
 v_expiry timestamptz; v_invite bigint; v_recipient text;
BEGIN
 SELECT value #>> '{}' INTO v_raw_ttl FROM system_config WHERE key='guest.invite_ttl_days';
 IF FOUND THEN
  IF v_raw_ttl IS NULL OR v_raw_ttl !~ '^[+-]?[0-9]+$' THEN RAISE EXCEPTION 'invalid guest invite TTL'; END IF;
  v_ttl:=v_raw_ttl::bigint;
  IF v_ttl<=0 THEN RAISE EXCEPTION 'invalid guest invite TTL'; END IF;
 END IF;
 SELECT ga.host_domain_id,ga.expires_at,creator.email,d.name,
  COALESCE(NULLIF((SELECT value #>> '{}' FROM system_config WHERE key='mail.default_sender'),''),'noreply@'||d.name),
  COALESCE(NULLIF((SELECT value #>> '{}' FROM system_config WHERE key='authserver.public_url'),''),''),ga.invited_email
 INTO STRICT v_host,v_guest_expiry,v_email,v_org,v_from,v_base,v_recipient
 FROM guest_accounts ga JOIN domains d ON d.id=ga.host_domain_id
 JOIN users creator ON creator.id=p_creator WHERE ga.user_id=p_guest;
 -- time.Duration(days)*24*time.Hour wraps signed 64-bit nanoseconds in Go.
 v_expiry:=date_trunc('microseconds',clock_timestamp()+
  ((mod(v_ttl::numeric*86400000000000+9223372036854775808,18446744073709551616)
    -9223372036854775808)/1000000000)::double precision*interval '1 second');
 IF v_guest_expiry IS NOT NULL AND v_guest_expiry<v_expiry THEN v_expiry:=v_guest_expiry; END IF;
 v_invite:=guest_invite_create(p_creator,p_guest,p_hash,v_host,v_email,v_expiry);
 RETURN jsonb_build_object('guest',p_guest,'invite',v_invite,'expires',v_expiry,
  'from',v_from,'org',v_org,'base',v_base,'ttl',v_ttl,'email',v_recipient);
END;
$$;
CREATE OR REPLACE FUNCTION rust_guest_invite(
 p_actor bigint,p_email text,p_name text,p_expiry timestamptz,p_profile bigint,p_hash text
) RETURNS jsonb LANGUAGE plpgsql VOLATILE AS $$
DECLARE v_profile jsonb;v_result jsonb;v_guest bigint;v_days integer;
BEGIN
 IF EXISTS(SELECT 1 FROM guest_invite_domains)
  AND NOT EXISTS(SELECT 1 FROM guest_invite_domains WHERE domain=lower(split_part(p_email,'@',2))) THEN
  RETURN jsonb_build_object('blocked',true);
 END IF;
 IF p_profile IS NOT NULL THEN
  v_profile:=guest_profile_invite_snapshot(p_actor,p_profile);
  IF p_expiry IS NULL THEN
   v_days:=(v_profile->>'defaultExpiryDays')::integer;
   IF v_days IS NOT NULL THEN
    -- Go's UTC duration arithmetic is absolute across DST and wraps int64.
    p_expiry:=clock_timestamp()+
     ((mod(v_days::numeric*86400000000000+9223372036854775808,18446744073709551616)
       -9223372036854775808)/1000000000)::double precision*interval '1 second';
   END IF;
  END IF;
 END IF;
 v_result:=provision_account(p_email=>p_email,p_display_name=>NULLIF(p_name,''),
  p_guest=>true,p_invited_by=>p_actor,p_guest_expires_at=>p_expiry,p_actor=>p_actor);
 v_guest:=(v_result->>'user_id')::bigint;
 IF p_profile IS NOT NULL THEN PERFORM guest_profile_apply(p_actor,v_guest,p_profile); END IF;
 RETURN rust_guest_invite_prepare(p_actor,v_guest,p_hash);
END;
$$;
CREATE OR REPLACE FUNCTION rust_guest_reinvite(p_actor bigint,p_guest bigint,p_expiry timestamptz,p_hash text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE AS $$
BEGIN
 PERFORM guest_set_status(p_actor,p_guest,'reinvite',p_expiry);
 RETURN rust_guest_invite_prepare(p_actor,p_guest,p_hash);
END;
$$;
CREATE OR REPLACE FUNCTION rust_guest_approval_decide(p_request bigint,p_actor bigint,p_decision text,p_comment text,p_hash text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE AS $$
DECLARE v_decision record;v_result jsonb;
BEGIN
 SELECT * INTO STRICT v_decision FROM guest_invite_approval_decide(p_request,p_actor,p_decision,p_comment);
 v_result:=jsonb_build_object('status',v_decision.status);
 IF v_decision.status='applied' THEN
  v_result:=v_result||rust_guest_invite_prepare(v_decision.requester_user_id,v_decision.guest_user_id,p_hash);
 END IF;
 RETURN v_result;
END;
$$;

-- Go's UX reach preflight and rechecked canonical revoke are one transaction.
-- A forbidden marker is decoded as rollback, before receipt/commit.
CREATE OR REPLACE FUNCTION rust_guest_invite_revoke(p_actor bigint,p_guest bigint,p_invite bigint)
RETURNS text LANGUAGE plpgsql VOLATILE AS $$
BEGIN
 IF NOT admin_can_reach(p_actor,p_guest) THEN RETURN 'forbidden'; END IF;
 RETURN guest_invite_revoke(p_actor,p_guest,p_invite);
END;
$$;
