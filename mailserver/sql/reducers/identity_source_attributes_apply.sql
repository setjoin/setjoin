-- Apply the governed profile matrix for exactly one active provisioning link.
-- An existing local or other-source authority is never overwritten.
DROP FUNCTION IF EXISTS identity_source_attributes_apply(bigint,bigint,bigint,jsonb);
CREATE OR REPLACE FUNCTION identity_source_attributes_apply(
    p_source_id BIGINT,
    p_expected_generation BIGINT,
    p_link_id BIGINT,
    p_batch_id UUID,
    p_object_key TEXT,
    p_payload JSONB
) RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_user_id BIGINT;
    v_field TEXT;
    v_value TEXT;
    v_applied INTEGER := 0;
    v_department_id BIGINT;
BEGIN
    IF jsonb_typeof(p_payload) <> 'object' THEN
        RAISE EXCEPTION 'profile payload must be an object'
            USING ERRCODE='BZ228';
    END IF;
    SELECT l.user_id INTO v_user_id
      FROM user_identity_links l
      JOIN identity_sources s ON s.id=l.source_id
     WHERE l.id=p_link_id AND l.source_id=p_source_id
       AND l.state='active' AND 'provision'=ANY(l.purposes)
       AND s.generation=p_expected_generation
       AND s.state='active'
       AND EXISTS (
           SELECT 1
             FROM identity_source_inbox i
            WHERE i.source_id=p_source_id
              AND i.batch_id=p_batch_id
              AND i.object_key=p_object_key
              AND i.source_generation=p_expected_generation
              AND i.state='pending'
       )
     FOR UPDATE OF l,s;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'source profile authority is stale'
            USING ERRCODE='BZ229',
                  HINT='{"type":"identity_generation_stale"}';
    END IF;

    IF NULLIF(p_payload->>'department','') IS NOT NULL THEN
        INSERT INTO departments(name,path,ldap_ou)
        VALUES (
            p_payload->>'department',
            p_payload->>'department',
            p_payload->>'department'
        )
        ON CONFLICT(path) DO UPDATE SET
            name=EXCLUDED.name,
            ldap_ou=EXCLUDED.ldap_ou
        RETURNING id INTO v_department_id;
    END IF;

    FOREACH v_field IN ARRAY ARRAY[
        'email','display_name','first_name','last_name',
        'job_title','phone','department_id','enabled'
    ] LOOP
        v_value := CASE v_field
            WHEN 'email' THEN NULLIF(p_payload->>'email','')
            WHEN 'display_name' THEN NULLIF(p_payload->>'displayName','')
            WHEN 'first_name' THEN p_payload->>'firstName'
            WHEN 'last_name' THEN p_payload->>'lastName'
            WHEN 'job_title' THEN p_payload->>'jobTitle'
            WHEN 'phone' THEN p_payload->>'phone'
            WHEN 'department_id' THEN v_department_id::text
            WHEN 'enabled' THEN p_payload->>'enabled'
        END;
        IF v_value IS NULL AND NOT COALESCE((p_payload->>'replaceAll')::boolean,false) THEN
            CONTINUE;
        END IF;

        INSERT INTO identity_attribute_authority(
            user_id,field,authority_kind,source_id,link_id,
            source_version,value_digest
        ) VALUES (
            v_user_id,v_field,'source',p_source_id,p_link_id,
            p_expected_generation::text,digest(COALESCE(v_value,''),'sha256')
        )
        ON CONFLICT(user_id,field) DO UPDATE
          SET source_version=EXCLUDED.source_version,
              value_digest=EXCLUDED.value_digest,
              generation=identity_attribute_authority.generation+1,
              updated_at=statement_timestamp()
        WHERE identity_attribute_authority.authority_kind='source'
          AND identity_attribute_authority.source_id=p_source_id
          AND identity_attribute_authority.link_id=p_link_id;
        IF FOUND THEN
            v_applied := v_applied + 1;
        END IF;
    END LOOP;

    UPDATE users u SET
        email=CASE WHEN identity_field_owned(v_user_id,'email',p_source_id,p_link_id)
                   AND NULLIF(p_payload->>'email','') IS NOT NULL
                   THEN lower(btrim(p_payload->>'email')) ELSE u.email END,
        display_name=CASE WHEN identity_field_owned(v_user_id,'display_name',p_source_id,p_link_id)
                   AND NULLIF(p_payload->>'displayName','') IS NOT NULL
                   THEN p_payload->>'displayName' ELSE u.display_name END,
        first_name=CASE WHEN identity_field_owned(v_user_id,'first_name',p_source_id,p_link_id)
                   AND (p_payload ? 'firstName')
                   THEN NULLIF(p_payload->>'firstName','') ELSE u.first_name END,
        last_name=CASE WHEN identity_field_owned(v_user_id,'last_name',p_source_id,p_link_id)
                   AND (p_payload ? 'lastName')
                   THEN NULLIF(p_payload->>'lastName','') ELSE u.last_name END,
        job_title=CASE WHEN identity_field_owned(v_user_id,'job_title',p_source_id,p_link_id)
                   AND (p_payload ? 'jobTitle')
                   THEN NULLIF(p_payload->>'jobTitle','') ELSE u.job_title END,
        phone=CASE WHEN identity_field_owned(v_user_id,'phone',p_source_id,p_link_id)
                   AND (p_payload ? 'phone')
                   THEN NULLIF(p_payload->>'phone','') ELSE u.phone END,
        department_id=CASE WHEN identity_field_owned(v_user_id,'department_id',p_source_id,p_link_id)
                   AND (p_payload ? 'department')
                   THEN v_department_id ELSE u.department_id END,
        enabled=CASE WHEN identity_field_owned(v_user_id,'enabled',p_source_id,p_link_id)
                   AND (p_payload ? 'enabled')
                   THEN (p_payload->>'enabled')::boolean ELSE u.enabled END,
        updated_at=statement_timestamp()
    WHERE u.id=v_user_id;

    RETURN jsonb_build_object('userId',v_user_id::text,'appliedFields',v_applied);
END;
$$;

SELECT apply_worker_ownership(
    'identity_source_attributes_apply(bigint,bigint,bigint,uuid,text,jsonb)'::regprocedure
);
