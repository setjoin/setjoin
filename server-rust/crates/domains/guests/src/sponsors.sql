SELECT COALESCE(jsonb_agg(jsonb_build_object('id',s.id,'email',s.email,'displayName',s.display_name) ORDER BY lower(s.display_name),s.id),'[]'::jsonb)::text FROM (
SELECT u.id, u.email, u.display_name
		  FROM users u
		 WHERE u.enabled
		   AND NOT is_guest_account(u.id)
		   AND guest_admin_can_transfer_to($1,$2,u.id)
		   AND ($3='' OR u.email ILIKE '%'||$3||'%' OR u.display_name ILIKE '%'||$3||'%')
		 ORDER BY lower(u.display_name), u.id
		 LIMIT 50
) AS s
