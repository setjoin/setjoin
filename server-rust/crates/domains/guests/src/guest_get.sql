SELECT result::text FROM (
SELECT jsonb_build_object(
		  'id',g.user_id,'displayName',u.display_name,'invitedEmail',g.invited_email,
		  'invitedBy',g.invited_by,'invitedByEmail',g.invited_by_email,
		  'status',g.status,'effectiveStatus',CASE WHEN g.expires_at < now() THEN 'expired' ELSE g.status END,
		  'expiresAt',g.expires_at,'sponsorUserId',g.sponsor_user_id,
		  'sponsorDisplayName',s.display_name,
		  'sponsorNeedsReview',(s.id IS NULL OR NOT s.enabled OR is_guest_account(s.id)),
		  'profileId',g.profile_id,'profileName',gp.name,
		  'pendingInvite',(SELECT jsonb_build_object(
		      'inviteId',gi.id::text,'expiresAt',gi.expires_at,'createdAt',gi.created_at,
		      'createdByEmail',CASE WHEN gi.created_by IS NOT NULL
		        AND admin_can_reach($1,gi.created_by) THEN gi.created_by_email ELSE NULL END)
		    FROM guest_invites gi WHERE gi.guest_user_id=g.user_id AND gi.used_at IS NULL
		      AND gi.expires_at > now()
		    ORDER BY gi.created_at DESC LIMIT 1),
		  'inviteHistory',(SELECT COALESCE(jsonb_agg(h.item ORDER BY h.created_at DESC,h.id DESC),'[]'::jsonb)
		    FROM (SELECT gi.id,gi.created_at,jsonb_build_object(
		      'inviteId',gi.id::text,
		      'state',CASE
		        WHEN gi.used_at IS NULL AND gi.expires_at <= now() THEN 'expired'
		        WHEN gi.used_at IS NULL THEN 'pending'
		        WHEN gi.terminal_reason = 'legacy_unknown' THEN 'unknown'
		        ELSE gi.terminal_reason END,
		      'createdAt',gi.created_at,'expiresAt',gi.expires_at,
		      'terminalAt',CASE
		        WHEN gi.used_at IS NULL AND gi.expires_at <= now() THEN gi.expires_at
		        WHEN gi.used_at IS NULL THEN NULL ELSE gi.used_at END,
		      'createdByEmail',CASE WHEN gi.created_by IS NOT NULL
		        AND admin_can_reach($1,gi.created_by) THEN gi.created_by_email ELSE NULL END
		    ) AS item FROM guest_invites gi WHERE gi.guest_user_id=g.user_id
		      ORDER BY gi.created_at DESC,gi.id DESC LIMIT 10) h),
		  'inviteHistoryHasMore',EXISTS(SELECT 1 FROM guest_invites gi
		    WHERE gi.guest_user_id=g.user_id ORDER BY gi.created_at DESC,gi.id DESC OFFSET 10 LIMIT 1),
		  'channelGrantCount',(SELECT count(*) FROM chat_channel_members cm WHERE cm.user_id=g.user_id),
		  'channelGrants',(SELECT COALESCE(jsonb_agg(jsonb_build_object(
		    'channelId',c.id,'kind',c.kind,'name',c.name,'role',cm.role,
		    'canPost',cm.can_post,'historyFloorSeq',cm.history_floor_seq
		  ) ORDER BY c.id),'[]'::jsonb) FROM chat_channel_members cm
		    JOIN chat_channels c ON c.id=cm.channel_id WHERE cm.user_id=g.user_id),
		  'appEntitlements',(SELECT jsonb_object_agg(apps.app,COALESCE(e.enabled,false) ORDER BY apps.app)
		    FROM (VALUES ('mail'),('calendar'),('contacts'),('tasks'),('chat'),('drive'),('meet')) apps(app)
		    LEFT JOIN user_app_entitlements e ON e.user_id=g.user_id AND e.app=apps.app),
		  'createdAt',g.created_at,'updatedAt',g.updated_at
		)
		FROM guest_accounts g JOIN users u ON u.id=g.user_id
		LEFT JOIN users s ON s.id=g.sponsor_user_id
		LEFT JOIN guest_profiles gp ON gp.id=g.profile_id
		WHERE g.user_id=$2
		  AND (guest_admin_can_reach_with_permission($1,g.user_id,'guests.view')
		       OR guest_admin_can_reach_with_permission($1,g.user_id,'guests.manage'))
) AS guests(result)
