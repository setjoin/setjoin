SELECT result::text FROM (
SELECT COALESCE(jsonb_agg(jsonb_build_object(
		  'id',g.user_id,'displayName',u.display_name,'invitedEmail',g.invited_email,
		  'status',g.status,'effectiveStatus',CASE WHEN g.expires_at < now() THEN 'expired' ELSE g.status END,
		  'expiresAt',g.expires_at,'sponsorUserId',g.sponsor_user_id,
		  'sponsorDisplayName',s.display_name,
		  'sponsorNeedsReview',(s.id IS NULL OR NOT s.enabled OR is_guest_account(s.id)),
		  'profileId',g.profile_id,'profileName',gp.name,
		  'pendingInvite',EXISTS(SELECT 1 FROM guest_invites gi
		    WHERE gi.guest_user_id=g.user_id AND gi.used_at IS NULL AND gi.expires_at > now()),
		  'channelGrantCount',(SELECT count(*) FROM chat_channel_members cm WHERE cm.user_id=g.user_id),
		  'createdAt',g.created_at,'updatedAt',g.updated_at
		) ORDER BY lower(u.display_name),g.user_id),'[]'::jsonb)
		FROM guest_accounts g JOIN users u ON u.id=g.user_id
		LEFT JOIN users s ON s.id=g.sponsor_user_id
		LEFT JOIN guest_profiles gp ON gp.id=g.profile_id
		WHERE guest_admin_can_reach_with_permission($1,g.user_id,'guests.view')
		   OR guest_admin_can_reach_with_permission($1,g.user_id,'guests.manage')

) AS guests(result)
