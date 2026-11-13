package drive

// chatAttachmentLiveSQL returns a boolean SQL expression for an exact version
// content read. Versions outside a chat-bound space pass unchanged. A version
// inside one is readable only when it is linked to at least one live message
// above this caller's immutable membership history floor. This is both Chat
// A2's soft-delete revocation and Guest G2's remembered-version-id backstop:
// derived membership in the channel space is necessary but not sufficient.
// The bytes+rows remain retained for A4 eDiscovery
// (deleted-for-members != purged, the same posture as A1's body retention) —
// the eDiscovery worker pool queries drive_file_versions/chat_message_
// attachments directly on the BYPASSRLS pool and never routes through this
// Go predicate, so it is unaffected.
func chatAttachmentLiveSQL(versionExpr, userExpr string) string {
	return `(
		NOT EXISTS (
			SELECT 1 FROM drive_file_versions cv
			  JOIN drive_spaces cs ON cs.id = cv.space_id
			 WHERE cv.id = ` + versionExpr + ` AND cs.chat_channel_id IS NOT NULL
		)
		OR EXISTS (
			SELECT 1 FROM chat_message_attachments cma
			  JOIN chat_messages msg ON msg.id = cma.message_id
			  JOIN chat_channel_members hcm
			    ON hcm.channel_id = msg.channel_id AND hcm.user_id = ` + userExpr + `
			 WHERE cma.version_id = ` + versionExpr + ` AND msg.deleted_at IS NULL
			   -- GUEST_HISTORY_FLOOR: drive_attachment_content
			   AND msg.seq > COALESCE(hcm.history_floor_seq, 0)
			   AND (hcm.history_floor_seq IS NULL OR msg.created_at >= hcm.joined_at)
		)
	)`
}

// chatAttachmentNodeVisibleSQL is the metadata twin for GET /drive/nodes.
// The guest allowlist exposes this exact-id batch route so chat attachments
// can resolve their head version; without this second choke a removed/re-added
// guest could still enumerate filename/hash/size for a pre-floor remembered
// node even though content streaming was denied.
func chatAttachmentNodeVisibleSQL(nodeExpr, userExpr string) string {
	return `(
		NOT EXISTS (
			SELECT 1 FROM drive_nodes cn
			  JOIN drive_spaces cs ON cs.id = cn.space_id
			 WHERE cn.id = ` + nodeExpr + ` AND cs.chat_channel_id IS NOT NULL
		)
		OR EXISTS (
			SELECT 1 FROM chat_message_attachments cma
			  JOIN chat_messages msg ON msg.id = cma.message_id
			  JOIN chat_channel_members hcm
			    ON hcm.channel_id = msg.channel_id AND hcm.user_id = ` + userExpr + `
			 WHERE cma.file_node_id = ` + nodeExpr + ` AND msg.deleted_at IS NULL
			   -- GUEST_HISTORY_FLOOR: drive_attachment_metadata
			   AND msg.seq > COALESCE(hcm.history_floor_seq, 0)
			   AND (hcm.history_floor_seq IS NULL OR msg.created_at >= hcm.joined_at)
		)
	)`
}
