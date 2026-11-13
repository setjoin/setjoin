package mdm

// Platform push capability map.
var platformHasPush = map[string]bool{
	"ios":         true, // APNs
	"ipados":      true, // APNs
	"android_gms": true, // FCM
	"android_hms": true, // HMS
	"harmonyos":   true, // HMS Push Kit (native to NEXT)
	// All others: no cloud push service available
}

// ResolveNotificationProfile determines the effective notification profile
// for a platform given the admin-configured profile. The client auto-adjusts
// based on what the platform actually supports.
//
// iOS can only use APNs (Apple restriction) — websocket_only falls back to push_only.
// Desktop has no push service — anything falls back to websocket_only.
func ResolveNotificationProfile(adminProfile, platform string) string {
	switch adminProfile {
	case "push_only":
		if PlatformSupportsPush(platform) {
			return "push_only"
		}
		// No push service available — fall back to WebSocket
		return "websocket_only"

	case "websocket_only":
		if platform == "ios" || platform == "ipados" {
			// Apple restriction: no persistent WebSocket in background.
			// Fall back to push_only (user gets manual refresh).
			return "push_only"
		}
		return "websocket_only"

	case "hybrid":
		if PlatformSupportsPush(platform) {
			return "hybrid"
		}
		// No push → fall back to WebSocket-only
		return "websocket_only"

	default:
		return ResolveNotificationProfile("hybrid", platform)
	}
}

// PlatformSupportsPush returns true if the platform has a cloud push
// notification service available (APNs, FCM, HMS).
func PlatformSupportsPush(platform string) bool {
	return platformHasPush[platform]
}

// DefaultNotificationProfile returns the system default notification profile.
func DefaultNotificationProfile() NotificationProfile {
	return NotificationProfile{
		Profile:                "hybrid",
		WebsocketKeepaliveSecs: 30,
	}
}
