package webhook

// Event types for webhook subscriptions.
const (
	EventUserCreated           = "user.created"
	EventUserDeleted           = "user.deleted"
	EventUserUpdated           = "user.updated"
	EventAuthLoginFailed       = "auth.login_failed"
	EventAuthLogin             = "auth.login"
	EventMailboxQuotaWarn      = "mailbox.quota_warning"
	EventSystemHealthAlert     = "system.health_alert"
	EventMigrationCompleted    = "migration.completed"
	EventMigrationFailed       = "migration.failed"
	EventMailReceived          = "mail.received"
	EventMailSent              = "mail.sent"
	EventMailRuleTriggered     = "mail.rule_triggered"
	EventCalendarInvite        = "calendar.invitation"
	EventMailboxSuspended      = "mailbox.suspended"
	EventMailboxResumed        = "mailbox.resumed"
	EventMailboxDetached       = "mailbox.detached"
	EventMailboxReconnected    = "mailbox.reconnected"
	EventMailboxPurgeScheduled = "mailbox.purge_scheduled"
	EventMailboxPurgeCancelled = "mailbox.purge_cancelled"
	EventMailboxPurged         = "mailbox.purged"
	EventMailWorkClaimed       = "mailwork.claimed"
	EventMailWorkAssigned      = "mailwork.assigned"
	EventMailWorkHandedOff     = "mailwork.handed_off"
	EventMailWorkCompleted     = "mailwork.completed"
	EventMailWorkSLABreached   = "mailwork.sla_breached"
)

// EventCatalog returns the full event type catalog (machine-readable).
func EventCatalog() []map[string]string {
	return eventCatalog
}

// IsKnownEventType keeps subscription admission pinned to the same catalog the
// admin UI renders. Unknown strings must never become silent, unbounded egress
// scopes merely because a client bypassed the UI.
func IsKnownEventType(eventType string) bool {
	for _, event := range eventCatalog {
		if event["type"] == eventType {
			return true
		}
	}
	return false
}

var eventCatalog = []map[string]string{
	{"type": EventUserCreated, "category": "admin", "source": "mailserver/auth"},
	{"type": EventUserDeleted, "category": "admin", "source": "mailserver/auth"},
	{"type": EventUserUpdated, "category": "admin", "source": "mailserver/auth"},
	{"type": EventAuthLoginFailed, "category": "admin", "source": "mailserver/auth"},
	{"type": EventAuthLogin, "category": "admin", "source": "mailserver/auth"},
	{"type": EventMailboxQuotaWarn, "category": "admin", "source": "mailserver/gateway"},
	{"type": EventSystemHealthAlert, "category": "admin", "source": "mailserver/gateway"},
	{"type": EventMigrationCompleted, "category": "admin", "source": "mailserver/gateway"},
	{"type": EventMigrationFailed, "category": "admin", "source": "mailserver/gateway"},
	{"type": EventMailReceived, "category": "mailbox", "source": "mailserver/gateway"},
	{"type": EventMailSent, "category": "mailbox", "source": "mailserver/gateway"},
	{"type": EventMailRuleTriggered, "category": "mailbox", "source": "mailserver/gateway"},
	{"type": EventCalendarInvite, "category": "mailbox", "source": "mailserver/gateway"},
	{"type": EventMailboxSuspended, "category": "admin", "source": "mailserver/lifecycle"},
	{"type": EventMailboxResumed, "category": "admin", "source": "mailserver/lifecycle"},
	{"type": EventMailboxDetached, "category": "admin", "source": "mailserver/lifecycle"},
	{"type": EventMailboxReconnected, "category": "admin", "source": "mailserver/lifecycle"},
	{"type": EventMailboxPurgeScheduled, "category": "admin", "source": "mailserver/lifecycle"},
	{"type": EventMailboxPurgeCancelled, "category": "admin", "source": "mailserver/lifecycle"},
	{"type": EventMailboxPurged, "category": "admin", "source": "mailserver/lifecycle"},
	{"type": EventMailWorkClaimed, "category": "mailbox", "source": "mailserver/mailwork"},
	{"type": EventMailWorkAssigned, "category": "mailbox", "source": "mailserver/mailwork"},
	{"type": EventMailWorkHandedOff, "category": "mailbox", "source": "mailserver/mailwork"},
	{"type": EventMailWorkCompleted, "category": "mailbox", "source": "mailserver/mailwork"},
	{"type": EventMailWorkSLABreached, "category": "mailbox", "source": "mailserver/mailwork"},
}
