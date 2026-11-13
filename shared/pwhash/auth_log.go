package pwhash

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/toggle"
)

// AuthProvider is the finite authentication-event provider vocabulary. It is
// also the only input accepted by AuthLogFeatureKey, so a caller cannot create
// an open-ended feature.auth_log_* key.
type AuthProvider string

const (
	AuthProviderAppPassword       AuthProvider = "app_password"
	AuthProviderBasic             AuthProvider = "basic"
	AuthProviderBcrypt            AuthProvider = "bcrypt"
	AuthProviderConditionalAccess AuthProvider = "conditional_access"
	AuthProviderJWT               AuthProvider = "jwt"
	AuthProviderKerberos          AuthProvider = "kerberos"
	AuthProviderLDAP              AuthProvider = "ldap"
	AuthProviderRateLimit         AuthProvider = "rate_limit"
	AuthProviderThreat            AuthProvider = "threat"
	AuthProviderWebAuthn          AuthProvider = "webauthn"
)

// AuthProviders returns the complete provider vocabulary in stable order.
func AuthProviders() []AuthProvider {
	return []AuthProvider{
		AuthProviderAppPassword,
		AuthProviderBasic,
		AuthProviderBcrypt,
		AuthProviderConditionalAccess,
		AuthProviderJWT,
		AuthProviderKerberos,
		AuthProviderLDAP,
		AuthProviderRateLimit,
		AuthProviderThreat,
		AuthProviderWebAuthn,
	}
}

// AuthLogFeatureKey maps every valid provider to one compiled feature key.
func AuthLogFeatureKey(provider AuthProvider) (string, bool) {
	switch provider {
	case AuthProviderAppPassword:
		return toggle.FeatureAuthLogAppPassword, true
	case AuthProviderBasic:
		return toggle.FeatureAuthLogBasic, true
	case AuthProviderBcrypt:
		return toggle.FeatureAuthLogBcrypt, true
	case AuthProviderConditionalAccess:
		return toggle.FeatureAuthLogCA, true
	case AuthProviderJWT:
		return toggle.FeatureAuthLogJWT, true
	case AuthProviderKerberos:
		return toggle.FeatureAuthLogKerberos, true
	case AuthProviderLDAP:
		return toggle.FeatureAuthLogLDAP, true
	case AuthProviderRateLimit:
		return toggle.FeatureAuthLogRateLimit, true
	case AuthProviderThreat:
		return toggle.FeatureAuthLogThreat, true
	case AuthProviderWebAuthn:
		return toggle.FeatureAuthLogWebAuthn, true
	default:
		return "", false
	}
}

// AuthEvent represents a single authentication event to be logged.
type AuthEvent struct {
	UserID    *int64 // nil for failed auths where user couldn't be found
	Event     string // "login" or "login_failed"
	Provider  AuthProvider
	Email     string // always available (the credential presented)
	IPAddress string // can be empty
	Details   string // optional JSONB string
}

// ToggleChecker allows callers to optionally gate logging behind feature toggles.
// *toggle.FeatureFlags satisfies this interface. Pass nil to always log.
type ToggleChecker interface {
	IsEnabled(key string) bool
}

// LogAuthEvent writes an authentication event to auth_event_log.
// Errors are silently swallowed — logging must never break auth flow.
func LogAuthEvent(ctx context.Context, pool *pgxpool.Pool, ev AuthEvent, checker ToggleChecker) {
	featureKey, known := AuthLogFeatureKey(ev.Provider)
	if !known || checker != nil && !checker.IsEnabled(featureKey) {
		return
	}
	var ip interface{}
	if ev.IPAddress != "" {
		ip = ev.IPAddress
	}
	var details interface{}
	if ev.Details != "" {
		details = ev.Details
	}
	var email interface{}
	if ev.Email != "" {
		email = ev.Email
	}

	_, _ = pool.Exec(ctx,
		`INSERT INTO auth_event_log (user_id, event, provider, email, ip_address, details)
         VALUES ($1, $2, $3, $4, $5, $6)`,
		ev.UserID, ev.Event, string(ev.Provider), email, ip, details,
	)
}
