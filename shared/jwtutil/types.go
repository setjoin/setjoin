package jwtutil

import (
	"time"

	"github.com/golang-jwt/jwt/v5"

	"setjoin.com/shared/permissions"
)

// NewNumericDate re-exports jwt.NewNumericDate for callers that import only jwtutil.
func NewNumericDate(t time.Time) *jwt.NumericDate { return jwt.NewNumericDate(t) }

type TokenType string

const (
	TypeAccess              TokenType = "access"
	TypeMFAPending          TokenType = "mfa_pending"
	TypeRefresh             TokenType = "refresh"
	TypeForcePasswordChange TokenType = "force_pw_change"
	TypePasswordReset       TokenType = "password_reset"
)

type Claims struct {
	UserID      int64    `json:"uid"`
	Email       string   `json:"email"`
	IsAdmin     bool     `json:"admin,omitempty"`
	Permissions []string `json:"perms,omitempty"`  // Phase 2: embedded permissions
	DomainScope *int64   `json:"domain,omitempty"` // Phase 2: embedded domain scope
	// GlobalPermissions is a live gateway-only projection of permissions whose
	// granting assignment is domain-, OU-, and scope-set-unscoped. It is never
	// accepted from or serialized into a JWT.
	GlobalPermissions []string  `json:"-"`
	Type              TokenType `json:"typ"`
	JTI               string    `json:"jti,omitempty"`
	FamilyID          string    `json:"fam,omitempty"` // refresh-family id (CA-3 substrate; inert until CA-3)
	AdminActorID      *int64    `json:"act,omitempty"`

	// AccountType marks a constrained principal class. "" = ordinary member
	// (backward-compatible absence); AccountTypeGuest = a guest account
	// (guest-accounts spec P13). Minted at EVERY access-token mint site and
	// belted by an UNCONDITIONAL guest_accounts satellite lookup at
	// chain.AuthenticateRequest — the claim is a fast path, never the sole
	// authority.
	AccountType string `json:"acct,omitempty"`

	// Authentication-context claims (OIDC Core §2 / NIST SP 800-63B AAL).
	// ACR signals the Authentication Context Class the session satisfied
	// (e.g. "aal1" for single-factor, "aal2" once a second factor completed).
	// AMR lists the Authentication Methods References actually performed
	// (RFC 8176 — "pwd", "otp", "hwk", "swk", "mfa", …). Both are omitempty so
	// pre-existing tokens (and any flow that does not set them) stay byte-for-byte
	// backward-compatible; downstream consumers MAY require a minimum ACR for
	// sensitive contexts (conditional-access step-up) but need not consume them.
	ACR string   `json:"acr,omitempty"`
	AMR []string `json:"amr,omitempty"`

	// AuthMethod is the per-request authentication mechanism that produced this
	// Claims (e.g. "certificate", "kerberos"). Set by auth methods that bypass
	// the JWT path (mTLS, SPNEGO) so the CA engine's auth_method condition can
	// see the correct value. omitempty: absent for JWT-bearer-derived tokens.
	AuthMethod string `json:"auth_method,omitempty"`

	// Device identity embedded in JWT at issuance time.
	// Set by authserver. Read by every app server for compliance gating.
	// Pointer so omitempty suppresses zero-value.
	Device *DeviceClaim `json:"device,omitempty"`

	// MAM policy snapshot valid at token issuance time.
	// Clients enforce locally, servers read for per-request gating.
	// Pointer so omitempty suppresses zero-value.
	MAM *MAMClaim `json:"mam,omitempty"`

	// Aggregated risk score from all app servers.
	// Set by authserver's policy engine at token issuance.
	// Pointer so omitempty suppresses zero-value.
	Risk *RiskClaim `json:"risk,omitempty"`

	// Cnf binds the token to a device-held key (RFC 9449 DPoP jkt / RFC 8705
	// mTLS cnf.x5t#S256). When present and feature.token_binding is on, the
	// gateway verifies a per-request proof binds to it. omitempty keeps pre-
	// binding tokens byte-compatible.
	Cnf *ConfirmationClaim `json:"cnf,omitempty"`

	// SignInFreq is the max session age in seconds the matched policy demanded
	// at issuance (sign-in-frequency). The gateway forces re-auth when
	// now-auth_time > SignInFreq. omitempty: absent ⇒ no max age.
	SignInFreq *int64 `json:"sif,omitempty"`

	// SessionAuthTime is the Unix timestamp of the authentication event that
	// created the refresh family. Unlike iat it does not advance when a refresh
	// token rotates, so sign-in-frequency cannot be reset by refreshing.
	SessionAuthTime *int64 `json:"auth_time,omitempty"`

	// IdentityFence binds an MFA-pending challenge that began with a normalized
	// federated first factor to the exact source/link generations that
	// authenticated it. Completion must re-run identity_auth_mint_fence with
	// these values; absence means a genuinely local or legacy challenge.
	IdentityFence *IdentityFenceClaim `json:"identity_fence,omitempty"`

	// CredentialFence is a one-way digest of the verified local password-hash
	// version. Local MFA completion and final token mint recheck it while holding
	// the identity-person transaction fence. It is never populated for
	// passwordless or federated authentication.
	CredentialFence string `json:"credential_fence,omitempty"`

	// Scp scopes a token to a single named surface (drive Drive P1 native-token
	// bridge: "drive"). A non-empty Scp is a MIRROR credential, never a full
	// session — the accepting chain must reject it outside the surface it names
	// (see mailserver/internal/auth/chain.go's scope-containment guard).
	// omitempty: absent on every normal session/access/refresh token.
	Scp string `json:"scp,omitempty"`

	// Attachment binds a five-minute mail-attachment mirror credential to one
	// immutable blob, the authenticated native device, the owning account, and
	// the exact effective-policy projection observed at mint time. It is absent
	// from every normal and Drive-scoped token. The bearer itself is never
	// persisted by the transfer controller; only these non-secret bounds are.
	Attachment *AttachmentTransferClaim `json:"attachment,omitempty"`

	jwt.RegisteredClaims
}

// AttachmentTransferClaim is the signed authority envelope for the exact
// GET /mail-attachment/{sha256} surface. OriginJTI/OriginIssuedAt preserve the
// parent session's narrow-revocation semantics even though the derived token
// deliberately receives its own unique JTI.
type AttachmentTransferClaim struct {
	SHA256            string `json:"sha256"`
	AccountID         int64  `json:"account_id"`
	MailboxID         int64  `json:"mailbox_id"`
	DeviceID          int64  `json:"device_id"`
	DeviceFingerprint string `json:"device_fingerprint"`
	PolicyGeneration  string `json:"policy_generation"`
	OriginJTI         string `json:"origin_jti"`
	OriginIssuedAt    int64  `json:"origin_iat"`
}

type IdentityFenceClaim struct {
	SourceID         int64 `json:"source_id"`
	SourceGeneration int64 `json:"source_generation"`
	LinkID           int64 `json:"link_id"`
	LinkGeneration   int64 `json:"link_generation"`
}

// ── Device Claim ──

// DeviceClaim embeds device identity and compliance state in the JWT.
// WipeRequested is checked by every app server on every request.
// TrustTier drives the compliance gating decision.
type DeviceClaim struct {
	ID               string `json:"id"`
	Platform         string `json:"platform"`
	TrustTier        string `json:"trust_tier"`        // trusted | compliant | quarantined | unknown
	ComplianceStatus string `json:"compliance_status"` // ok | jailbroken | os_outdated | no_passcode
	WipeRequested    bool   `json:"wipe_requested"`
}

// Trust tier constants — used by RequireDeviceCompliance middleware.
const (
	TrustTierTrusted     = "trusted"
	TrustTierCompliant   = "compliant"
	TrustTierQuarantined = "quarantined"
	TrustTierUnknown     = "unknown"
)

// Compliance status constants.
const (
	ComplianceOK         = "ok"
	ComplianceJailbroken = "jailbroken"
	ComplianceOSOutdated = "os_outdated"
	ComplianceNoPasscode = "no_passcode"
)

// ── MAM Claim ──

// MAMClaim is a snapshot of the resolved MAM policy for the device,
// embedded in the JWT so app servers can enforce without querying authserver.
type MAMClaim struct {
	PolicyVersion       int64  `json:"policy_version"`
	CopyPaste           string `json:"copy_paste"`     // allow | block_external | block
	ScreenCapture       string `json:"screen_capture"` // allow | block
	Encryption          string `json:"encryption"`     // required | optional
	Watermark           bool   `json:"watermark"`
	NotificationProfile string `json:"notification_profile"` // push | batch | silent
	MaxOfflineDays      int    `json:"max_offline_days"`
}

// Notification profile constants.
const (
	NotificationPush   = "push"
	NotificationBatch  = "batch"
	NotificationSilent = "silent"
)

// ── Risk Claim ──

// RiskClaim carries the aggregated user risk score and any active risk signals.
// App servers can optionally escalate requirements (e.g., require MFA re-auth
// for sensitive operations) when the score is elevated.
type RiskClaim struct {
	UserScore   int      `json:"user_score"`   // 0-100, aggregated across all app servers
	Level       string   `json:"level"`        // none|low|medium|high (mirrors user_risk.level)
	RequiresMFA bool     `json:"requires_mfa"` // user must re-authenticate with MFA
	Signals     []string `json:"signals"`      // which risk signals triggered this score
}

// ── Confirmation Claim (token binding) ──

// ConfirmationClaim is the RFC 7800 cnf claim. JKT is the base64url SHA-256
// thumbprint of the DPoP public JWK (RFC 9449); X5TS256 is the mTLS client-cert
// thumbprint (RFC 8705). Exactly one is set per bound token.
type ConfirmationClaim struct {
	JKT     string `json:"jkt,omitempty"`
	X5TS256 string `json:"x5t#S256,omitempty"`
}

// AccountTypeGuest is the AccountType claim value for guest accounts.
const AccountTypeGuest = "guest"

// IsGuest reports whether the claims mark a guest account.
func (c *Claims) IsGuest() bool { return c.AccountType == AccountTypeGuest }

// RefreshFamilyID returns the refresh-family id carried in the token (CA-3 substrate).
// Empty when the token predates family tracking.
func (c *Claims) RefreshFamilyID() string { return c.FamilyID }

// HasPermission checks whether the claims include a specific permission.
// Permissions are resolved at auth time (from governed admin_role_assignments)
// and carried in c.Permissions.
//
// This is a thin adapter over permissions.HasPermission — a pure, deny-by-default
// set-membership test. The legacy "IsAdmin with an empty resolved permission set
// ⇒ full access" bridge has been DELETED, and the users.admin_role enum that once
// fed a `role` claim is GONE (the RBAC cut-over dropped the column): the IsAdmin
// flag no longer grants anything on its own. A super-admin earns AllPermissions
// through a governed admin_role_assignments row, so an empty perm set always
// denies — closing the privilege-escalation where an admin with no governed
// assignment silently became a superuser.
func (c *Claims) HasPermission(perm string) bool {
	return permissions.HasPermission(c.Permissions, perm)
}
