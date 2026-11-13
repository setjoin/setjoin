// Package threat — Conditional Access Policy Engine.
//
// Extends the 8-step threat pipeline into a configurable policy engine.
// Evaluates device trust, IP reputation scoring, geo risk tier, user/group
// membership, auth method, time of day, and client type against administrator-
// defined ordered rules. Actions: allow, block, step-up (require MFA), notify.
// First-match-wins. Gated behind feature.conditional_access toggle.
//
// Spec: docs/design/security/ (conditional access policies)
package threat

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	"setjoin.com/shared/toggle"
)

// ── Types ──

// NamedLocation is a named set of IP ranges and/or country codes used by the
// location_in / location_trusted conditions (CA-1 A2).
type NamedLocation struct {
	ID        int64    `json:"id"`
	Name      string   `json:"name"`
	CIDRs     []string `json:"cidrs"`
	Countries []string `json:"countries"`
	Trusted   bool     `json:"trusted"`
	// parsedCIDRs holds pre-parsed netip.Prefix values for CIDRs, populated by
	// setNamedLocations to avoid re-parsing on every auth request.
	// ponytail: nil fallback in ipInLocation keeps unit tests that build NamedLocation
	// directly (without setNamedLocations) working; hot path always has parsedCIDRs set.
	parsedCIDRs []netip.Prefix
}

// PolicyDecision is the outcome of a conditional access policy evaluation.
type PolicyDecision int

const (
	DecisionAllow  PolicyDecision = iota // proceed normally
	DecisionBlock                        // deny access (403)
	DecisionStepUp                       // require MFA
	DecisionNotify                       // allow but fire alert
)

func (d PolicyDecision) String() string {
	switch d {
	case DecisionAllow:
		return "allow"
	case DecisionBlock:
		return "block"
	case DecisionStepUp:
		return "step_up"
	case DecisionNotify:
		return "notify"
	default:
		return "unknown"
	}
}

// PolicyEvalContext holds all the metadata needed to evaluate conditional access policies.
type PolicyEvalContext struct {
	UserID   int64   `json:"user_id"`
	GroupIDs []int64 `json:"group_ids"`
	// IsGuest is derived from the guest_accounts satellite (or from a JWT only
	// after the mailserver auth belt has re-derived it from that satellite).
	// It is the sole input for scope_type='guests'.
	IsGuest bool `json:"is_guest"`
	// RoleGroupIDs are the admin role-group IDs the principal holds via
	// admin_role_assignments (ResolveRoleGroups). Distinct from GroupIDs (directory
	// groups). Used by scopeMatches for 'role' scope policies (e.g. mfa-for-admins).
	// Nil/empty means the principal holds no admin roles (no role-scoped policy fires).
	RoleGroupIDs []int64   `json:"role_group_ids,omitempty"`
	SourceIP     string    `json:"source_ip"`
	Country      string    `json:"country"`
	DeviceFP     string    `json:"device_fp"`
	AuthMethod   string    `json:"auth_method"`
	ClientType   string    `json:"client_type"`
	Protocol     string    `json:"protocol"`
	UserAgent    string    `json:"user_agent"`
	RequestTime  time.Time `json:"request_time"`

	// CurrentACR is the Authentication Context Class the session has reached so
	// far (NIST AAL — "aal1"/"aal2"), if known at evaluation time. A policy with
	// a require_acr action is satisfied (no step-up) when CurrentACR already meets
	// it; otherwise the engine returns DecisionStepUp to force the missing factor.
	// Empty means "not yet authenticated beyond the first factor" — treated as
	// below any required AAL.
	CurrentACR string `json:"current_acr"`

	// Device-bound credential signals (CA-2). DeviceBound is TRUE only when a
	// valid X-Device-HMAC proof was verified by the DeviceCredentialResolver;
	// EnrollState is the resolved devices.enroll_state. A blocking lockdown
	// decision rests on these crypto signals, never on the forgeable DeviceFP.
	// ponytail: DeviceID is carried for audit/logging; policy matchers use DeviceBound+EnrollState only.
	DeviceBound bool   `json:"device_bound"`
	DeviceID    int64  `json:"device_id"`
	EnrollState string `json:"enroll_state"`

	// CompletedFactors are the authentication factors the session has already
	// completed (e.g. "password","webauthn","totp","push"), used to evaluate a
	// require_strength grant on the HTTP path. Empty/unknown on IMAP/SMTP.
	// Populated by CA-F §2 F1; consumed by future require_strength action dispatch.
	CompletedFactors []string `json:"completed_factors,omitempty"`

	// RiskLevel is the authenticated user's current risk band (none|low|medium|high),
	// sourced from the JWT Risk claim at the runtime gate (F2) or from user_risk at
	// login. Used by the require_risk_remediation action to skip blocking a genuinely
	// low-risk user (who would otherwise get a mass false-lockout).
	// Empty string is treated as "not elevated" (same as "none"/"low").
	RiskLevel string `json:"risk_level,omitempty"`

	// RevocationSensitive marks a context whose decision must NOT be served from
	// the F8 decision cache (CA-3a sets it for runtime revocation/denylist reads —
	// a revoked session must be denied immediately, not within the TTL).
	RevocationSensitive bool `json:"-"`

	// TrustTierOverride, when non-empty, bypasses DeviceTrustResolver and injects
	// the supplied trust tier directly into policy evaluation. Intended for the
	// What-If simulator (D6) where device_trust is a caller-supplied hint, not a
	// real DeviceFP lookup.  Valid values: "unknown", "compliant", "trusted".
	// Never set this on live authentication paths.
	TrustTierOverride string `json:"trust_tier_override,omitempty"`
}

// policyOutcome is one row of the per-evaluation trace recorded into ca_signin_log.
// Priority, Scope, and FirstFailed are populated by EvaluateWithPolicies (simulator path)
// and zero-valued on the live Evaluate path — the extra fields are additive in the
// JSONB log column and ignored by existing readers.
type policyOutcome struct {
	PolicyID    int64  `json:"policy_id"`
	Name        string `json:"name"`
	Outcome     string `json:"outcome"`                // applied|would_block|would_step_up|would_notify|skipped|excluded
	Priority    int    `json:"priority,omitempty"`     // simulator: policy priority (0 = live path, omitted)
	Scope       string `json:"scope,omitempty"`        // simulator: scope_type ("global","user","group","role")
	FirstFailed string `json:"first_failed,omitempty"` // simulator: first condition key that returned false, or "scope:<type>"
}

// newCorrelationID mints a short opaque per-evaluation reference (e.g. "CA-7f3c9a")
// stamped on enforcing block/step_up responses so a blocked user can quote it and an
// admin resolves the exact ca_signin_log row by it.
func newCorrelationID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return "CA-" + hex.EncodeToString(b[:])
}

// PolicyResult is the outcome of a conditional access policy evaluation.
type PolicyResult struct {
	Decision       PolicyDecision `json:"decision"`
	Reason         string         `json:"reason"`
	PolicyID       int64          `json:"policy_id"`
	PolicyName     string         `json:"policy_name"`
	StepUpMethods  []string       `json:"step_up_methods,omitempty"`
	NotifyChannels []string       `json:"notify_channels,omitempty"`

	// RequiredACR is the minimum Authentication Context Class (NIST AAL —
	// "aal2") a require_acr policy demands for this context. When set and the
	// session has not yet reached it, the engine returns DecisionStepUp; the
	// access token ultimately issued must carry an acr that satisfies it. Empty
	// when the matched policy imposes no acr requirement.
	RequiredACR string `json:"required_acr,omitempty"`

	// Remediation is a typed self-service unblock the gateway renders as a 403
	// the SPA acts on, instead of a dead end. "" = none; "terms" = accept a
	// ToU; "risk" = complete MFA re-auth (and optionally a password change).
	// The two CA-3b action verbs require_terms / require_risk_remediation set
	// this. The Decision is DecisionBlock (the request is denied now) but the
	// body tells the client how to clear it.
	Remediation        string `json:"remediation,omitempty"`
	RemediationTermsID int64  `json:"remediation_tou_id,omitempty"`

	// LimitedWeb is set when the matched policy's action is "limited_web": the
	// session is allowed but the gateway projects a capability cut (no attachment
	// download / no external auto-forward) via effective_capabilities.
	LimitedWeb bool `json:"limited_web,omitempty"`

	// StrictLocation is set when the matched policy's session_control demands
	// strict-location (the IP-variation grace is removed for this session).
	StrictLocation bool `json:"strict_location,omitempty"`

	// Evaluated is the ordered per-policy outcome trace for this evaluation
	// (applied|would_*|skipped|excluded), persisted to ca_signin_log by the caller.
	Evaluated []policyOutcome `json:"evaluated,omitempty"`
	// CorrelationID is the opaque 'why blocked' reference minted on an enforcing
	// block/step_up decision; stamped on the block response and echoed into
	// ca_signin_log. Empty for allow / report-only flows.
	CorrelationID string `json:"correlation_id,omitempty"`
}

// PolicyRow is a policy loaded from the database.
type PolicyRow struct {
	ID                  int64
	Priority            int
	Name                string
	Description         string
	Enabled             bool
	State               string // off|report_only|on (CA-0a; supersedes Enabled)
	ScopeType           string
	ScopeTarget         string
	Conditions          map[string]interface{}
	Actions             map[string]interface{}
	ExcludeUsers        []int64 // break-glass: user ids excluded from this policy (CA-0a)
	ExcludeGroups       []int64 // break-glass: user-group ids excluded from this policy (CA-0a)
	CreatedFromTemplate string  // template slug that produced this policy (V030; may be empty)
}

// ── PolicyStore ──

// ScopeResolver is the CHECKED, error-surfacing per-principal scope-resolution
// seam (CA-SCOPE-RESOLUTION-FAIL-OPEN-CACHED). *pgxPolicyStore implements it
// (cache-backed, 60s TTL, failures never cached). When the engine's store
// implements this interface, Evaluate resolves group/role membership through it
// for every user-scoped evaluation instead of trusting caller-supplied
// PolicyEvalContext membership — so a caller that resolved through an
// error-dropping wrapper (silent empty membership on a transient blip) is
// repaired, and a resolution FAILURE routes into failModeDecision instead of
// silently skipping every group/role-scoped policy.
type ScopeResolver interface {
	// ResolveUserScope returns the directory group IDs and admin role-group IDs
	// for userID, surfacing the query error. Implementations must never convert
	// a failure into empty membership and must never cache a failure.
	ResolveUserScope(ctx context.Context, userID int64) (groups, roleGroups []int64, err error)
}

// PolicyStore abstracts database access for the conditional access policy engine.
// Each server (authserver, gateway) provides its own SQL-backed implementation.
type PolicyStore interface {
	// LoadAllPolicies returns EVERY enabled policy, UNFILTERED by scope. The engine
	// caches this raw set and scope-filters per request in Evaluate, so the cache is
	// never poisoned with one user's scope (the cross-user leak fix, F2a).
	LoadAllPolicies(ctx context.Context) ([]PolicyRow, error)
	LoadPolicies(ctx context.Context, pectx PolicyEvalContext) ([]PolicyRow, error)
	ResolveGeoTier(ctx context.Context, country string) (string, error)
	// LoadBreakGlass reads the system break-glass user-id set from
	// system_config.ca_break_glass_user_ids. Returns nil, nil when the key is absent
	// (not an error — means no break-glass set has been configured yet).
	LoadBreakGlass(ctx context.Context) ([]int64, error)
	// LoadNamedLocations returns all non-deleted named locations (CA-1 A2).
	LoadNamedLocations(ctx context.Context) ([]NamedLocation, error)
	// LoadAuthStrengths returns all auth-strength definitions (CA-1 A3).
	LoadAuthStrengths(ctx context.Context) ([]AuthStrength, error)
}

// ── PolicyEngine ──

// policyCacheTTL is the default duration policy rows are cached before re-fetching.
const policyCacheTTL = 30 * time.Second

// decisionCacheTTL is the SHORT TTL for the per-principal decision cache (F8),
// well under policyCacheTTL so a verdict can't go stale beyond a few seconds.
const decisionCacheTTL = 5 * time.Second

// maxDecisionCacheEntries bounds the decision cache (simple size cap; on overflow
// the cache is cleared rather than grown unbounded).
const maxDecisionCacheEntries = 4096

// cachedDecision holds a cached PolicyResult with an expiry timestamp.
type cachedDecision struct {
	result PolicyResult
	expiry time.Time
}

// PolicyEngine evaluates conditional access policies after the 8-step threat pipeline.
type PolicyEngine struct {
	store       PolicyStore
	toggles     *toggle.FeatureFlags
	deviceTrust *DeviceTrustResolver
	ipRisk      *IPRiskScorer
	logger      *slog.Logger
	// scopeResolver is the checked scope-resolution seam (ScopeResolver), set at
	// construction when store implements it. nil = caller-supplied membership is
	// used as-is (legacy stores / test fakes).
	scopeResolver ScopeResolver
	// failClosed is DEPRECATED — it is now a back-compat shim. NewPolicyEngine maps
	// failClosed=true → pe.failMode="closed" at construction time; failModeDecision
	// consults only pe.failMode. Do not use failClosed directly in logic.
	failClosed bool

	// F7 fail-closed posture. failMode ∈ {"closed","open"} (default "closed",
	// sourced from system_config ca_fail_mode). On an eval error, "closed" blocks
	// unless the cache was SUCCESSFULLY loaded and shows zero enforcing policies —
	// the ONLY safe signal that nothing enforces. failClosed=true is mapped to
	// "closed" at construction time (back-compat shim; the field is not consulted in logic).
	failMode string
	// ExcludeChecker, when set, reports whether a principal is break-glass/excluded
	// (CA-0a fills it). It short-circuits BEFORE the fail-closed branch so an eval
	// error can never strand the break-glass admin. nil = no exclusions.
	ExcludeChecker func(ctx context.Context, pectx PolicyEvalContext) bool

	// In-memory policy cache — avoids hitting the DB on every auth request.
	cacheMu        sync.RWMutex
	cachedAt       time.Time
	cachedPolicies []PolicyRow
	cacheTTL       time.Duration
	// cacheLoaded is set to true only after at least one SUCCESSFUL LoadAllPolicies call.
	// Used by failModeDecision to distinguish "zero enforcing policies confirmed by a
	// successful load" from "never loaded / cold-boot / DB-down" (both have an empty
	// cachedPolicies slice, but only the former is safe to treat as fail-open in "closed" mode).
	cacheLoaded bool

	// F8 per-principal DECISION cache — layered ABOVE the policy-set cache. Keyed
	// by hash(principal | action/protocol | resource | bucketed ctx); ≤5s TTL;
	// flushed by InvalidateCache alongside the policy-set cache.
	decisionMu    sync.Mutex
	decisionCache map[uint64]cachedDecision

	// breakGlass holds system break-glass user IDs (CA-0a). These users are
	// excluded from every policy in Evaluate. Set via SetBreakGlass at load time;
	// refreshed on cache invalidation. Protected by cacheMu.
	breakGlass []int64

	// namedLocations is the engine location cache keyed by id (CA-1 A2).
	// Parallel to cachedPolicies; cleared by InvalidateCache. Protected by cacheMu.
	namedLocations map[int64]NamedLocation

	// authStrengths is the engine auth-strength cache keyed by id (CA-1 A3).
	// Parallel to namedLocations; cleared by InvalidateCache. Protected by cacheMu.
	authStrengths map[int64]AuthStrength
}

// SetFailMode sets the fail-closed/fail-open posture of the engine.
// mode must be "closed" (default, deny on eval error) or "open" (allow on eval error).
// Call once at startup after constructing the engine, sourced from system_config
// ca_fail_mode. Unrecognised values default to "closed" for safety.
func (pe *PolicyEngine) SetFailMode(mode string) {
	if mode == "open" {
		pe.failMode = "open"
	} else {
		pe.failMode = "closed"
	}
}

// NewPolicyEngine creates a conditional access policy engine.
// failClosed: DEPRECATED back-compat param — if true it is mapped to failMode="closed"
// (single source of truth). The admin-facing posture is failMode ("closed"/"open",
// default "closed"), set via pe.failMode after construction (sourced from
// system_config ca_fail_mode). failClosed is no longer consulted in decision logic.
func NewPolicyEngine(store PolicyStore, toggles *toggle.FeatureFlags, deviceTrust *DeviceTrustResolver, ipRisk *IPRiskScorer, logger *slog.Logger, failClosed bool) *PolicyEngine {
	pe := &PolicyEngine{
		store:       store,
		toggles:     toggles,
		deviceTrust: deviceTrust,
		ipRisk:      ipRisk,
		logger:      logger,
		failClosed:  failClosed, // retained for struct transparency; not consulted in logic
		failMode:    "closed",   // default posture; admin may set to "open" post-construction
		cacheTTL:    policyCacheTTL,
	}
	// Wire the checked scope-resolution seam when the store provides it
	// (*pgxPolicyStore does; test fakes that don't keep the legacy behavior).
	if sr, ok := store.(ScopeResolver); ok {
		pe.scopeResolver = sr
	}
	// Back-compat shim: map legacy failClosed=true → failMode="closed" (already the
	// default, but this documents the intent; failClosed=false leaves failMode="closed"
	// as well — the field is deprecated and purely preserved for transparency).
	if failClosed {
		pe.failMode = "closed"
	}
	return pe
}

// Evaluate runs all enabled policies in priority order. First full match wins.
// Returns DecisionAllow with empty PolicyID if no policy matches or toggle is disabled.
func (pe *PolicyEngine) Evaluate(ctx context.Context, pectx PolicyEvalContext) PolicyResult {
	// Toggle gate — when disabled, behave identically to pre-policy-engine behavior.
	// FeatureConditionalAccess is a DEFAULT-OFF security toggle: the registry
	// (toggle.registryDefaults) pins its absent-row default to false, so this
	// read agrees with the sibling gates (device_trust_gate.go) — the historical
	// unknown-key→true default once silently ENGAGED the engine on a drifted DB
	// whose row was missing while the sibling gates stayed off (a split-brain
	// read of one flag). Drifted-DB detection is the startup seed assertion
	// (toggle.RequireSeeded), not an unsafe read default here.
	if pe.toggles != nil && !pe.toggles.IsEnabled(toggle.FeatureConditionalAccess) {
		return PolicyResult{Decision: DecisionAllow, Reason: "conditional access disabled"}
	}

	// Break-glass / exclude short-circuits BEFORE any fail-closed branch (F7): an
	// eval error must never strand the excluded/break-glass admin.
	//
	// Two-layer check — either is sufficient:
	// 1. Internal snapshot (I1 fix): read pe.breakGlass under cacheMu BEFORE
	//    loadPolicies/geo-resolution can error out. This is the floor — it works
	//    without any per-server wiring and can never be forgotten by a caller.
	// 2. ExcludeChecker hook (CA-1/CA-3 richer exclusions, e.g. group membership).
	//    Kept working for future phases, but NOT depended on for system break-glass.
	pe.cacheMu.RLock()
	bgSnapshot := pe.breakGlass
	pe.cacheMu.RUnlock()
	if isBreakGlass(bgSnapshot, pectx.UserID) {
		return PolicyResult{Decision: DecisionAllow, Reason: "break-glass exempt"}
	}
	if pe.ExcludeChecker != nil && pe.ExcludeChecker(ctx, pectx) {
		return PolicyResult{Decision: DecisionAllow, Reason: "break-glass/excluded principal"}
	}

	policies, err := pe.loadPolicies(ctx)
	if err != nil {
		return pe.failModeDecision(err)
	}

	// Checked scope resolution (CA-SCOPE-RESOLUTION-FAIL-OPEN-CACHED). When the
	// store can resolve scopes with surfaced errors, the engine owns the
	// membership used by scope filtering, exclude matching, and the user_group
	// condition — for every user-scoped evaluation:
	//
	//   - a caller that resolved through an error-dropping wrapper (the
	//     deprecated threat.ResolveUserGroups/ResolveRoleGroups read a transient
	//     blip as silent empty membership) is repaired with the checked set;
	//   - a resolution FAILURE routes into failModeDecision — fail-CLOSED in the
	//     default posture (block unless the cache positively proves zero
	//     enforcing policies) — never a silent skip of group/role-scoped
	//     policies. The scope cache never stores failures, so recovery is
	//     honored on the next evaluation.
	//
	// This runs BEFORE the decision-cache lookup so the cache key hashes the
	// repaired membership and a wrong-membership verdict is neither served nor
	// stored. The signal-only-vs-fail-closed question for admin-configured
	// fail-open engines remains a flagged open tradeoff; the shipped arm is the
	// engine's default fail-closed posture.
	if pectx.UserID > 0 && pe.scopeResolver != nil {
		groups, roleGroups, scopeErr := pe.scopeResolver.ResolveUserScope(ctx, pectx.UserID)
		if scopeErr != nil {
			return pe.failModeDecision(fmt.Errorf("resolve CA scope for user %d: %w", pectx.UserID, scopeErr))
		}
		pectx.GroupIDs = groups
		pectx.RoleGroupIDs = roleGroups
	}

	// F8 per-principal decision cache: lookup BEFORE the expensive geo/trust
	// resolution so identical evals skip all computation on a hit.
	// Excluded: revocation-sensitive evals (CA-3a) and any eval where a candidate
	// policy carries time_of_day (checked after computing; see store below).
	// The key uses raw pectx fields — each is deterministic for its computed bucket
	// (Country → geoTier, SourceIP → scoreBand, DeviceFP → trustTier) so no
	// information is lost while avoiding the resolution calls on a cache hit.
	cacheable := !pectx.RevocationSensitive
	key := decisionCacheKey(pectx)
	if cacheable {
		if r, ok := pe.lookupDecision(key); ok {
			return pe.stampCorrelation(ctx, r, pectx)
		}
	}

	// Resolve computed attributes — geo tier is resolved once by resolveIPRiskChecked
	// and reused for both IP risk scoring and geo_risk_tier condition matching.
	// Mid-eval resolver errors (e.g. geo backend down) also route through failModeDecision.
	trustTier := pe.resolveTrustTier(ctx, pectx)
	score, scoreBand, geoTier, geoErr := pe.resolveIPRiskChecked(ctx, pectx)
	if geoErr != nil {
		return pe.failModeDecision(geoErr)
	}

	// Snapshot break-glass set, location cache, and auth-strength cache under read-lock before the scan.
	pe.cacheMu.RLock()
	breakGlass := pe.breakGlass
	locs := pe.namedLocations     // may be nil if LoadNamedLocations failed (see guard below)
	strengths := pe.authStrengths // may be nil if not yet loaded (evalGrant handles nil)
	pe.cacheMu.RUnlock()

	// Nil-locs fail-closed guard: matchNamedLocation returns false on a nil cache, which
	// makes condition matchers fail-closed at the matcher level — but for location_in /
	// location_trusted=false (block-if-outside-trusted) policies the condition NOT matching
	// means the block policy silently does NOT fire (fail-open at the access-control level).
	// The TTL is 30s, so a DB blip lasting > 30s means location-conditioned blocks are
	// unenforced. To close this window: if locs is nil AND any loaded policy carries a
	// location condition, route through failModeDecision (fail-closed by default, open if
	// admin configured). The scan is O(n) only on this rare error path.
	// ponytail: per-location-policy flag on PolicyRow would make this O(1); add when the
	// nil-blip window is measured as a real operational problem.
	if locs == nil {
		for _, p := range policies {
			if _, ok := p.Conditions["location_in"]; ok {
				return pe.failModeDecision(fmt.Errorf("named_locations cache unavailable; location_in condition cannot be evaluated"))
			}
			if _, ok := p.Conditions["location_trusted"]; ok {
				return pe.failModeDecision(fmt.Errorf("named_locations cache unavailable; location_trusted condition cannot be evaluated"))
			}
		}
	}

	// Pre-compute platform once from the UA so the hot path (matchAll) never
	// calls parseDevicePlatform per-policy, and A5/A6/simulator can inject directly.
	platform := parseDevicePlatform(pectx.UserAgent)

	var evaluated []policyOutcome
	var enforced *PolicyResult
	for _, p := range policies {
		// Exclude OVERRIDES include (Locked L1) — checked before scope/conditions.
		// A matching exclude (per-policy list or system break-glass) means the
		// principal is NOT subject to this policy; skip it entirely.
		if excludeMatches(p, pectx.UserID, pectx.GroupIDs, breakGlass) {
			evaluated = append(evaluated, policyOutcome{PolicyID: p.ID, Name: p.Name, Outcome: "excluded"})
			continue
		}

		// Scope filter
		if !scopeMatches(p.ScopeType, p.ScopeTarget, pectx.UserID, pectx.GroupIDs, pectx.RoleGroupIDs, pectx.IsGuest) {
			evaluated = append(evaluated, policyOutcome{PolicyID: p.ID, Name: p.Name, Outcome: "skipped"})
			continue
		}

		// Condition matching
		if !matchAll(p.Conditions, pectx, trustTier, scoreBand, geoTier, platform, locs) {
			evaluated = append(evaluated, policyOutcome{PolicyID: p.ID, Name: p.Name, Outcome: "skipped"})
			continue
		}

		decided := dispatchAction(p.Actions, p, pectx, strengths)

		// report_only NEVER enforces and does NOT shadow an `on` match (Locked L3):
		// log the would-be decision and continue scanning for an enforcing `on` policy.
		if p.State == "report_only" {
			evaluated = append(evaluated, policyOutcome{PolicyID: p.ID, Name: p.Name, Outcome: "would_" + decided.Decision.String()})
			pe.logger.InfoContext(ctx, "conditional access report-only match (not enforced)",
				"policy_id", p.ID,
				"policy_name", p.Name,
				"would_decision", decided.Decision.String(),
				"user_id", pectx.UserID,
				"source_ip", pectx.SourceIP,
			)
			continue // report-only never short-circuits enforcement
		}

		// state == "on": first enforcing match wins.
		if enforced == nil {
			evaluated = append(evaluated, policyOutcome{PolicyID: p.ID, Name: p.Name, Outcome: "applied"})
			d := decided
			enforced = &d
			pe.logger.InfoContext(ctx, "conditional access policy matched",
				"policy_id", p.ID,
				"policy_name", p.Name,
				"decision", decided.Decision.String(),
				"user_id", pectx.UserID,
				"source_ip", pectx.SourceIP,
				"trust_tier", trustTier,
				"ip_score", score,
				"ip_band", scoreBand,
				"geo_tier", geoTier,
			)
		} else {
			evaluated = append(evaluated, policyOutcome{PolicyID: p.ID, Name: p.Name, Outcome: "skipped"})
		}
	}

	var result PolicyResult
	if enforced != nil {
		enforced.Evaluated = evaluated
		result = *enforced
	} else {
		result = PolicyResult{Decision: DecisionAllow, Reason: "no matching policy (default allow)", Evaluated: evaluated}
	}

	// Store into the decision cache unless excluded:
	// - revocation-sensitive (already caught by cacheable=false above)
	// - any scope-matching candidate has time_of_day (decision can flip at a window boundary)
	// The cached result carries NO correlation id — it is minted per-event in
	// stampCorrelation at return, so a cache hit never replays a stale id.
	if cacheable && !anyTimeOfDay(policies, pectx) {
		pe.storeDecision(key, result)
	}

	return pe.stampCorrelation(ctx, result, pectx)
}

// stampCorrelation mints a FRESH per-evaluation correlation id on an enforcing
// (block/step_up) decision and logs it, so every sign-in event — including a
// decision-cache hit — gets a unique "why blocked" reference. The decision cache
// stores results without an id; this is the single mint+log choke point.
func (pe *PolicyEngine) stampCorrelation(ctx context.Context, r PolicyResult, pectx PolicyEvalContext) PolicyResult {
	if r.Decision == DecisionBlock || r.Decision == DecisionStepUp {
		r.CorrelationID = newCorrelationID()
		pe.logger.InfoContext(ctx, "conditional access enforcing decision",
			"policy_id", r.PolicyID, "policy_name", r.PolicyName,
			"decision", r.Decision.String(), "user_id", pectx.UserID,
			"source_ip", pectx.SourceIP, "correlation_id", r.CorrelationID)
	}
	return r
}

// EvaluateTokenACR enforces conditional-access acr requirements against an
// already-issued token. It is the downstream, post-authentication counterpart to
// Evaluate: a resource server (or a re-evaluation on a sensitive operation) calls
// it with the token's acr in pectx.CurrentACR. When a matched require_acr policy
// is not satisfied by that acr, the result is DecisionStepUp (the caller MUST
// reject / force re-auth — e.g. an aal1 token against an aal2 requirement). When
// no policy demands more than the token already carries, the result is
// DecisionAllow. Block/notify policies still take effect as in Evaluate.
//
// Satisfied is a convenience: true iff the decision is neither Block nor StepUp.
func (pe *PolicyEngine) EvaluateTokenACR(ctx context.Context, pectx PolicyEvalContext) (result PolicyResult, satisfied bool) {
	result = pe.Evaluate(ctx, pectx)
	satisfied = result.Decision != DecisionBlock && result.Decision != DecisionStepUp
	return result, satisfied
}

// ReferencedConditions returns the set of condition keys that any ENABLED policy
// in the slice references. The runtime middleware uses it to skip device-trust
// and IP/geo resolution entirely when no enabled policy needs them — the common
// hot-path case is then a cheap map lookup, not a GeoIP/device call.
func (pe *PolicyEngine) ReferencedConditions(policies []PolicyRow) map[string]bool {
	ref := make(map[string]bool)
	for _, p := range policies {
		// ponytail: Enabled is never scanned from DB (State supersedes it per struct comment);
		// check State so report_only policies still warm the condition set.
		if p.State != "on" && p.State != "report_only" {
			continue
		}
		for k, v := range p.Conditions {
			if v != nil && v != "" {
				ref[k] = true
			}
		}
	}
	return ref
}

// loadPolicies returns cached raw policies when the cache is fresh, otherwise
// reloads the UNFILTERED set from the store AND refreshes the namedLocations /
// authStrengths caches in the same pass (CA-1 A7). Scope-filtering happens per-request
// in Evaluate via scopeMatches — the cache never holds a user-specific subset
// (the cross-user leak fix, F2a).
//
// Location and auth-strength load errors are logged but do NOT abort the policy load.
// Named-location errors: Evaluate carries a nil-locs guard that calls failModeDecision
// when any loaded policy has a location_in/location_trusted condition, so location-
// conditioned blocks cannot silently disengage during a DB blip (fail-closed for
// access-control, not just matcher-level). Auth-strength errors degrade gracefully
// (evalGrant handles nil strengths — require_strength actions fall back to "no match").
// ponytail: separate error paths; upgrade to a combined query if round-trip cost matters.
func (pe *PolicyEngine) loadPolicies(ctx context.Context) ([]PolicyRow, error) {
	pe.cacheMu.RLock()
	if time.Since(pe.cachedAt) < pe.cacheTTL && pe.cachedPolicies != nil {
		cached := pe.cachedPolicies
		pe.cacheMu.RUnlock()
		return cached, nil
	}
	pe.cacheMu.RUnlock()

	policies, err := pe.store.LoadAllPolicies(ctx)
	if err != nil {
		return nil, err
	}

	// Refresh location + auth-strength caches in the same cache-miss window.
	if locs, locErr := pe.store.LoadNamedLocations(ctx); locErr != nil {
		pe.logger.Warn("conditional access: failed to load named_locations", "error", locErr)
	} else {
		pe.setNamedLocations(locs)
	}
	if strengths, sErr := pe.store.LoadAuthStrengths(ctx); sErr != nil {
		pe.logger.Warn("conditional access: failed to load auth_strengths", "error", sErr)
	} else {
		pe.setAuthStrengths(strengths)
	}

	pe.cacheMu.Lock()
	pe.cachedPolicies = policies
	pe.cachedAt = time.Now()
	pe.cacheLoaded = true // SUCCESSFULLY loaded — safe to interpret zero enforcing as "none exist"
	pe.cacheMu.Unlock()

	return policies, nil
}

// EvaluateWithPolicies runs the policy engine against an EXPLICIT policy/location/strength
// set (caller-supplied) WITHOUT touching the in-memory cache. Intended for the
// policy simulator (A8) and admin dry-run handlers where the caller controls the
// exact policy document under evaluation.
//
// Decision-cache is NOT consulted or populated (uncached path): each simulator
// call is independent and must NOT bleed into live Evaluate verdicts.
func (pe *PolicyEngine) EvaluateWithPolicies(
	ctx context.Context,
	pectx PolicyEvalContext,
	policies []PolicyRow,
	locs []NamedLocation,
	strengths []AuthStrength,
) PolicyResult {
	// Build location map from the caller-supplied slice (no cache write; simulator path).
	locMap := buildLocMap(locs)

	// Build strength map from the caller-supplied slice.
	strMap := make(map[int64]AuthStrength, len(strengths))
	for _, s := range strengths {
		strMap[s.ID] = s
	}

	// Snapshot break-glass (live engine field; simulator still respects break-glass).
	pe.cacheMu.RLock()
	breakGlass := pe.breakGlass
	pe.cacheMu.RUnlock()

	// Resolve geo/trust. Unlike Evaluate (which fails-closed on geoErr), the simulator
	// fails gracefully — geoTier defaults to "low" so the admin can still preview
	// non-geo policies. Log the error so the caller knows the geo tier is degraded.
	// ponytail: intentional divergence from Evaluate; add PolicyResult.GeoError field
	// if callers need a structured indicator that geo was unavailable during simulation.
	trustTier := pe.resolveTrustTier(ctx, pectx)
	score, scoreBand, geoTier, geoErr := pe.resolveIPRiskChecked(ctx, pectx)
	if geoErr != nil {
		pe.logger.WarnContext(ctx, "conditional access simulator: geo resolution failed; geoTier defaults to low", "error", geoErr)
	}
	_ = score // used only for logging in Evaluate; simulator callers don't need it

	platform := parseDevicePlatform(pectx.UserAgent)

	var evaluated []policyOutcome
	var enforced *PolicyResult
	for _, p := range policies {
		o := policyOutcome{PolicyID: p.ID, Name: p.Name, Priority: p.Priority, Scope: p.ScopeType}
		if excludeMatches(p, pectx.UserID, pectx.GroupIDs, breakGlass) {
			o.Outcome = "excluded"
			evaluated = append(evaluated, o)
			continue
		}
		if !scopeMatches(p.ScopeType, p.ScopeTarget, pectx.UserID, pectx.GroupIDs, pectx.RoleGroupIDs, pectx.IsGuest) {
			// ponytail: scope: prefix lets the UI distinguish scope miss from condition miss.
			o.Outcome = "skipped"
			o.FirstFailed = "scope:" + p.ScopeType
			evaluated = append(evaluated, o)
			continue
		}
		condOK, firstFailed := matchAllVerbose(p.Conditions, pectx, trustTier, scoreBand, geoTier, platform, locMap)
		if !condOK {
			o.Outcome = "skipped"
			o.FirstFailed = firstFailed
			evaluated = append(evaluated, o)
			continue
		}
		decided := dispatchAction(p.Actions, p, pectx, strMap)
		if p.State == "report_only" {
			o.Outcome = "would_" + decided.Decision.String()
			evaluated = append(evaluated, o)
			continue
		}
		if enforced == nil {
			o.Outcome = "applied"
			evaluated = append(evaluated, o)
			d := decided
			enforced = &d
		} else {
			o.Outcome = "skipped"
			// ponytail: first_failed omitted — conditions matched; shadowed by higher-priority policy.
			evaluated = append(evaluated, o)
		}
	}

	if enforced != nil {
		enforced.Evaluated = evaluated
		return *enforced
	}
	return PolicyResult{Decision: DecisionAllow, Reason: "no matching policy (default allow)", Evaluated: evaluated}
}

// SimulateEntry is the per-policy trace row returned by SimulateWithPolicies.
// It mirrors policyOutcome — the extra Priority/Scope/FirstFailed fields are
// now populated by EvaluateWithPolicies so SimulateWithPolicies is a thin wrapper.
// ponytail: kept as a distinct exported type for the handler's JSON response shape;
// the internal policyOutcome type remains unexported.
type SimulateEntry struct {
	PolicyID    int64  `json:"policy_id"`
	Name        string `json:"name"`
	Priority    int    `json:"priority"`
	Scope       string `json:"scope"`                  // scope_type value ("global","user","group","role")
	Outcome     string `json:"outcome"`                // applied|would_block|would_step_up|would_notify|skipped|excluded
	FirstFailed string `json:"first_failed,omitempty"` // first condition key that returned false, or "scope:<type>"
}

// SimulateResult is the full response from SimulateWithPolicies.
type SimulateResult struct {
	// MatchedPolicy is the ID of the first enforcing or report-only policy that
	// matched all conditions, or nil when no policy matched (default-allow path).
	MatchedPolicy *int64 `json:"matched_policy"`
	// Decision is the canonical 6-value outcome string. When no policy matches,
	// Decision is "applied" (default-allow calm path). Never empty.
	Decision string `json:"decision"`
	// Grants are the action grants from the matched policy (nil/empty on default-allow).
	Grants []Grant `json:"grants,omitempty"`
	// Evaluated is the full per-policy trace ordered by priority.
	Evaluated []SimulateEntry `json:"evaluated"`
}

// SimulateWithPolicies is the diagnostic twin of EvaluateWithPolicies: delegates to
// EvaluateWithPolicies (which now uses matchAllVerbose and fills Priority/Scope/FirstFailed
// on every policyOutcome row) and converts the result to SimulateResult.
//
// Read-only: no cache read/write, no ca_signin_log append, no enforcement.
// ponytail: was a duplicate 85-line loop; now a thin wrapper (~20 lines).
// The SimulateEntry type is kept for the handler's exported JSON shape.
func (pe *PolicyEngine) SimulateWithPolicies(
	ctx context.Context,
	pectx PolicyEvalContext,
	policies []PolicyRow,
	locs []NamedLocation,
	strengths []AuthStrength,
) SimulateResult {
	r := pe.EvaluateWithPolicies(ctx, pectx, policies, locs, strengths)

	entries := make([]SimulateEntry, len(r.Evaluated))
	for i, o := range r.Evaluated {
		entries[i] = SimulateEntry{
			PolicyID:    o.PolicyID,
			Name:        o.Name,
			Priority:    o.Priority,
			Scope:       o.Scope,
			Outcome:     o.Outcome,
			FirstFailed: o.FirstFailed,
		}
	}

	var matchedID *int64
	var grants []Grant
	decision := "applied" // default-allow calm path
	if r.PolicyID != 0 {
		id := r.PolicyID
		matchedID = &id
		decision = r.Decision.String()
		// Re-derive grants from the matched policy's actions.
		for _, p := range policies {
			if p.ID == r.PolicyID {
				_, grants = parseGrants(p.Actions)
				break
			}
		}
	}

	return SimulateResult{
		MatchedPolicy: matchedID,
		Decision:      decision,
		Grants:        grants,
		Evaluated:     entries,
	}
}

// SetBreakGlass sets the system break-glass user-id set (CA-0a). These users are
// excluded from every policy in Evaluate. Loaded with the policies; refreshed on
// cache invalidation. Safe for concurrent reads in Evaluate (set at load time).
func (pe *PolicyEngine) SetBreakGlass(ids []int64) {
	pe.cacheMu.Lock()
	pe.breakGlass = ids
	pe.cacheMu.Unlock()
}

// InvalidateCache clears the in-memory policy cache so the next evaluation
// reloads from the database. Safe for concurrent use. Called from the
// "conditional_access" NOTIFY listener on both servers when CA policies change.
// Also flushes the F8 per-principal decision cache so stale verdicts are dropped.
func (pe *PolicyEngine) InvalidateCache() {
	pe.cacheMu.Lock()
	pe.cachedPolicies = nil
	pe.cachedAt = time.Time{}
	pe.namedLocations = nil // flush location cache alongside policy cache (CA-1 A2)
	pe.authStrengths = nil  // flush auth-strength cache alongside policy cache (CA-1 A3)
	pe.cacheMu.Unlock()

	pe.decisionMu.Lock()
	pe.decisionCache = nil // flush the layered decision cache too (F8)
	pe.decisionMu.Unlock()
}

// buildLocMap converts a slice of NamedLocation into a map keyed by ID with CIDRs
// pre-parsed into netip.Prefix so ipInLocation never calls ParsePrefix on the hot path.
// Called by both setNamedLocations (cache path) and EvaluateWithPolicies (simulator path).
func buildLocMap(locs []NamedLocation) map[int64]NamedLocation {
	m := make(map[int64]NamedLocation, len(locs))
	for _, l := range locs {
		pfxs := make([]netip.Prefix, 0, len(l.CIDRs))
		for _, cidr := range l.CIDRs {
			if pfx, err := netip.ParsePrefix(cidr); err == nil {
				pfxs = append(pfxs, pfx)
			}
		}
		l.parsedCIDRs = pfxs
		m[l.ID] = l
	}
	return m
}

// setNamedLocations replaces the engine's cached location set under the cache lock (CA-1 A2).
// CIDRs are pre-parsed here so ipInLocation never calls netip.ParsePrefix on the hot path.
func (pe *PolicyEngine) setNamedLocations(locs []NamedLocation) {
	m := buildLocMap(locs)
	pe.cacheMu.Lock()
	pe.namedLocations = m
	pe.cacheMu.Unlock()
}

// decisionCacheKey hashes the BUCKETED input signals so the key space stays small.
// Uses raw pectx fields that each deterministically determine their computed bucket
// (Country → geoTier, SourceIP → scoreBand, DeviceFP → trustTier, UserAgent →
// platform bucket via parseDevicePlatform), avoiding the geo/trust/score resolution
// on a cache hit. Fields: principal | protocol | client_type | country | source_ip |
// device_fp | auth_method | acr | user_agent | group_ids | role_group_ids |
// completed_factors | enroll_state | device_bound | is_guest | risk_level.
//
// UserAgent is included because matchDevicePlatform branches on parseDevicePlatform(UA)
// — two requests with the same UserID/SourceIP/DeviceFP but different UAs (e.g. iOS
// vs Android) must NOT share a cached decision when a device_platform condition is
// present. The raw UA is hashed (not the parsed bucket) consistent with the raw-field
// pattern above; parseDevicePlatform is deterministic so the mapping is injective.
//
// GroupIDs are included because scopeMatches (group-scope policies) and
// matchUserGroup (group condition) both branch on group membership — two evals
// with the same UserID but different GroupIDs must NOT collide. RoleGroupIDs are
// included for the same reason: scopeMatches 'role' case branches on role membership.
// Both slices are sorted ascending before hashing so the same membership set always
// produces the same key regardless of order.
// CompletedFactors is included because require_strength dispatch (CA-F) branches on
// it — two sessions with the same user/ACR but different completed factors must NOT
// collide (one would receive the other's allow/block). Sorted ascending for
// order-independence (same set, different slice order → same key).
// IsGuest is included because scopeMatches branches on it ('guests' scope
// policies) and RiskLevel because require_risk_remediation dispatches on the
// band — a guest→member or risk-level transition mid-TTL must not serve the
// other side's cached verdict (D-SHARED-THREAT-007).
func decisionCacheKey(pectx PolicyEvalContext) uint64 {
	h := fnv.New64a()
	_, _ = io.WriteString(h, strconv.FormatInt(pectx.UserID, 10))
	for _, s := range []string{pectx.Protocol, pectx.ClientType, pectx.Country, pectx.SourceIP, pectx.DeviceFP, pectx.AuthMethod, pectx.CurrentACR, pectx.UserAgent} {
		_, _ = io.WriteString(h, "|")
		_, _ = io.WriteString(h, s)
	}
	// DeviceBound (CA-2): require_compliant_device + device_bound conditions branch on this.
	// Two evals with the same user/DeviceFP but different DeviceBound (e.g. HMAC verified
	// vs not) must NOT collide — the verdicts differ.
	if pectx.DeviceBound {
		_, _ = io.WriteString(h, "|db:1")
	} else {
		_, _ = io.WriteString(h, "|db:0")
	}
	_, _ = io.WriteString(h, "|es:")
	_, _ = io.WriteString(h, pectx.EnrollState)
	// IsGuest (CA narrow-race hardening, D-SHARED-THREAT-007): scopeMatches
	// branches on it (scope_type='guests' policies), so a guest→member
	// transition mid-TTL must not serve the other side's cached verdict.
	if pectx.IsGuest {
		_, _ = io.WriteString(h, "|ig:1")
	} else {
		_, _ = io.WriteString(h, "|ig:0")
	}
	// RiskLevel (same hardening): require_risk_remediation dispatch branches
	// on the risk band (policy_actions.go), so verdicts must not collide
	// across bands.
	_, _ = io.WriteString(h, "|rl:")
	_, _ = io.WriteString(h, pectx.RiskLevel)
	// Hash GroupIDs order-independently: copy → sort ascending → write each int64.
	// Separator byte 0xFF between elements distinguishes {1,23} from {12,3}.
	ids := make([]int64, len(pectx.GroupIDs))
	copy(ids, pectx.GroupIDs)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	_, _ = io.WriteString(h, "|g")
	var buf [8]byte
	for _, gid := range ids {
		binary.LittleEndian.PutUint64(buf[:], uint64(gid))
		_, _ = h.Write(buf[:])
		_, _ = h.Write([]byte{0xFF})
	}
	// Hash RoleGroupIDs (admin role groups) — same pattern as GroupIDs.
	rids := make([]int64, len(pectx.RoleGroupIDs))
	copy(rids, pectx.RoleGroupIDs)
	sort.Slice(rids, func(i, j int) bool { return rids[i] < rids[j] })
	_, _ = io.WriteString(h, "|r")
	for _, rid := range rids {
		binary.LittleEndian.PutUint64(buf[:], uint64(rid))
		_, _ = h.Write(buf[:])
		_, _ = h.Write([]byte{0xFF})
	}
	// Hash CompletedFactors (e.g. "password","webauthn") — require_strength dispatch
	// (CA-F) branches on these, so different completed-factor sets must NOT collide.
	// ponytail: sorted strings, same pattern as GroupIDs/RoleGroupIDs; 0xFF separator
	// prevents {ab,c} ≡ {a,bc} collisions.
	factors := make([]string, len(pectx.CompletedFactors))
	copy(factors, pectx.CompletedFactors)
	sort.Strings(factors)
	_, _ = io.WriteString(h, "|f")
	for _, f := range factors {
		_, _ = io.WriteString(h, f)
		_, _ = h.Write([]byte{0xFF})
	}
	return h.Sum64()
}

// lookupDecision checks the F8 decision cache for a live (non-expired) entry.
func (pe *PolicyEngine) lookupDecision(key uint64) (PolicyResult, bool) {
	pe.decisionMu.Lock()
	defer pe.decisionMu.Unlock()
	if pe.decisionCache == nil {
		return PolicyResult{}, false
	}
	cd, ok := pe.decisionCache[key]
	if !ok || time.Now().After(cd.expiry) {
		return PolicyResult{}, false
	}
	return cd.result, true
}

// storeDecision saves a PolicyResult into the F8 decision cache with a TTL.
// On overflow (>maxDecisionCacheEntries) the cache is cleared rather than grown unbounded.
func (pe *PolicyEngine) storeDecision(key uint64, result PolicyResult) {
	pe.decisionMu.Lock()
	defer pe.decisionMu.Unlock()
	if pe.decisionCache == nil {
		pe.decisionCache = make(map[uint64]cachedDecision)
	}
	if len(pe.decisionCache) >= maxDecisionCacheEntries {
		pe.decisionCache = make(map[uint64]cachedDecision) // bounded: clear on overflow
	}
	pe.decisionCache[key] = cachedDecision{result: result, expiry: time.Now().Add(decisionCacheTTL)}
}

// anyTimeOfDay reports whether any scope-matching candidate policy carries a
// time_of_day condition (those decisions must never be cached — they flip at a
// window boundary).
func anyTimeOfDay(policies []PolicyRow, pectx PolicyEvalContext) bool {
	for _, p := range policies {
		if !scopeMatches(p.ScopeType, p.ScopeTarget, pectx.UserID, pectx.GroupIDs, pectx.RoleGroupIDs, pectx.IsGuest) {
			continue
		}
		if _, ok := p.Conditions["time_of_day"]; ok {
			return true
		}
	}
	return false
}

// resolveTrustTier computes the device trust tier for the evaluation context.
// TrustTierOverride (set by the simulator) short-circuits the DeviceTrustResolver.
func (pe *PolicyEngine) resolveTrustTier(ctx context.Context, pectx PolicyEvalContext) string {
	if pectx.TrustTierOverride != "" {
		return pectx.TrustTierOverride // ponytail: simulator inject; never set on live path
	}
	if pe.deviceTrust != nil {
		return pe.deviceTrust.Resolve(ctx, pectx.DeviceFP, pectx.UserID, pe.isVPN(pectx))
	}
	return "unknown"
}

// resolveIPRiskChecked computes the IP risk score, band, and country risk tier,
// returning any geo-tier resolver error so the caller can route it through
// failModeDecision (F7 mid-eval error path). Evaluate uses this form.
func (pe *PolicyEngine) resolveIPRiskChecked(ctx context.Context, pectx PolicyEvalContext) (score int, band string, tier string, err error) {
	tier = "low"
	if pectx.Country != "" && pe.store != nil {
		if t, geoErr := pe.store.ResolveGeoTier(ctx, pectx.Country); geoErr != nil {
			return 0, "low", "low", geoErr
		} else {
			tier = t
		}
	}
	if pe.ipRisk != nil {
		score, band = pe.ipRisk.ScoreWithTier(ctx, pectx.SourceIP, tier)
		return score, band, tier, nil
	}
	return 0, "low", tier, nil
}

// resolveIPRisk is a thin wrapper around resolveIPRiskChecked that drops the
// error (swallowing geo failures as "low" tier). Kept for any callers that do
// not need to surface mid-eval resolver errors.
func (pe *PolicyEngine) resolveIPRisk(ctx context.Context, pectx PolicyEvalContext) (score int, band string, tier string) {
	score, band, tier, _ = pe.resolveIPRiskChecked(ctx, pectx)
	return score, band, tier
}

// ── F7: fail-closed posture helpers ─────────────────────────────────────────

// failModeDecision converts an eval error into a decision per the F7 posture.
//
// Single source of truth: consults ONLY pe.failMode (pe.failClosed is mapped to
// pe.failMode="closed" at construction time; it is not read here).
//
// "closed" mode decision table:
//
//	cache never successfully loaded (cold-boot / DB-down)  → BLOCK
//	  (we cannot prove it is safe; enforcing policies may exist but couldn't load)
//	cache loaded, enforcing block/require policy present    → BLOCK
//	cache loaded, zero enforcing policies confirmed         → ALLOW
//	  (spec "zero enforcing → allow" — only when we POSITIVELY KNOW there are zero)
//
// "open" mode → ALLOW regardless of cache state.
func (pe *PolicyEngine) failModeDecision(err error) PolicyResult {
	if pe.failMode != "closed" {
		pe.logger.Warn("conditional access: eval error, failing open",
			"error", err, "fail_mode", pe.failMode)
		return PolicyResult{Decision: DecisionAllow, Reason: "eval error (fail open)"}
	}

	// "closed" mode: check cache state.
	pe.cacheMu.RLock()
	loaded := pe.cacheLoaded
	pe.cacheMu.RUnlock()

	if !loaded {
		// Cold-boot or DB-down: we have never successfully loaded policies.
		// We cannot prove it is safe to allow — BLOCK.
		pe.logger.Error("conditional access: eval error, cache never loaded — failing CLOSED (cold-boot safe default)",
			"error", err, "fail_mode", pe.failMode)
		return PolicyResult{Decision: DecisionBlock, Reason: "eval error (fail closed — cache never loaded)"}
	}

	if pe.hasEnforcingBlockPolicy() {
		pe.logger.Error("conditional access: eval error, failing CLOSED — enforcing policy present",
			"error", err, "fail_mode", pe.failMode)
		return PolicyResult{Decision: DecisionBlock, Reason: "eval error (fail closed)"}
	}

	// Cache was successfully loaded and confirms zero enforcing policies — safe to allow.
	pe.logger.Warn("conditional access: eval error, failing open — no enforcing policy in cache",
		"error", err, "fail_mode", pe.failMode)
	return PolicyResult{Decision: DecisionAllow, Reason: "eval error (fail open — no enforcing policy)"}
}

// hasEnforcingBlockPolicy reports whether the last-known cached policy set holds
// at least one enforcing action (block / require_acr / require_strength /
// require_terms / require_risk_remediation / require_compliant_device).
//
// Back-compat: policies with State=="" (pre-Task-6 loads that predate the State
// field) are treated as enforcing — the historic default is "on". Only the
// explicit non-enforcing states ("report_only", "off") are excluded.
func (pe *PolicyEngine) hasEnforcingBlockPolicy() bool {
	pe.cacheMu.RLock()
	defer pe.cacheMu.RUnlock()
	for _, p := range pe.cachedPolicies {
		// report_only and off are never enforcing; "" and "on" are.
		if p.State == "report_only" || p.State == "off" {
			continue
		}
		if isEnforcingActions(p.Actions) {
			return true
		}
	}
	return false
}

// isEnforcingActions reports whether an actions map contains at least one
// enforcing grant (block/require_acr/require_strength). Handles both the legacy
// single-action form {"action":"block"} and the canonical grants array.
func isEnforcingActions(actions map[string]interface{}) bool {
	// require_terms and require_risk_remediation are CA-3b block verbs: both produce
	// DecisionBlock on the normal eval path, so they are enforcing for fail-closed mode.
	// Omitting them causes failModeDecision to fail-open when the only active policies
	// use these verbs — a known security gap (CA-3b T4 confirmed finding).
	enforcingTypes := map[string]bool{
		"block":                    true,
		"require_acr":              true,
		"require_strength":         true,
		"require_terms":            true,
		"require_risk_remediation": true,
	}
	// require_compliant_device is enforcing (blocks non-compliant devices; CA-2).
	if rcd, _ := actions["require_compliant_device"].(bool); rcd {
		return true
	}
	// Legacy single-action form.
	if a, _ := actions["action"].(string); enforcingTypes[a] {
		return true
	}
	// Canonical grants array form.
	if rawValue, exists := actions["grants"]; exists {
		raw, ok := rawValue.([]interface{})
		if !ok || len(raw) == 0 {
			return true
		}
		for _, g := range raw {
			gm, ok := g.(map[string]interface{})
			if !ok {
				return true
			}
			t, invalid := grantDiscriminator(gm)
			if invalid || t == "" || !allowedActions[t] {
				// Runtime dispatch blocks malformed/unknown grants, so fail-mode
				// classification must also treat them as enforcing.
				return true
			}
			if enforcingTypes[t] {
				return true
			}
		}
	}
	return false
}

// CheckFailModePosture logs a loud startup warning when the engine boots in
// "open" mode while enforcing block policies exist — an eval error then will
// NOT enforce. Call once after the first policy load at startup.
func (pe *PolicyEngine) CheckFailModePosture() {
	if pe.failMode == "open" && pe.hasEnforcingBlockPolicy() {
		pe.logger.Warn("CA fail-open with enforcing block policies present — an eval error will NOT enforce",
			"fail_mode", pe.failMode)
	}
}

// isVPN checks if the connection appears to be from a VPN/proxy.
// This is a placeholder; the full implementation uses GeoIP Anonymous IP DB.
func (pe *PolicyEngine) isVPN(pectx PolicyEvalContext) bool {
	// VPN detection is handled by IPRiskScorer via GeoIP Anonymous IP DB
	return false
}

// ── CA-1 A3: device-platform + country_in matchers; AuthStrength type + cache ──

// AuthStrength is an ordered authenticator-combination requirement loaded from
// auth_strengths. Outer slice = OR alternatives; inner slice = AND combinators.
// Builtin strengths (phishing-resistant/passwordless/mfa) are seeded in V030.
type AuthStrength struct {
	ID           int64      `json:"id"`
	Slug         string     `json:"slug"`
	Name         string     `json:"name"`
	Builtin      bool       `json:"builtin"`
	Combinations [][]string `json:"combinations"` // mirrors auth_strengths.requirement
	MinACR       string     `json:"min_acr"`
}

// setAuthStrengths replaces the engine's cached auth-strength set under the cache
// lock, mirroring setNamedLocations. No pre-parse needed (Combinations is already
// [][]string). Call after loading auth_strengths from the DB.
func (pe *PolicyEngine) setAuthStrengths(strengths []AuthStrength) {
	m := make(map[int64]AuthStrength, len(strengths))
	for _, s := range strengths {
		m[s.ID] = s
	}
	pe.cacheMu.Lock()
	pe.authStrengths = m
	pe.cacheMu.Unlock()
}

// ── Scope ──

// scopeMatches checks if the policy's scope includes the current principal.
func scopeMatches(scopeType, scopeTarget string, userID int64, groupIDs, roleGroupIDs []int64, isGuest bool) bool {
	switch scopeType {
	case "global":
		return true
	case "user":
		if scopeTarget == "" {
			return false
		}
		targetID, err := strconv.ParseInt(scopeTarget, 10, 64)
		return err == nil && targetID == userID
	case "group":
		if scopeTarget == "" {
			return false
		}
		targetID, err := strconv.ParseInt(scopeTarget, 10, 64)
		if err != nil {
			return false
		}
		for _, gid := range groupIDs {
			if gid == targetID {
				return true
			}
		}
		return false
	case "role":
		// role scope matches when the principal holds the target admin role-group
		// (via admin_role_assignments, resolved as ResolveRoleGroups → pectx.RoleGroupIDs).
		// An empty RoleGroupIDs means no admin roles — no role-scoped policy fires.
		if scopeTarget == "" {
			return false
		}
		targetID, err := strconv.ParseInt(scopeTarget, 10, 64)
		if err != nil {
			return false
		}
		for _, rid := range roleGroupIDs {
			if rid == targetID {
				return true
			}
		}
		return false
	case "guests":
		// Guest scope is a set, not an id-targeted scope. Reject a target so a
		// malformed imported policy cannot look configured while matching.
		return scopeTarget == "" && isGuest
	default:
		return false
	}
}

// isBreakGlass reports whether userID appears in the system break-glass snapshot.
// Used by Evaluate for the early short-circuit (I1 fix) — must execute BEFORE
// loadPolicies so a DB/geo error can never strand a break-glass admin.
func isBreakGlass(breakGlass []int64, userID int64) bool {
	for _, id := range breakGlass {
		if id == userID {
			return true
		}
	}
	return false
}

// excludeMatches reports whether the principal is excluded from a policy
// (break-glass). Exclude OVERRIDES include (Locked L1): a match means the policy
// is skipped entirely for this principal. True iff userID is in the policy's
// ExcludeUsers, or any of the principal's groups is in ExcludeGroups, or userID
// is in the system break-glass set.
func excludeMatches(p PolicyRow, userID int64, groupIDs []int64, breakGlass []int64) bool {
	for _, u := range p.ExcludeUsers {
		if u == userID {
			return true
		}
	}
	for _, b := range breakGlass {
		if b == userID {
			return true
		}
	}
	for _, eg := range p.ExcludeGroups {
		for _, g := range groupIDs {
			if eg == g {
				return true
			}
		}
	}
	return false
}

// ── Helpers ──

// toInt64 converts an interface{} (from JSON number) to int64.
func toInt64(v interface{}) (int64, error) {
	switch n := v.(type) {
	case float64:
		return int64(n), nil
	case int64:
		return n, nil
	case int:
		return int64(n), nil
	case string:
		return strconv.ParseInt(n, 10, 64)
	default:
		return 0, fmt.Errorf("cannot convert %T to int64", v)
	}
}
