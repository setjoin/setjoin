package threat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ── Scope cache ──

// scopeCacheTTL is the per-user group/role-group resolution cache TTL.
// ponytail: 60s matches the policy cache TTL (30s) × 2 — group membership
// changes are low-frequency admin ops; upgrade to pg_notify invalidation if
// sub-minute responsiveness is needed.
const scopeCacheTTL = 60 * time.Second

// scopeCacheEntry is a cached result for one user.
type scopeCacheEntry struct {
	groups     []int64
	roleGroups []int64
	expiresAt  time.Time
}

// scopeCache is a bounded per-user LRU-by-TTL cache of resolved group/role-group IDs.
// It is SEPARATE from the PolicyEngine policy-set and decision caches:
// PolicyEngine.InvalidateCache() never touches it. Per-user isolation is guaranteed
// by sync.Map — each key is a unique int64 userID, so one user's entry cannot
// contaminate another's.
//
// ponytail: sync.Map grows unbounded until entries expire; add an explicit size cap
// and LRU eviction if the user population grows past ~10k active sessions.
type scopeCache struct {
	m     sync.Map // int64(userID) → scopeCacheEntry
	ttl   time.Duration
	now   func() time.Time // injectable for tests; production: time.Now
	fetch scopeCacheFetch  // injectable for tests; production: queries user_group_members + admin_role_assignments
}

// scopeCacheFetch is the DB-fetch function type used by scopeCache.
type scopeCacheFetch func(ctx context.Context, userID int64) (groups, roleGroups []int64, err error)

// resolve returns the cached (groups, roleGroups) for userID, or fetches from DB on miss/expiry.
func (sc *scopeCache) resolve(ctx context.Context, userID int64) ([]int64, []int64, error) {
	now := sc.now()
	if raw, ok := sc.m.Load(userID); ok {
		e := raw.(scopeCacheEntry)
		if now.Before(e.expiresAt) {
			return e.groups, e.roleGroups, nil
		}
	}
	groups, roleGroups, err := sc.fetch(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	sc.m.Store(userID, scopeCacheEntry{
		groups:     groups,
		roleGroups: roleGroups,
		expiresAt:  now.Add(sc.ttl),
	})
	return groups, roleGroups, nil
}

// lockoutKeys returns the three lockout keys in the canonical order used
// everywhere in the pipeline: ip, user, ip_user. Centralised so Check/
// Escalate/Reset can never drift apart. The username is normalised
// case-insensitively (account lookup is lower(email)-based): the username is
// attacker-supplied, so spelling rotation ("victim@x.com" vs "Victim@X.com")
// must not split one identity across multiple user:/ip_user: keys and reset
// its escalation counters.
func lockoutKeys(sourceIP, username string) []string {
	username = strings.ToLower(username)
	return []string{"ip:" + sourceIP, "user:" + username, "ip_user:" + sourceIP + ":" + username}
}

// ── LockoutStore ──

// LockoutStore abstracts auth_lockouts access for LockoutManager.
type LockoutStore interface {
	// IsLocked reports whether any key is currently locked and the longest remaining duration.
	IsLocked(ctx context.Context, keys []string) (bool, time.Duration, error)
	// Escalate bumps the lockout counter for a single key (calls lockout_escalate()).
	Escalate(ctx context.Context, key string) error
	// Clear removes all lockouts for the given keys.
	Clear(ctx context.Context, keys []string) error
}

// pgxLockoutStore is the production LockoutStore. pool is the WORKER
// credential (DB_WORKER_DSN; it aliases the request pool until that DSN is
// set — the W1b INERT convention): auth_lockouts is deny-all FORCE RLS under
// V259, so every statement below goes through the worker-owned SECURITY
// DEFINER accessors (authserver/sql/reducers/lockout_accessors.sql,
// lockout_escalate.sql) rather than touching the table directly.
type pgxLockoutStore struct{ pool *pgxpool.Pool }

func (s *pgxLockoutStore) IsLocked(ctx context.Context, keys []string) (bool, time.Duration, error) {
	// lockout_check folds the two pre-refactor probes (EXISTS + longest
	// remaining) into ONE worker-owned SECURITY DEFINER call; the result
	// shape matches the old scans exactly (locked, remaining seconds of the
	// LONGEST active lock).
	var locked bool
	var remainingSecs float64
	if err := s.pool.QueryRow(ctx,
		`SELECT locked, remaining_seconds FROM lockout_check($1)`,
		keys).Scan(&locked, &remainingSecs); err != nil {
		return false, 0, err
	}
	if !locked {
		return false, 0, nil
	}
	return true, time.Duration(remainingSecs) * time.Second, nil
}

func (s *pgxLockoutStore) Escalate(ctx context.Context, key string) error {
	// lockout_escalate($1) — unchanged resolution; the mutator converted in
	// place to a worker-owned SECURITY DEFINER (lockout_escalate.sql).
	_, err := s.pool.Exec(ctx, `SELECT lockout_escalate($1)`, key)
	return err
}

func (s *pgxLockoutStore) Clear(ctx context.Context, keys []string) error {
	// lockout_clear (lockout_accessors.sql): the auth-success reset DELETE,
	// behind the worker-owned definer; the deleted-row count is not needed here.
	_, err := s.pool.Exec(ctx, `SELECT lockout_clear($1)`, keys)
	return err
}

// ── SprayStore ──

// SprayStore abstracts password-spray detection + its side effects for SprayDetector.
type SprayStore interface {
	Detect(ctx context.Context, sourceIP string, windowSecs, maxUsers int) (bool, error)
	LockIP(ctx context.Context, sourceIP string, lockoutMins int) error
	Audit(ctx context.Context, sourceIP string, metaJSON []byte) error
	Notify(ctx context.Context, sourceIP string) error
}

// pgxSprayStore is the production SprayStore. pool is the WORKER credential
// (same W1b aliasing convention as pgxLockoutStore): the detector's
// attack-accounting writes (auth_lockouts via lockout_arm) ride the worker
// credential under the V259 deny-all FORCE posture.
type pgxSprayStore struct{ pool *pgxpool.Pool }

func (s *pgxSprayStore) Detect(ctx context.Context, sourceIP string, windowSecs, maxUsers int) (bool, error) {
	// SQL lifted verbatim from interceptor.go step 5 (spray detection), pre-refactor.
	var detected bool
	err := s.pool.QueryRow(ctx, `SELECT detect_spray($1::INET, $2, $3)`, sourceIP, windowSecs, maxUsers).Scan(&detected)
	return detected, err
}

func (s *pgxSprayStore) LockIP(ctx context.Context, sourceIP string, lockoutMins int) error {
	// lockout_arm (lockout_accessors.sql): the spray IP-lock upsert, same
	// ON CONFLICT statement shape, behind the worker-owned SECURITY DEFINER.
	_, err := s.pool.Exec(ctx, `SELECT lockout_arm($1, $2)`,
		"ip:"+sourceIP, lockoutMins)
	return err
}

func (s *pgxSprayStore) Audit(ctx context.Context, sourceIP string, metaJSON []byte) error {
	// SQL lifted verbatim from interceptor.go step 5 (spray audit row), pre-refactor.
	_, err := s.pool.Exec(ctx,
		`INSERT INTO audit_log (source_ip, event_type, metadata)
				 VALUES ($1::INET, 'spray_detected', $2::JSONB)`,
		sourceIP, string(metaJSON))
	return err
}

func (s *pgxSprayStore) Notify(ctx context.Context, sourceIP string) error {
	// SQL lifted verbatim from interceptor.go step 5 (spray pg_notify), pre-refactor.
	_, err := s.pool.Exec(ctx, `SELECT pg_notify('alert:spray', $1::TEXT)`, sourceIP)
	return err
}

// ── RateLimitStore ──

// RateLimitStore abstracts the per-IP/protocol auth counter for RateLimiter.
type RateLimitStore interface {
	Incr(ctx context.Context, key string) (int, error)
}

type pgxRateLimitStore struct{ pool *pgxpool.Pool }

func (s *pgxRateLimitStore) Incr(ctx context.Context, key string) (int, error) {
	// SQL lifted verbatim from interceptor.go step 8 (rate limit counter upsert), pre-refactor.
	var count int
	err := s.pool.QueryRow(ctx,
		`INSERT INTO rate_limit_counters (key, count, window_start)
			 VALUES ($1, 1, now())
			 ON CONFLICT (key) DO UPDATE
			 SET count = CASE
			               WHEN rate_limit_counters.window_start + INTERVAL '1 minute' < now()
			                 THEN 1
			               ELSE rate_limit_counters.count + 1
			             END,
			     window_start = CASE WHEN rate_limit_counters.window_start + INTERVAL '1 minute' < now()
			                        THEN now() ELSE rate_limit_counters.window_start END
			 RETURNING count`,
		key).Scan(&count)
	return count, err
}

// ── PolicyStore ──

type pgxPolicyStore struct {
	pool       *pgxpool.Pool
	logger     *slog.Logger
	userScopes scopeCache // per-user group/role-group cache; decoupled from policy+decision caches
}

// NewPolicyStore creates a SQL-backed threat.PolicyStore for the conditional
// access policy engine. Both servers (authserver, gateway) share this single
// adapter — the SQL (against conditional_access_policies / geo_country_tiers) is
// identical for both.
func NewPolicyStore(pool *pgxpool.Pool, logger *slog.Logger) PolicyStore {
	s := &pgxPolicyStore{pool: pool, logger: logger}
	s.userScopes.ttl = scopeCacheTTL
	s.userScopes.now = time.Now
	// Scope resolution errors are PROPAGATED, never swallowed into empty
	// membership: a transient blip surfaces as an error the caller can route
	// through the engine fail-mode posture (PolicyEngine failModeDecision)
	// instead of silently skipping group/role-scoped policies for the TTL
	// (CA-SCOPE-RESOLUTION-FAIL-OPEN-CACHED). scopeCache.resolve does not store
	// failures, so the error is re-fetched, not cached.
	s.userScopes.fetch = func(ctx context.Context, userID int64) ([]int64, []int64, error) {
		groups, err := ResolveUserGroupsChecked(ctx, pool, userID)
		if err != nil {
			return nil, nil, err
		}
		roleGroups, err := ResolveRoleGroupsChecked(ctx, pool, userID)
		if err != nil {
			return nil, nil, err
		}
		return groups, roleGroups, nil
	}
	return s
}

// ResolveUserScope returns the directory group IDs and admin role-group IDs for
// userID, served from a per-user TTL cache (scopeCacheTTL) that is INDEPENDENT
// of the PolicyEngine policy-set and decision caches. PolicyEngine.InvalidateCache()
// never touches this cache — group membership outlasts policy reload cycles and
// is refreshed on its own 60s TTL. The cache is safe for concurrent callers
// (sync.Map); per-userID isolation prevents cross-user data leakage (F2/F8 lesson).
//
// Error contract (CA-SCOPE-RESOLUTION-FAIL-OPEN-CACHED): a scope-resolution
// error is RETURNED, never converted into empty membership, and the cache does
// not store failures — the next resolve re-queries, so recovery is honored
// immediately. Callers must not discard the error: route it through the engine
// fail-mode posture (PolicyEngine failMode / failModeDecision). The engine now
// does this itself: Evaluate resolves through this seam whenever the store
// implements ScopeResolver, so a scope failure fails CLOSED in the default
// posture and silent empty membership can never bypass group/role-scoped
// policies. (Whether an admin-configured fail-open engine should keep failing
// open on scope errors — signal-only vs fail-closed — remains a flagged open
// tradeoff decision.)
//
// CA-F post-auth callers use this to populate PolicyEvalContext.GroupIDs /
// RoleGroupIDs without re-querying the DB on every request within the TTL.
func (s *pgxPolicyStore) ResolveUserScope(ctx context.Context, userID int64) (groups, roleGroups []int64, err error) {
	return s.userScopes.resolve(ctx, userID)
}

// parseIDArray unmarshals a JSONB int-id array ("[7,9]") into []int64; nil/invalid → nil.
func parseIDArray(raw []byte) []int64 {
	if len(raw) == 0 {
		return nil
	}
	var ids []int64
	if err := json.Unmarshal(raw, &ids); err != nil {
		return nil
	}
	return ids
}

// LoadBreakGlass reads the system break-glass user-id set (CA-0a).
// Absent key (pgx.ErrNoRows) → nil, nil (legitimate empty set, not an error).
// Any other DB error → nil, err so callers can keep the prior snapshot (T6 fix).
func (s *pgxPolicyStore) LoadBreakGlass(ctx context.Context) ([]int64, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx,
		`SELECT value FROM system_config WHERE key = 'ca_break_glass_user_ids'`).Scan(&raw)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil // key not configured yet — empty set, not an error
		}
		return nil, fmt.Errorf("load break-glass: %w", err)
	}
	return parseIDArray(raw), nil
}

// LoadAllPolicies fetches ALL non-off policies from the database, unfiltered by
// scope, ordered by priority. The engine caches this raw set and scope-filters
// per request in Evaluate (cross-user leak fix, F2a). Both 'on' and 'report_only'
// policies are loaded; 'off' policies and soft-deleted rows are excluded at the SQL level.
func (s *pgxPolicyStore) LoadAllPolicies(ctx context.Context) ([]PolicyRow, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, priority, name, description, state, scope_type, scope_target,
		        conditions, actions, exclude_users, exclude_groups, created_from_template
		 FROM conditional_access_policies
		 WHERE state IN ('on','report_only')
		   AND deleted_at IS NULL
		 ORDER BY priority ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("query all policies: %w", err)
	}
	defer rows.Close()

	var policies []PolicyRow
	for rows.Next() {
		var p PolicyRow
		var condBytes, actBytes, exUsers, exGroups []byte
		if err := rows.Scan(&p.ID, &p.Priority, &p.Name, &p.Description, &p.State,
			&p.ScopeType, &p.ScopeTarget, &condBytes, &actBytes, &exUsers, &exGroups,
			&p.CreatedFromTemplate); err != nil {
			s.logger.Warn("conditional access: failed to scan policy row", "error", err)
			continue
		}
		if err := json.Unmarshal(condBytes, &p.Conditions); err != nil {
			s.logger.Warn("conditional access: invalid conditions JSONB", "policy_id", p.ID, "error", err)
			continue
		}
		if err := json.Unmarshal(actBytes, &p.Actions); err != nil {
			s.logger.Warn("conditional access: invalid actions JSONB", "policy_id", p.ID, "error", err)
			continue
		}
		p.ExcludeUsers = parseIDArray(exUsers)
		p.ExcludeGroups = parseIDArray(exGroups)
		policies = append(policies, p)
	}
	return policies, rows.Err()
}

// LoadPolicies fetches non-off, non-deleted policies from the database, filtered by scope
// (global / user / group / role) and ordered by priority.
func (s *pgxPolicyStore) LoadPolicies(ctx context.Context, pectx PolicyEvalContext) ([]PolicyRow, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, priority, name, description, state, scope_type, scope_target,
		        conditions, actions, exclude_users, exclude_groups, created_from_template
		 FROM conditional_access_policies
		 WHERE state IN ('on','report_only')
		   AND deleted_at IS NULL
		   AND (scope_type = 'global'
		        OR (scope_type = 'user'  AND scope_target = $1)
		        OR (scope_type = 'group' AND scope_target = ANY($2))
		        OR (scope_type = 'role'  AND scope_target = ANY($3))
		        OR (scope_type = 'guests' AND scope_target = '' AND $4::boolean))
		 ORDER BY priority ASC`,
		strconv.FormatInt(pectx.UserID, 10),
		formatGroupIDs(pectx.GroupIDs),
		formatRoleGroupIDs(pectx.RoleGroupIDs),
		pectx.IsGuest,
	)
	if err != nil {
		return nil, fmt.Errorf("query policies: %w", err)
	}
	defer rows.Close()

	var policies []PolicyRow
	for rows.Next() {
		var p PolicyRow
		var condBytes, actBytes, exUsers, exGroups []byte
		if err := rows.Scan(&p.ID, &p.Priority, &p.Name, &p.Description, &p.State,
			&p.ScopeType, &p.ScopeTarget, &condBytes, &actBytes, &exUsers, &exGroups,
			&p.CreatedFromTemplate); err != nil {
			s.logger.Warn("conditional access: failed to scan policy row", "error", err)
			continue
		}
		if err := json.Unmarshal(condBytes, &p.Conditions); err != nil {
			s.logger.Warn("conditional access: invalid conditions JSONB", "policy_id", p.ID, "error", err)
			continue
		}
		if err := json.Unmarshal(actBytes, &p.Actions); err != nil {
			s.logger.Warn("conditional access: invalid actions JSONB", "policy_id", p.ID, "error", err)
			continue
		}
		p.ExcludeUsers = parseIDArray(exUsers)
		p.ExcludeGroups = parseIDArray(exGroups)
		policies = append(policies, p)
	}
	return policies, rows.Err()
}

// LoadNamedLocations returns all non-deleted named locations from the DB (CA-1 A2).
// Callers pass the result to pe.setNamedLocations which pre-parses CIDRs.
func (s *pgxPolicyStore) LoadNamedLocations(ctx context.Context) ([]NamedLocation, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, ip_ranges, countries, is_trusted
		 FROM named_locations
		 WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, fmt.Errorf("query named_locations: %w", err)
	}
	defer rows.Close()

	var locs []NamedLocation
	for rows.Next() {
		var l NamedLocation
		var ipRangesB, countriesB []byte
		if err := rows.Scan(&l.ID, &l.Name, &ipRangesB, &countriesB, &l.Trusted); err != nil {
			s.logger.Warn("conditional access: failed to scan named_location row", "error", err)
			continue
		}
		// ip_ranges → CIDRs; countries → Countries (both are JSON string arrays)
		_ = json.Unmarshal(ipRangesB, &l.CIDRs)
		_ = json.Unmarshal(countriesB, &l.Countries)
		locs = append(locs, l)
	}
	return locs, rows.Err()
}

// LoadAuthStrengths returns all auth-strength definitions from the DB (CA-1 A3).
// No deleted_at on auth_strengths (builtin rows must never be deleted; admin
// soft-deletes are handled at the application layer in future reducers).
// ponytail: no deleted_at column in auth_strengths — V030 schema confirms absence.
func (s *pgxPolicyStore) LoadAuthStrengths(ctx context.Context) ([]AuthStrength, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, slug, name, builtin, requirement, min_acr
		 FROM auth_strengths`)
	if err != nil {
		return nil, fmt.Errorf("query auth_strengths: %w", err)
	}
	defer rows.Close()

	var strengths []AuthStrength
	for rows.Next() {
		var s2 AuthStrength
		var reqB []byte
		if err := rows.Scan(&s2.ID, &s2.Slug, &s2.Name, &s2.Builtin, &reqB, &s2.MinACR); err != nil {
			s.logger.Warn("conditional access: failed to scan auth_strength row", "error", err)
			continue
		}
		// requirement is JSON array of arrays: [["webauthn"],["password","totp"],...]
		_ = json.Unmarshal(reqB, &s2.Combinations)
		strengths = append(strengths, s2)
	}
	return strengths, rows.Err()
}

// ResolveGeoTier looks up the country risk tier from geo_country_tiers (default: "low").
func (s *pgxPolicyStore) ResolveGeoTier(ctx context.Context, country string) (string, error) {
	var tier string
	err := s.pool.QueryRow(ctx,
		`SELECT tier FROM geo_country_tiers WHERE country_code = $1`, country,
	).Scan(&tier)
	if err != nil {
		return "low", nil // not found is not an error — default to "low"
	}
	return tier, nil
}

// formatGroupIDs converts []int64 to a PostgreSQL text array string.
func formatGroupIDs(ids []int64) string {
	if len(ids) == 0 {
		return "{}"
	}
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.FormatInt(id, 10)
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// formatRoleGroupIDs mirrors formatGroupIDs for admin role-group IDs (scope_type='role').
// ponytail: identical to formatGroupIDs; split so call sites self-document intent.
func formatRoleGroupIDs(ids []int64) string { return formatGroupIDs(ids) }
