// Package connector defines the identity source abstraction for the auth server.
// Each connector represents a directory (AD, local PG, LDAP) that can
// authenticate users and synchronize identity data.
package connector

import (
	"context"
	"fmt"
	"sync"
)

// Identity represents a user identity from any connector.
type Identity struct {
	ExternalID  string
	Email       string
	DisplayName string
	GivenName   string
	Surname     string
	Phone       string
	Title       string
	Department  string
	Office      string
	Disabled    bool
	Attributes  map[string]string // raw connector-specific data
}

// Connector abstracts a user directory.
type Connector interface {
	ID() int64
	Type() string
	HealthCheck(ctx context.Context) error
	VerifyPassword(ctx context.Context, extID, password string) error
	ChangePassword(ctx context.Context, extID, oldPassword, newPassword string) error
	// LookupByAddress resolves a person by ANY of their addresses — the full
	// identity set (`users.email` ∪ `aliases.email` ∪ `users.ad_upn`),
	// case-insensitive — not the primary SMTP address alone. This is the
	// resolve_identity seam (ADR-004): an external IdP commonly asserts a UPN
	// or alias rather than the primary, so resolution must union the whole set
	// to avoid duplicate JIT-provisioning. Returns the same identity regardless
	// of which of a person's addresses was supplied.
	LookupByAddress(ctx context.Context, address string) (*Identity, error)
}

// ResolveIdentitySQL is the canonical resolve_identity rule (ADR-004): resolve a
// person by ANY of their addresses — `users.email` ∪ `aliases.email` (joined to
// the owning person via `mailboxes.user_id`) ∪ `users.ad_upn` — case-insensitive.
// It binds the supplied address to $1 once and returns the matched user's id so
// every consumer (the local connector here, the SP-mode federated-auth resolver
// in handlers) shares one matching key rather than re-deriving "which person is
// this address?" — the divergence ADR-004 set out to eliminate. The SELECT list
// is appended by the caller (different consumers need different columns), so this
// is the FROM/WHERE core only.
//
// Resolution contract (V249 admission/backfill, med-identity-resolution-001):
// the authoritative anchor is THE enabled users row that legitimately owns the
// address. The two tail clauses fail closed — identity_address_claim_count(…) = 1
// binds the address only when exactly ONE enabled person claims it (a
// cross-person duplicate injected by bypassing the admission triggers resolves
// to ZERO rows, never a LIMIT-1 pick that could bind auth to the wrong person —
// the consumer then errors or fails its JIT insert loudly via the same triggers),
// and the identity_address_quarantined(…) exclusion keeps an address the
// one-time backfill (identity_address_overlap_backfill) quarantined with an
// operator report resolving for NO ONE until an operator releases it. The
// exclusion goes through the SECURITY DEFINER helper rather than the ledger
// table because the ledger is FORCE RLS with zero policies: under the runtime
// role (setjoin_app, NOBYPASSRLS) a direct ledger probe is vacuously empty, so
// a "NOT EXISTS (SELECT … FROM identity_address_quarantine)" twin would
// silently RESUME resolution once one competing claim is removed — without any
// operator release. The worker-owned helper (ARCH-018 recipe) returns the
// quarantine fact identically to owner and runtime connections. A deterministic
// tie-break may remain only as defense downstream of the single-claim guarantee.
//
// Multi-forest: a person synced from two AD forests with addresses on different
// domains resolves to ONE identity because all of their addresses (proxyAddresses
// → aliases, userPrincipalName → ad_upn) union here under their single users row.
//
// CO-EVOLVING TWIN of mailserver/sql/reducers/resolve_identity.sql. The matching
// predicate below (the WHERE: enabled ∧ email ∪ ad_upn ∪ alias, all case-folded,
// ∧ single-claim ∧ not quarantined) MUST stay structurally identical to that
// reducer twin — if the two rules drift you get split-brain identity (auth
// resolves a person the mailserver can't: silent lockout / duplicate JIT).
// scripts/check-identity-predicate.sh enforces it (extracts + normalizes + diffs
// both WHERE clauses; shared/identity plan, 2026-06-18). The PROJECTION may
// differ (the reducer returns 3 columns; this fragment lets each caller append
// its own SELECT). A change to the matching RULE here is the documented trigger
// to merge the union into a resolvable_identity view.
const ResolveIdentitySQL = `
	FROM users u
	WHERE u.enabled = TRUE
	  AND (
	    lower(u.email) = lower($1)
	    OR lower(u.ad_upn) = lower($1)
	    OR EXISTS (
	      SELECT 1 FROM aliases a
	      JOIN mailboxes mb ON mb.id = a.mailbox_id
	      WHERE mb.user_id = u.id AND lower(a.email) = lower($1)
	    )
	  )
  AND identity_address_claim_count(lower($1)) = 1
  AND NOT identity_address_quarantined(lower($1))
LIMIT 1`

// Factory creates a Connector from configuration.
type Factory func(ctx context.Context, id int64, config map[string]interface{}, attributeMap map[string]string) (Connector, error)

// ConnectorManager owns BOTH the type→Factory registry and the live-instance
// cache in one seam. It replaces the former split (Registry + ConnectorStore):
// there was never a reason to have two collaborators — a factory map and an
// instance cache with no behavior between them — so they are merged here behind
// Create (warm a typed instance) + CachedGet (the zero-arg handler read). No
// process-global mutable state: main() builds one and injects it; each test
// builds its own, so instances never leak across managers.
//
// Instance addressing contract (D-AUTHSERVER-INTERNAL-CONNECTOR-007): the
// cache is keyed by type string (the zero-arg handler read has no other
// handle), so the contract is EXACTLY ONE live instance per type per manager.
// The connector id is enforced at Create time — a second Create for a type
// already warmed with a DIFFERENT id fails loudly instead of silently
// rebinding the type key to another directory instance (wrong-authority
// hazard: CachedGet("ad") would hand out a different directory's connector
// with no error). A future multi-connector-per-type deployment must first
// widen CachedGet to id-addressed lookup, not bypass this guard.
type ConnectorManager struct {
	mu        sync.RWMutex
	factories map[string]Factory
	instances sync.Map // map[string]Connector — warmed by Create
}

// NewManager creates an empty manager (no factories, no instances). main()
// registers the ad/local factories explicitly (no import-side-effect init()).
func NewManager() *ConnectorManager {
	return &ConnectorManager{factories: make(map[string]Factory)}
}

// Register adds a connector factory for the given type.
func (m *ConnectorManager) Register(typ string, f Factory) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.factories[typ] = f
}

func (m *ConnectorManager) factory(typ string) (Factory, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	f, ok := m.factories[typ]
	return f, ok
}

// Create instantiates a connector of the given type from its registered factory
// and warms the instance cache so a later CachedGet(typ) returns it. An
// unregistered type errors (no nil cached). main() pre-creates connectors at
// startup; the handler then reads them via CachedGet.
//
// The connector id is part of the instance's identity: re-creating the same
// type with the same id is an idempotent re-warm, but a DIFFERENT id for an
// already-warmed type is refused (see the instance addressing contract above).
func (m *ConnectorManager) Create(ctx context.Context, typ string, id int64, config map[string]interface{}, attributeMap map[string]string) (Connector, error) {
	f, ok := m.factory(typ)
	if !ok {
		return nil, fmt.Errorf("connector type %q not registered", typ)
	}
	conn, err := f(ctx, id, config, attributeMap)
	if err != nil {
		return nil, err
	}
	if prev, ok := m.instances.Load(typ); ok {
		if prevID := prev.(Connector).ID(); prevID != id {
			return nil, fmt.Errorf("connector type %q already created with id %d; refusing to rebind to id %d (one instance per type — see ConnectorManager)", typ, prevID, id)
		}
	}
	m.instances.Store(typ, conn)
	return conn, nil
}

// CachedGet returns the connector previously warmed via Create for the given
// type, or nil if none was created. This is the zero-arg handler seam (the AD
// password write-back reads CachedGet("ad")); it never instantiates, so an
// unconfigured type stays nil (the write-back then no-ops).
func (m *ConnectorManager) CachedGet(typ string) Connector {
	v, ok := m.instances.Load(typ)
	if !ok {
		return nil
	}
	return v.(Connector)
}
