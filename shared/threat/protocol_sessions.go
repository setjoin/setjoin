package threat

import (
	"io"
	"sync"
	"time"
)

// ProtocolSessionRegistry tracks authenticated, stateful runtime connections
// that cannot be invalidated by rejecting a later HTTP request. Every gateway
// process owns one registry and applies the same session_revoke NOTIFY plus the
// periodic database reconciliation used by SessionDenylist. It covers legacy
// IMAP/SMTP connections and token-bound WS/SSE push streams.
type ProtocolSessionRegistry struct {
	mu            sync.Mutex
	nextID        uint64
	sessions      map[int64]map[uint64]protocolSession
	allBefore     map[int64]expiringWatermark
	revokedJTI    map[int64]map[string]time.Time
	revokedFamily map[int64]map[string]time.Time
}

type expiringWatermark struct {
	notBefore time.Time
	expiresAt time.Time
}

type protocolSession struct {
	authenticatedAt time.Time
	jti             string
	familyID        string
	conn            io.Closer
}

func NewProtocolSessionRegistry() *ProtocolSessionRegistry {
	return &ProtocolSessionRegistry{
		sessions:      make(map[int64]map[uint64]protocolSession),
		allBefore:     make(map[int64]expiringWatermark),
		revokedJTI:    make(map[int64]map[string]time.Time),
		revokedFamily: make(map[int64]map[string]time.Time),
	}
}

// Register records one authenticated IMAP or SMTP connection. The returned
// release function is idempotent and must run when the connection exits or
// re-authenticates.
func (r *ProtocolSessionRegistry) Register(
	userID int64,
	authenticatedAt time.Time,
	conn io.Closer,
) func() {
	return r.register(userID, authenticatedAt, "", "", conn)
}

// RegisterTokenSession records one long-lived access-token session such as a
// WebSocket or SSE push stream. JTI and refresh-family identity allow narrow
// revocations to close the same runtime transport instead of waiting for JWT
// expiry. The returned release function is idempotent.
func (r *ProtocolSessionRegistry) RegisterTokenSession(
	userID int64,
	authenticatedAt time.Time,
	jti string,
	familyID string,
	conn io.Closer,
) func() {
	return r.register(userID, authenticatedAt, jti, familyID, conn)
}

func (r *ProtocolSessionRegistry) register(
	userID int64,
	authenticatedAt time.Time,
	jti string,
	familyID string,
	conn io.Closer,
) func() {
	if r == nil || userID <= 0 || authenticatedAt.IsZero() || conn == nil {
		return func() {}
	}
	r.mu.Lock()
	now := time.Now()
	r.pruneExpiredLocked(now)
	if watermark := r.allBefore[userID]; !authenticatedAt.After(watermark.notBefore) {
		r.mu.Unlock()
		_ = conn.Close()
		return func() {}
	}
	if jti != "" {
		if _, revoked := r.revokedJTI[userID][jti]; revoked {
			r.mu.Unlock()
			_ = conn.Close()
			return func() {}
		}
	}
	if familyID != "" {
		if _, revoked := r.revokedFamily[userID][familyID]; revoked {
			r.mu.Unlock()
			_ = conn.Close()
			return func() {}
		}
	}
	r.nextID++
	id := r.nextID
	if r.sessions[userID] == nil {
		r.sessions[userID] = make(map[uint64]protocolSession)
	}
	r.sessions[userID][id] = protocolSession{
		authenticatedAt: authenticatedAt,
		jti:             jti,
		familyID:        familyID,
		conn:            conn,
	}
	r.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			delete(r.sessions[userID], id)
			if len(r.sessions[userID]) == 0 {
				delete(r.sessions, userID)
			}
			r.mu.Unlock()
		})
	}
}

// Apply closes stateful runtime sessions covered by an all/JTI/family
// revocation. Password-authenticated IMAP/SMTP registrations carry no token
// identity, so only scope=all applies to them.
func (r *ProtocolSessionRegistry) Apply(row RevocationRow) {
	if r == nil || row.UserID <= 0 || row.NotBefore.IsZero() {
		return
	}
	now := time.Now()
	if !row.ExpiresAt.IsZero() && !row.ExpiresAt.After(now) {
		return
	}
	expiresAt := row.ExpiresAt
	if expiresAt.IsZero() {
		// Rolling compatibility for notifications emitted before expires_at was
		// added to the payload. The durable reconcile supplies the exact value.
		expiresAt = now.Add(31 * 24 * time.Hour)
	}

	var close []io.Closer
	r.mu.Lock()
	r.pruneExpiredLocked(now)
	switch row.Scope {
	case ScopeAll:
		if current := r.allBefore[row.UserID]; row.NotBefore.After(current.notBefore) {
			r.allBefore[row.UserID] = expiringWatermark{
				notBefore: row.NotBefore,
				expiresAt: expiresAt,
			}
		}
	case ScopeJTI:
		if row.JTI == "" {
			r.mu.Unlock()
			return
		}
		if r.revokedJTI[row.UserID] == nil {
			r.revokedJTI[row.UserID] = make(map[string]time.Time)
		}
		r.revokedJTI[row.UserID][row.JTI] = expiresAt
	case ScopeFamily:
		if row.FamilyID == "" {
			r.mu.Unlock()
			return
		}
		if r.revokedFamily[row.UserID] == nil {
			r.revokedFamily[row.UserID] = make(map[string]time.Time)
		}
		r.revokedFamily[row.UserID][row.FamilyID] = expiresAt
	default:
		r.mu.Unlock()
		return
	}
	for id, session := range r.sessions[row.UserID] {
		matches := false
		switch row.Scope {
		case ScopeAll:
			matches = !session.authenticatedAt.After(row.NotBefore)
		case ScopeJTI:
			matches = session.jti != "" && session.jti == row.JTI
		case ScopeFamily:
			matches = session.familyID != "" && session.familyID == row.FamilyID
		}
		if matches {
			close = append(close, session.conn)
			delete(r.sessions[row.UserID], id)
		}
	}
	if len(r.sessions[row.UserID]) == 0 {
		delete(r.sessions, row.UserID)
	}
	r.mu.Unlock()

	// Never call external Close methods while holding the registry lock.
	for _, conn := range close {
		_ = conn.Close()
	}
}

// Reconcile reapplies the active database rows after a listener reconnect or
// missed notification. Revocations are monotonic for an already-established
// connection, so rows absent from the new snapshot require no resurrection.
func (r *ProtocolSessionRegistry) Reconcile(rows []RevocationRow) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.pruneExpiredLocked(time.Now())
	r.mu.Unlock()
	for _, row := range rows {
		r.Apply(row)
	}
}

func (r *ProtocolSessionRegistry) pruneExpiredLocked(now time.Time) {
	for userID, watermark := range r.allBefore {
		if !watermark.expiresAt.After(now) {
			delete(r.allBefore, userID)
		}
	}
	for userID, entries := range r.revokedJTI {
		for key, expiresAt := range entries {
			if !expiresAt.After(now) {
				delete(entries, key)
			}
		}
		if len(entries) == 0 {
			delete(r.revokedJTI, userID)
		}
	}
	for userID, entries := range r.revokedFamily {
		for key, expiresAt := range entries {
			if !expiresAt.After(now) {
				delete(entries, key)
			}
		}
		if len(entries) == 0 {
			delete(r.revokedFamily, userID)
		}
	}
}
