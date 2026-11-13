package admin

// L2-C1 (astra-proposal-c1-mdm-r5) — MAM device endpoint scope, id-namespace
// and error-propagation suite.
//
// What is pinned here (the r4/r5 operative spec):
//   - SAME-STATEMENT SCOPE (R1): every MAM device statement — the list, and
//     the console-id resolution the per-device endpoints share — resolves the
//     device THROUGH its owner (device_registry.user_id → users.domain_id) and
//     carries the admin's domain scope in the same WHERE. An out-of-scope
//     device is a closed 404 indistinguishable from a missing one; a scoped
//     list never leaks out-of-scope rows.
//   - ID NAMESPACE (headline): the console URL id is a device_registry.id,
//     while device_events.device_id / device_policy.device_id FK to devices.id
//     (a different sequence). The endpoints resolve the registry id to its
//     authoritative devices.id server-side (same user_id+fingerprint match
//     mamDeviceListQuery documents) — the colliding-IDs fixture
//     (device_registry.id == devices.id, different owners) proves no
//     cross-attach in either direction.
//   - MISSING vs ZERO-ROWS: a dangling console id is 404 (closed outcome); a
//     resolved device with no events is 200 with an empty history; a
//     registry-only device (no authoritative devices row) reads empty but
//     refuses mutations that would previously have been silently dropped.
//   - IN-STATEMENT SCOPE ON EVERY OPERATION (delta-r2): the scoped lookup is
//     not the last authorization — the policy UPSERT, the policy DELETE, the
//     device_events INSERT and the device_events SELECT all re-derive the
//     owner→domain predicate IN their own statement (devices→users join), so
//     a domain change between lookup and operation (the mid-flight fixture
//     below) cannot authorize a write or a read on stale state.
//   - CHECKED PROPAGATION: the former `_ = mdm.LogDeviceEvent(...)` +
//     best-effort notify shapes are gone — an insertion failure is a 5xx, and
//     a failed policy-change push ALSO surfaces as an error response (the
//     mutation may have committed; the response never reports success), with
//     the notification failure injected through a shadow-schema pg_notify.
//
// Registry/authoritative-device rows use explicit high ids (nanotime base) so
// the collision fixture can force device_registry.id == devices.id across
// owners without touching sequence-assigned rows.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/testsupport"
)

// mamScopeIDBase returns a per-test unique high base for explicit-id fixtures.
// The 8e9 floor keeps fixture ids far from sequence-assigned rows; the
// nanotime component differs across runs, so leftovers from a crashed run
// cannot collide either.
func mamScopeIDBase() int64 {
	return int64(8_000_000_000) + time.Now().UnixNano()
}

// seedMAMRegistryDevice inserts a device_registry row (the CONSOLE id space)
// with an explicit id and fingerprint, registering cleanup.
func seedMAMRegistryDevice(t *testing.T, pool *pgxpool.Pool, userID, id int64, fingerprint string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO device_registry (id, user_id, device_hash, device_fingerprint)
		 VALUES ($1, $2, $3, $4::uuid)`,
		id, userID, fmt.Sprintf("mam-scope-%d", id), fingerprint,
	); err != nil {
		t.Fatalf("seedMAMRegistryDevice(%d): %v", id, err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM device_registry WHERE id = $1`, id)
	})
}

// seedMAMAuthoritativeDevice inserts a devices row (the AUTHORITATIVE id
// space: the device_events/device_policy FK target) with an explicit id,
// registering cleanup of its evidence rows first.
func seedMAMAuthoritativeDevice(t *testing.T, pool *pgxpool.Pool, userID, id int64, fingerprint string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO devices (id, user_id, fingerprint, device_name, platform)
		 VALUES ($1, $2, $3, 'MAM Scope Device', 'ios')`,
		id, userID, fingerprint,
	); err != nil {
		t.Fatalf("seedMAMAuthoritativeDevice(%d): %v", id, err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM device_events WHERE device_id = $1`, id)
		_, _ = pool.Exec(c, `DELETE FROM device_policy WHERE device_id = $1`, id)
		_, _ = pool.Exec(c, `DELETE FROM devices WHERE id = $1`, id)
	})
}

// seedMAMDeviceEvent inserts one device_events row for an authoritative
// device id.
func seedMAMDeviceEvent(t *testing.T, pool *pgxpool.Pool, devicesID int64, eventType string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO device_events (device_id, event_type, severity, details)
		 VALUES ($1, $2, 'info', '{}'::jsonb)`,
		devicesID, eventType,
	); err != nil {
		t.Fatalf("seedMAMDeviceEvent(%d, %s): %v", devicesID, eventType, err)
	}
}

// seedMAMDevicePolicy inserts one device_policy override row for an
// authoritative device id.
func seedMAMDevicePolicy(t *testing.T, pool *pgxpool.Pool, devicesID int64, key, value string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO device_policy (device_id, policy_key, policy_value, updated_at)
		 VALUES ($1, $2, $3, now())`,
		devicesID, key, value,
	); err != nil {
		t.Fatalf("seedMAMDevicePolicy(%d, %s): %v", devicesID, key, err)
	}
}

func mamDeviceEventCount(t *testing.T, pool *pgxpool.Pool, devicesID int64, eventType string) int {
	t.Helper()
	q := `SELECT count(*) FROM device_events WHERE device_id = $1`
	args := []any{devicesID}
	if eventType != "" {
		q += ` AND event_type = $2`
		args = append(args, eventType)
	}
	var n int
	if err := pool.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatalf("mamDeviceEventCount(%d): %v", devicesID, err)
	}
	return n
}

func mamDevicePolicyCount(t *testing.T, pool *pgxpool.Pool, devicesID int64, key string) int {
	t.Helper()
	q := `SELECT count(*) FROM device_policy WHERE device_id = $1`
	args := []any{devicesID}
	if key != "" {
		q += ` AND policy_key = $2`
		args = append(args, key)
	}
	var n int
	if err := pool.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatalf("mamDevicePolicyCount(%d): %v", devicesID, err)
	}
	return n
}

// mamDeviceReq builds a MAM device-endpoint request carrying the given domain
// scope, the console id in its path value and (for policy-key routes) the key.
func mamDeviceReq(method, path, consoleID, key string, scope int64, body string) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, stringReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.SetPathValue("device_id", consoleID)
	if key != "" {
		r.SetPathValue("key", key)
	}
	return adminClaimsCtx(r, 1, scope)
}

type mamEventsBody struct {
	Events []struct {
		DeviceID  int64  `json:"device_id"`
		EventType string `json:"event_type"`
	} `json:"events"`
	Total int `json:"total"`
}

// TestMAMDeviceResolveQuery_ResolvesThroughOwner pins the seam shape: the
// console registry id is resolved to the authoritative devices row by
// user_id+fingerprint identity (never numeric-id equality across the two
// sequences), with the domain-scope arm part of the SAME statement.
func TestMAMDeviceResolveQuery_ResolvesThroughOwner(t *testing.T) {
	for _, fragment := range []string{
		"FROM device_registry AS r",
		"LEFT JOIN devices AS dev",
		"dev.user_id = r.user_id",
		"dev.fingerprint = r.device_fingerprint::text",
		"WHERE r.id = $1",
	} {
		if !strings.Contains(mamDeviceResolveQuery, fragment) {
			t.Errorf("console-id resolution query missing %q", fragment)
		}
	}
	if !strings.Contains(mamDeviceResolveScopeArm, "r.user_id IN (SELECT id FROM users WHERE domain_id = $2)") {
		t.Error("resolution scope arm missing the owner-derived domain predicate")
	}
	if !strings.Contains(mamDeviceListScopeArm, "d.user_id IN (SELECT id FROM users WHERE domain_id = $1)") {
		t.Error("list scope arm missing the owner-derived domain predicate")
	}
}

// TestMAMDevices_DomainScope_List proves the MAM device list is filtered IN
// SQL for domain-scoped admins (R1): out-of-scope registry devices never enter
// the result; the global admin's view is unchanged.
func TestMAMDevices_DomainScope_List(t *testing.T) {
	pool := mailboxTestPool(t)
	h := NewMAMHandler(pool, mailboxTestLogger())

	domA := ensureScopeTestDomain(t, pool, "mam-list-a.scope.test")
	domB := ensureScopeTestDomain(t, pool, "mam-list-b.scope.test")
	userA := createScopeTestUser(t, pool, domA, "mam-list-a.scope.test")
	userB := createScopeTestUser(t, pool, domB, "mam-list-b.scope.test")
	base := mamScopeIDBase()
	regA, regB := base+1, base+2
	seedMAMRegistryDevice(t, pool, userA, regA, "11111111-1111-4111-8111-aaaaaaaaaaaa")
	seedMAMRegistryDevice(t, pool, userB, regB, "22222222-2222-4222-8222-bbbbbbbbbbbb")

	list := func(scope int64) map[int64]bool {
		t.Helper()
		req := adminClaimsCtx(httptest.NewRequest(http.MethodGet, "/admin/mam/devices", nil), 1, scope)
		rec := httptest.NewRecorder()
		h.ListDevices(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("ListDevices(scope=%d): want 200, got %d (body=%s)", scope, rec.Code, rec.Body.String())
		}
		var body struct {
			Devices []mamDevice `json:"devices"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode list: %v", err)
		}
		seen := map[int64]bool{}
		for _, d := range body.Devices {
			seen[d.ID] = true
		}
		return seen
	}

	scoped := list(domA)
	if !scoped[regA] {
		t.Errorf("domain-A admin must see same-domain device %d", regA)
	}
	if scoped[regB] {
		t.Errorf("domain-A admin list leaked out-of-scope device %d (IDOR)", regB)
	}

	global := list(0)
	if !global[regA] || !global[regB] {
		t.Errorf("global admin must see both devices (A=%v B=%v)", global[regA], global[regB])
	}
}

// TestMAMDevices_DomainScope_OutOfScopeClosed proves every per-device endpoint
// closes 404 on an out-of-scope device (indistinguishable from missing — no
// existence oracle) with NOTHING written to that device's evidence/policy
// rows, while the same global-authority request succeeds and lands its
// evidence on the RESOLVED authoritative devices row.
func TestMAMDevices_DomainScope_OutOfScopeClosed(t *testing.T) {
	pool := mailboxTestPool(t)
	h := NewMAMHandler(pool, mailboxTestLogger())

	domA := ensureScopeTestDomain(t, pool, "mam-oos-a.scope.test")
	domB := ensureScopeTestDomain(t, pool, "mam-oos-b.scope.test")
	userB := createScopeTestUser(t, pool, domB, "mam-oos-b.scope.test")
	base := mamScopeIDBase()
	regB := base + 10 // B's console id
	devB := base + 11 // B's authoritative devices row (resolved via fp match)
	fpB := "33333333-3333-4333-8333-cccccccccccc"
	seedMAMRegistryDevice(t, pool, userB, regB, fpB)
	seedMAMAuthoritativeDevice(t, pool, userB, devB, fpB)
	seedMAMDeviceEvent(t, pool, devB, "registered")

	id := fmt.Sprint(regB)

	// Scoped-to-A admin: all four device endpoints close 404.
	rec := httptest.NewRecorder()
	h.LockDevice(rec, mamDeviceReq(http.MethodPost, "/admin/mam/devices/x/lock", id, "", domA, ""))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("out-of-scope lock: want 404, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.GetDeviceEvents(rec, mamDeviceReq(http.MethodGet, "/admin/mam/devices/x/events", id, "", domA, ""))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("out-of-scope events: want 404, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.SetPerDevicePolicy(rec, mamDeviceReq(http.MethodPut, "/admin/mam/devices/x/policy", id, "", domA, `{"policies":{"require_pin":"true"}}`))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("out-of-scope set policy: want 404, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.UnsetPerDevicePolicy(rec, mamDeviceReq(http.MethodDelete, "/admin/mam/devices/x/policy/k", id, "k", domA, ""))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("out-of-scope unset policy: want 404, got %d", rec.Code)
	}

	// Nothing was written to the out-of-scope device: the bait event/policy
	// rows are untouched (the 404 is genuinely closed, not a post-write 404).
	if got := mamDeviceEventCount(t, pool, devB, "device_locked"); got != 0 {
		t.Errorf("out-of-scope lock wrote device_locked evidence: %d rows", got)
	}
	if got := mamDevicePolicyCount(t, pool, devB, "require_pin"); got != 0 {
		t.Errorf("out-of-scope set policy wrote an override row: %d rows", got)
	}

	// Global admin (full authority): the same lock succeeds and its evidence
	// lands on the RESOLVED authoritative devices row.
	rec = httptest.NewRecorder()
	h.LockDevice(rec, mamDeviceReq(http.MethodPost, "/admin/mam/devices/x/lock", id, "", 0, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("global lock: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if got := mamDeviceEventCount(t, pool, devB, "device_locked"); got != 1 {
		t.Errorf("global lock evidence on resolved devices row %d = %d rows, want 1", devB, got)
	}
	// A domain-B-scoped admin (the device's own domain) locks it too: the
	// SCOPED operation statements (event INSERT with the owner→domain arm)
	// must match in-scope rows — the positive arm for the in-statement scope.
	rec = httptest.NewRecorder()
	h.LockDevice(rec, mamDeviceReq(http.MethodPost, "/admin/mam/devices/x/lock", id, "", domB, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("domain-B scoped lock: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if got := mamDeviceEventCount(t, pool, devB, "device_locked"); got != 2 {
		t.Errorf("scoped lock evidence on resolved devices row %d = %d rows, want 2", devB, got)
	}
	rec = httptest.NewRecorder()
	h.GetDeviceEvents(rec, mamDeviceReq(http.MethodGet, "/admin/mam/devices/x/events", id, "", domB, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("in-scope events read: want 200, got %d", rec.Code)
	}
	var body mamEventsBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode events: %v", err)
	}
	if body.Total != 3 || body.Events[0].DeviceID != devB {
		t.Errorf("in-scope events = %+v, want all rows keyed on resolved devices id %d", body, devB)
	}
}

// TestMAMDevices_DanglingID_ClosedOutcome proves the missing-vs-zero-rows
// distinction: a console id addressing NO registry row is a closed 404 on
// every endpoint; a registry-only device (registry row present, no
// authoritative devices row) reads an empty event history ("exists, zero
// rows") but REFUSES mutations that would previously have been silently
// dropped (the FK used to reject them into `_ =`).
func TestMAMDevices_DanglingID_ClosedOutcome(t *testing.T) {
	pool := mailboxTestPool(t)
	h := NewMAMHandler(pool, mailboxTestLogger())

	domA := ensureScopeTestDomain(t, pool, "mam-dangling.scope.test")
	userA := createScopeTestUser(t, pool, domA, "mam-dangling.scope.test")
	base := mamScopeIDBase()
	ghost := base + 20    // no registry row anywhere
	regOnly := base + 21  // registry row, NO matching devices row
	devNever := base + 22 // hypothetical devices id — must never be touched
	fpOnly := "44444444-4444-4444-8444-dddddddddddd"
	seedMAMRegistryDevice(t, pool, userA, regOnly, fpOnly)

	// A devices row with id == regOnly owned by ANOTHER user must exist for
	// the cross-namespace read to be dangerous — but here the registry row's
	// fingerprint matches nothing, so nothing may attach. (The collision
	// fixture below covers the cross-owner case; here we pin the dangling
	// semantics.) Seed a sentinel devices row the endpoints must never touch.
	sentinelFP := "55555555-5555-4555-8555-eeeeeeeeeeee"
	other := createScopeTestUser(t, pool, domA, "mam-dangling.scope.test")
	seedMAMAuthoritativeDevice(t, pool, other, devNever, sentinelFP)
	seedMAMDeviceEvent(t, pool, devNever, "sentinel")

	// ── ghost id (no registry row): 404 everywhere, global scope.
	for _, tc := range []struct {
		name string
		call func(http.ResponseWriter, *http.Request)
		req  *http.Request
	}{
		{"lock", h.LockDevice, mamDeviceReq(http.MethodPost, "/admin/mam/devices/x/lock", fmt.Sprint(ghost), "", 0, "")},
		{"events", h.GetDeviceEvents, mamDeviceReq(http.MethodGet, "/admin/mam/devices/x/events", fmt.Sprint(ghost), "", 0, "")},
		{"set_policy", h.SetPerDevicePolicy, mamDeviceReq(http.MethodPut, "/admin/mam/devices/x/policy", fmt.Sprint(ghost), "", 0, `{"policies":{"k":"v"}}`)},
		{"unset_policy", h.UnsetPerDevicePolicy, mamDeviceReq(http.MethodDelete, "/admin/mam/devices/x/policy/k", fmt.Sprint(ghost), "k", 0, "")},
	} {
		rec := httptest.NewRecorder()
		tc.call(rec, tc.req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("ghost id %s: want 404, got %d (body=%s)", tc.name, rec.Code, rec.Body.String())
		}
	}

	// ── registry-only device (global scope): reads exist/zero-rows, writes close.
	rec := httptest.NewRecorder()
	h.GetDeviceEvents(rec, mamDeviceReq(http.MethodGet, "/admin/mam/devices/x/events", fmt.Sprint(regOnly), "", 0, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("registry-only events: want 200 empty, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var body mamEventsBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Total != 0 {
		t.Fatalf("registry-only events body = %s (err=%v), want total 0", rec.Body.String(), err)
	}

	rec = httptest.NewRecorder()
	h.LockDevice(rec, mamDeviceReq(http.MethodPost, "/admin/mam/devices/x/lock", fmt.Sprint(regOnly), "", 0, ""))
	if rec.Code != http.StatusNotFound {
		t.Errorf("registry-only lock: want 404 (nothing to attach to), got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.SetPerDevicePolicy(rec, mamDeviceReq(http.MethodPut, "/admin/mam/devices/x/policy", fmt.Sprint(regOnly), "", 0, `{"policies":{"k":"v"}}`))
	if rec.Code != http.StatusNotFound {
		t.Errorf("registry-only set policy: want 404, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.UnsetPerDevicePolicy(rec, mamDeviceReq(http.MethodDelete, "/admin/mam/devices/x/policy/k", fmt.Sprint(regOnly), "k", 0, ""))
	if rec.Code != http.StatusNotFound {
		t.Errorf("registry-only unset policy: want 404, got %d", rec.Code)
	}

	// The sentinel device (the numeric neighbor in the devices namespace) was
	// never touched by any of the above.
	if got := mamDeviceEventCount(t, pool, devNever, ""); got != 1 {
		t.Errorf("sentinel device events = %d, want exactly the seeded 1", got)
	}
	if got := mamDevicePolicyCount(t, pool, devNever, "k"); got != 0 {
		t.Errorf("sentinel device gained a policy row: %d", got)
	}
}

// TestMAMDevices_CollidingIDs_NoCrossAttach is the headline fixture: registry
// ids and devices ids COLLIDE numerically across owners. The old endpoints
// used the raw console id against device_events/device_policy (FK target
// devices.id), attaching one user's evidence/policies to another user's
// device. The resolved endpoints must attach through the owner+fingerprint
// match only — proven in BOTH directions with bait rows on every colliding
// row.
func TestMAMDevices_CollidingIDs_NoCrossAttach(t *testing.T) {
	pool := mailboxTestPool(t)
	h := NewMAMHandler(pool, mailboxTestLogger())

	domA := ensureScopeTestDomain(t, pool, "mam-collide-a.scope.test")
	domB := ensureScopeTestDomain(t, pool, "mam-collide-b.scope.test")
	userA := createScopeTestUser(t, pool, domA, "mam-collide-a.scope.test")
	userB := createScopeTestUser(t, pool, domB, "mam-collide-b.scope.test")

	base := mamScopeIDBase()
	collisionID := base + 30 // registry id (A) == devices id (B)
	regA := base + 31        // A's console id == a devices id owned by B
	regB := base + 32        // B's console id
	devA := base + 33        // A's authoritative devices row
	devB := base + 34        // B's authoritative devices row

	fpA := "66666666-6666-4666-8666-aaaaaaaaaaa1"
	fpB := "66666666-6666-4666-8666-bbbbbbbbbbb2"
	fpNone := "66666666-6666-4666-8666-ccccccccccc3" // matches NO devices row

	// The collision pair: A's registry row and B's devices row share one
	// numeric id. B's row carries bait evidence + bait policy.
	seedMAMRegistryDevice(t, pool, userA, collisionID, fpNone)
	seedMAMAuthoritativeDevice(t, pool, userB, collisionID, "77777777-7777-4777-8777-ddddddddd1")
	seedMAMDeviceEvent(t, pool, collisionID, "collide_bait")
	seedMAMDevicePolicy(t, pool, collisionID, "collide_bait", "1")

	// A's real pair: registry regA resolves (via fpA) to devices devA. A
	// DIFFERENT devices row with id == regA (owned by B) carries bait — the
	// old code would read/write THAT row for A's console id.
	seedMAMRegistryDevice(t, pool, userA, regA, fpA)
	seedMAMAuthoritativeDevice(t, pool, userA, devA, fpA)
	seedMAMDeviceEvent(t, pool, devA, "authoritative_a")
	seedMAMAuthoritativeDevice(t, pool, userB, regA, "77777777-7777-4777-8777-ddddddddd2")
	seedMAMDeviceEvent(t, pool, regA, "collide_bait2")

	// B's real pair: registry regB resolves (via fpB) to devices devB.
	seedMAMRegistryDevice(t, pool, userB, regB, fpB)
	seedMAMAuthoritativeDevice(t, pool, userB, devB, fpB)
	seedMAMDeviceEvent(t, pool, devB, "authoritative_b")

	// ── events READS: resolve through owner, never through numeric collision.
	rec := httptest.NewRecorder()
	h.GetDeviceEvents(rec, mamDeviceReq(http.MethodGet, "/admin/mam/devices/x/events", fmt.Sprint(regA), "", 0, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("events(regA): want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var body mamEventsBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode events(regA): %v", err)
	}
	if body.Total != 1 || body.Events[0].EventType != "authoritative_a" || body.Events[0].DeviceID != devA {
		t.Fatalf("events(regA) = %+v, want exactly devA's authoritative_a (devices id %d) — no cross-attach to B's colliding row", body, devA)
	}

	rec = httptest.NewRecorder()
	h.GetDeviceEvents(rec, mamDeviceReq(http.MethodGet, "/admin/mam/devices/x/events", fmt.Sprint(collisionID), "", 0, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("events(collisionID): want 200, got %d", rec.Code)
	}
	body = mamEventsBody{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Total != 0 {
		t.Fatalf("events(collisionID) = %s (err=%v), want EMPTY — B's bait events must not attach to A's registry id", rec.Body.String(), err)
	}

	rec = httptest.NewRecorder()
	h.GetDeviceEvents(rec, mamDeviceReq(http.MethodGet, "/admin/mam/devices/x/events", fmt.Sprint(regB), "", 0, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("events(regB): want 200, got %d", rec.Code)
	}
	body = mamEventsBody{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Total != 1 || body.Events[0].DeviceID != devB {
		t.Fatalf("events(regB) = %+v (err=%v), want devB's authoritative_b (devices id %d)", body, err, devB)
	}

	// ── lock: evidence attaches to the RESOLVED row, never the colliding one.
	rec = httptest.NewRecorder()
	h.LockDevice(rec, mamDeviceReq(http.MethodPost, "/admin/mam/devices/x/lock", fmt.Sprint(regA), "", 0, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("lock(regA): want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if got := mamDeviceEventCount(t, pool, devA, "device_locked"); got != 1 {
		t.Errorf("lock(regA) evidence on resolved devA = %d, want 1", got)
	}
	if got := mamDeviceEventCount(t, pool, regA, "device_locked"); got != 0 {
		t.Errorf("lock(regA) leaked device_locked onto B's colliding devices row %d: %d rows", regA, got)
	}

	rec = httptest.NewRecorder()
	h.LockDevice(rec, mamDeviceReq(http.MethodPost, "/admin/mam/devices/x/lock", fmt.Sprint(collisionID), "", 0, ""))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("lock(collisionID): want 404 (registry fp matches nothing), got %d", rec.Code)
	}
	if got := mamDeviceEventCount(t, pool, collisionID, ""); got != 1 {
		t.Errorf("lock(collisionID) touched B's colliding devices row: %d events, want the seeded 1", got)
	}

	// ── unlock: same contract (one checked call each).
	rec = httptest.NewRecorder()
	h.UnlockDevice(rec, mamDeviceReq(http.MethodPost, "/admin/mam/devices/x/unlock", fmt.Sprint(regA), "", 0, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("unlock(regA): want 200, got %d", rec.Code)
	}
	if got := mamDeviceEventCount(t, pool, regA, "device_unlocked"); got != 0 {
		t.Errorf("unlock(regA) leaked device_unlocked onto B's colliding row: %d rows", got)
	}
	if got := mamDeviceEventCount(t, pool, devA, "device_unlocked"); got != 1 {
		t.Errorf("unlock(regA) evidence on resolved devA = %d, want 1", got)
	}

	// ── per-device policy: overrides key on the resolved row only.
	rec = httptest.NewRecorder()
	h.SetPerDevicePolicy(rec, mamDeviceReq(http.MethodPut, "/admin/mam/devices/x/policy", fmt.Sprint(regA), "", 0, `{"policies":{"require_pin":"true"}}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("set policy(regA): want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if got := mamDevicePolicyCount(t, pool, devA, "require_pin"); got != 1 {
		t.Errorf("set policy(regA) override on resolved devA = %d, want 1", got)
	}
	if got := mamDevicePolicyCount(t, pool, regA, "require_pin"); got != 0 {
		t.Errorf("set policy(regA) leaked an override onto B's colliding devices row %d: %d rows", regA, got)
	}

	rec = httptest.NewRecorder()
	h.SetPerDevicePolicy(rec, mamDeviceReq(http.MethodPut, "/admin/mam/devices/x/policy", fmt.Sprint(collisionID), "", 0, `{"policies":{"require_pin":"true"}}`))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("set policy(collisionID): want 404, got %d", rec.Code)
	}
	if got := mamDevicePolicyCount(t, pool, collisionID, "require_pin"); got != 0 {
		t.Errorf("set policy(collisionID) wrote onto B's colliding devices row: %d rows", got)
	}
	if got := mamDevicePolicyCount(t, pool, collisionID, "collide_bait"); got != 1 {
		t.Errorf("B's bait policy row was disturbed: %d, want 1", got)
	}

	// ── unset: exists-zero-rows (resolved device, no such override) is 404
	// "policy not found", distinct from the resolver's dangling 404.
	rec = httptest.NewRecorder()
	h.UnsetPerDevicePolicy(rec, mamDeviceReq(http.MethodDelete, "/admin/mam/devices/x/policy/k", fmt.Sprint(regA), "k", 0, ""))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unset policy(regA, missing key): want 404, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.UnsetPerDevicePolicy(rec, mamDeviceReq(http.MethodDelete, "/admin/mam/devices/x/policy/require_pin", fmt.Sprint(regA), "require_pin", 0, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("unset policy(regA): want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if got := mamDevicePolicyCount(t, pool, devA, "require_pin"); got != 0 {
		t.Errorf("unset policy(regA) left the override on devA: %d", got)
	}

	// ── scope still applies on top of the resolution: B's console ids are
	// invisible to a domain-A admin even though the numeric resolution would
	// succeed.
	rec = httptest.NewRecorder()
	h.GetDeviceEvents(rec, mamDeviceReq(http.MethodGet, "/admin/mam/devices/x/events", fmt.Sprint(regB), "", domA, ""))
	if rec.Code != http.StatusNotFound {
		t.Errorf("scoped events(regB): want 404, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.GetDeviceEvents(rec, mamDeviceReq(http.MethodGet, "/admin/mam/devices/x/events", fmt.Sprint(regA), "", domA, ""))
	if rec.Code != http.StatusOK {
		t.Errorf("scoped events(regA): want 200, got %d", rec.Code)
	}
}

// mamMidFlightFixtureSQL is the shared shadow fixture for the
// between-lookup-and-operation regression: the minimal device_registry/devices/
// device_policy/device_events tables plus a shadow `users` VIEW whose
// domain_id is computed by a VOLATILE function (mam_owner_domain) modeling a
// mid-flight domain move — see mamMidFlightFlipSQL.
const mamMidFlightFixtureSQL = `
	CREATE TABLE __SCHEMA__.device_registry(
		id bigint, user_id bigint, device_hash text, device_fingerprint uuid,
		last_seen timestamptz, first_seen timestamptz);
	CREATE TABLE __SCHEMA__.devices(id bigint, user_id bigint, fingerprint text);
	CREATE TABLE __SCHEMA__.device_policy(
		id bigint, device_id bigint, policy_key text, policy_value text,
		updated_at timestamptz);
	CREATE UNIQUE INDEX device_policy_device_key
		ON __SCHEMA__.device_policy(device_id, policy_key);
	CREATE TABLE __SCHEMA__.device_events(
		id bigint, device_id bigint, event_type text, severity text,
		details jsonb, occurred_at timestamptz);
	CREATE TABLE __SCHEMA__.mam_users_base(id bigint);
	INSERT INTO __SCHEMA__.mam_users_base VALUES (555030);
	INSERT INTO __SCHEMA__.device_registry
	VALUES(7030, 555030, 'mam-midflight', '88888888-8888-4888-8888-888888888890', now(), now());
	INSERT INTO __SCHEMA__.devices
	VALUES(8030, 555030, '88888888-8888-4888-8888-888888888890');`

// mamMidFlightFlipSQL models the mid-flight domain change deterministically.
// The shadow `users` view computes domain_id through a VOLATILE function that
// flips the owner's domain (1 → 2) on the FIRST transaction that reads it and
// then reports the flipped value to every LATER transaction. The guard
// (txid_current) keeps the value STABLE for rescans within one transaction, so
// every evaluation inside the resolution statement sees the pre-change domain
// (the lookup authorizes) while every later statement — the operation — sees
// the post-change domain (out of scope). This is exactly the
// between-lookup-and-operation window: no hook can fire between two implicit
// transactions, so the change rides the first one.
const mamMidFlightFlipSQL = `
	CREATE TABLE __SCHEMA__.mam_domain_state(
		display bigint, target bigint, flipped boolean, last_tx bigint, tx_display bigint);
	INSERT INTO __SCHEMA__.mam_domain_state VALUES (1, 2, false, 0, 1);
	CREATE FUNCTION __SCHEMA__.mam_owner_domain() RETURNS bigint
	LANGUAGE plpgsql VOLATILE AS $fn$
	DECLARE s record; t bigint;
	BEGIN
	  SELECT * INTO s FROM __SCHEMA__.mam_domain_state;
	  t := txid_current();
	  IF s.last_tx = t THEN
	    RETURN s.tx_display;
	  END IF;
	  IF NOT s.flipped THEN
	    UPDATE __SCHEMA__.mam_domain_state SET flipped = true, display = s.target;
	  END IF;
	  UPDATE __SCHEMA__.mam_domain_state SET last_tx = t, tx_display = s.display;
	  RETURN s.display;
	END $fn$;
	CREATE VIEW __SCHEMA__.users AS
	  SELECT id, __SCHEMA__.mam_owner_domain() AS domain_id FROM __SCHEMA__.mam_users_base;`

// mamMidFlightStaticUsersSQL is the no-change control view: the owner's
// domain stays 1 forever, so scoped statements must succeed end to end.
const mamMidFlightStaticUsersSQL = `
	CREATE VIEW __SCHEMA__.users AS
	  SELECT id, 1::bigint AS domain_id FROM __SCHEMA__.mam_users_base;`

// TestMAMDevices_DomainChangeBetweenLookupAndOperation_Closed is the delta-r2
// mid-flight regression: the scoped lookup authorizes the device (the owner's
// domain is inside the admin's scope), THEN the owner's domain changes, THEN
// the operation statement runs. Every operation statement re-derives the
// owner→domain scope IN its own WHERE (devices→users join — the policy
// UPSERT, the policy DELETE, the device_events INSERT and the device_events
// SELECT), so the stale authorization cannot reach the rows: mutations
// affect zero rows and close 404, the read returns no cross-domain rows, and
// the static-domain control proves the same statements DO match rows while
// the device stays in scope (the closed outcomes are not vacuous).
func TestMAMDevices_DomainChangeBetweenLookupAndOperation_Closed(t *testing.T) {
	const consoleID = "7030"
	const devicesID = int64(8030)

	t.Run("closed_outcomes_after_midflight_domain_change", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			call func(h *MAMHandler, pool *pgxpool.Pool) *httptest.ResponseRecorder
			// assert checks the response and the shadow rows after the call.
			assert func(t *testing.T, pool *pgxpool.Pool, rec *httptest.ResponseRecorder)
		}{
			{
				name: "lock_event_insert",
				call: func(h *MAMHandler, _ *pgxpool.Pool) *httptest.ResponseRecorder {
					rec := httptest.NewRecorder()
					h.LockDevice(rec, mamDeviceReq(http.MethodPost, "/admin/mam/devices/x/lock", consoleID, "", 1, ""))
					return rec
				},
				assert: func(t *testing.T, pool *pgxpool.Pool, rec *httptest.ResponseRecorder) {
					if rec.Code != http.StatusNotFound {
						t.Fatalf("mid-flight lock: want 404 closed, got %d (body=%s)", rec.Code, rec.Body.String())
					}
					if got := mamDeviceEventCount(t, pool, devicesID, "device_locked"); got != 0 {
						t.Errorf("mid-flight lock wrote device_locked evidence: %d rows", got)
					}
				},
			},
			{
				name: "set_policy_upsert",
				call: func(h *MAMHandler, _ *pgxpool.Pool) *httptest.ResponseRecorder {
					rec := httptest.NewRecorder()
					h.SetPerDevicePolicy(rec, mamDeviceReq(http.MethodPut, "/admin/mam/devices/x/policy", consoleID, "", 1, `{"policies":{"require_pin":"true"}}`))
					return rec
				},
				assert: func(t *testing.T, pool *pgxpool.Pool, rec *httptest.ResponseRecorder) {
					if rec.Code != http.StatusNotFound {
						t.Fatalf("mid-flight set policy: want 404 closed, got %d (body=%s)", rec.Code, rec.Body.String())
					}
					if got := mamDevicePolicyCount(t, pool, devicesID, "require_pin"); got != 0 {
						t.Errorf("mid-flight set policy wrote an override row: %d rows", got)
					}
					if got := mamDeviceEventCount(t, pool, devicesID, "policy_applied"); got != 0 {
						t.Errorf("mid-flight set policy wrote evidence: %d rows", got)
					}
				},
			},
			{
				name: "unset_policy_delete",
				call: func(h *MAMHandler, pool *pgxpool.Pool) *httptest.ResponseRecorder {
					// Bait row: the stale authorization would delete it.
					if _, err := pool.Exec(context.Background(),
						`INSERT INTO device_policy (device_id, policy_key, policy_value, updated_at)
						 VALUES ($1, 'bait', '1', now())`, devicesID); err != nil {
						t.Fatalf("seed bait policy row: %v", err)
					}
					rec := httptest.NewRecorder()
					h.UnsetPerDevicePolicy(rec, mamDeviceReq(http.MethodDelete, "/admin/mam/devices/x/policy/bait", consoleID, "bait", 1, ""))
					return rec
				},
				assert: func(t *testing.T, pool *pgxpool.Pool, rec *httptest.ResponseRecorder) {
					if rec.Code != http.StatusNotFound {
						t.Fatalf("mid-flight unset policy: want 404 closed, got %d (body=%s)", rec.Code, rec.Body.String())
					}
					if got := mamDevicePolicyCount(t, pool, devicesID, "bait"); got != 1 {
						t.Errorf("mid-flight unset policy deleted the out-of-scope bait row: %d rows left, want 1", got)
					}
				},
			},
			{
				name: "events_read_select",
				call: func(h *MAMHandler, pool *pgxpool.Pool) *httptest.ResponseRecorder {
					// Bait row: the stale authorization would read it.
					if _, err := pool.Exec(context.Background(),
						`INSERT INTO device_events (device_id, event_type, severity, details)
						 VALUES ($1, 'registered', 'info', '{}'::jsonb)`, devicesID); err != nil {
						t.Fatalf("seed bait event row: %v", err)
					}
					rec := httptest.NewRecorder()
					h.GetDeviceEvents(rec, mamDeviceReq(http.MethodGet, "/admin/mam/devices/x/events", consoleID, "", 1, ""))
					return rec
				},
				assert: func(t *testing.T, pool *pgxpool.Pool, rec *httptest.ResponseRecorder) {
					if rec.Code != http.StatusOK {
						t.Fatalf("mid-flight events read: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
					}
					var body mamEventsBody
					if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
						t.Fatalf("decode events: %v", err)
					}
					if body.Total != 0 {
						t.Errorf("mid-flight events read leaked %d out-of-scope row(s)", body.Total)
					}
				},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				pool := openMAMListFixturePool(t, mamMidFlightFixtureSQL+mamMidFlightFlipSQL)
				h := NewMAMHandler(pool, mailboxTestLogger())
				tc.assert(t, pool, tc.call(h, pool))
			})
		}
	})

	// Control: with NO domain change, the same scoped endpoints succeed end
	// to end — the in-statement arms match in-scope rows.
	t.Run("static_domain_succeeds", func(t *testing.T) {
		pool := openMAMListFixturePool(t, mamMidFlightFixtureSQL+mamMidFlightStaticUsersSQL)
		h := NewMAMHandler(pool, mailboxTestLogger())

		rec := httptest.NewRecorder()
		h.LockDevice(rec, mamDeviceReq(http.MethodPost, "/admin/mam/devices/x/lock", consoleID, "", 1, ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("static-domain lock: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
		}
		if got := mamDeviceEventCount(t, pool, devicesID, "device_locked"); got != 1 {
			t.Errorf("static-domain lock evidence = %d rows, want 1", got)
		}

		rec = httptest.NewRecorder()
		h.SetPerDevicePolicy(rec, mamDeviceReq(http.MethodPut, "/admin/mam/devices/x/policy", consoleID, "", 1, `{"policies":{"require_pin":"true"}}`))
		if rec.Code != http.StatusOK {
			t.Fatalf("static-domain set policy: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
		}
		if got := mamDevicePolicyCount(t, pool, devicesID, "require_pin"); got != 1 {
			t.Errorf("static-domain policy override = %d rows, want 1", got)
		}
		if got := mamDeviceEventCount(t, pool, devicesID, "policy_applied"); got != 1 {
			t.Errorf("static-domain policy evidence = %d rows, want 1", got)
		}

		rec = httptest.NewRecorder()
		h.GetDeviceEvents(rec, mamDeviceReq(http.MethodGet, "/admin/mam/devices/x/events", consoleID, "", 1, ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("static-domain events read: want 200, got %d", rec.Code)
		}
		var body mamEventsBody
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode events: %v", err)
		}
		if body.Total != 2 { // device_locked + policy_applied
			t.Errorf("static-domain events read = %d rows, want 2", body.Total)
		}
	})
}

// TestMAMDevices_Lock_InsertionFailure_5xx proves the checked event
// insertion: with the resolution succeeding but the device_events INSERT
// failing (a shadow-schema device_events with a planted NOT NULL column the
// insert does not satisfy), LockDevice answers 5xx — never a silent 200.
func TestMAMDevices_Lock_InsertionFailure_5xx(t *testing.T) {
	shadowPool := openMAMListFixturePool(t, `
		CREATE TABLE __SCHEMA__.device_registry(
			id bigint, user_id bigint, device_hash text, device_fingerprint uuid,
			last_seen timestamptz, first_seen timestamptz);
		CREATE TABLE __SCHEMA__.devices(id bigint, user_id bigint, fingerprint text);
		CREATE TABLE __SCHEMA__.device_events(
			id bigint, device_id bigint, event_type text, severity text,
			details jsonb, occurred_at timestamptz,
			planted_insert_failure text NOT NULL);
		INSERT INTO __SCHEMA__.device_registry
		VALUES(7001, 555001, 'mam-insert-fail', '88888888-8888-4888-8888-888888888888', now(), now());
		INSERT INTO __SCHEMA__.devices
		VALUES(8001, 555001, '88888888-8888-4888-8888-888888888888')`)

	h := NewMAMHandler(shadowPool, mailboxTestLogger())
	rec := httptest.NewRecorder()
	h.LockDevice(rec, mamDeviceReq(http.MethodPost, "/admin/mam/devices/x/lock", "7001", "", 0, ""))
	if rec.Code < 500 {
		t.Fatalf("insertion failure: want 5xx, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestMAMDevices_SetPolicy_InsertionFailure_5xx proves the checked contract
// for the per-device policy EVIDENCE EVENT: the policy write SUCCEEDS (the
// override row is present) and the device_events INSERT FAILS (a shadow-schema
// device_events with a planted NOT NULL column the insert does not satisfy);
// SetPerDevicePolicy answers 5xx — never a silent 200. The failure is planted
// on device_events (NOT device_policy): a policy-write failure would exit the
// handler before the evidence branch and prove nothing about the checked
// LogDeviceEvent call — the policy row landing is the discriminator that the
// exercised failure is the event insert.
func TestMAMDevices_SetPolicy_InsertionFailure_5xx(t *testing.T) {
	shadowPool := openMAMListFixturePool(t, `
		CREATE TABLE __SCHEMA__.device_registry(
			id bigint, user_id bigint, device_hash text, device_fingerprint uuid,
			last_seen timestamptz, first_seen timestamptz);
		CREATE TABLE __SCHEMA__.devices(id bigint, user_id bigint, fingerprint text);
		CREATE TABLE __SCHEMA__.device_policy(
			id bigint, device_id bigint, policy_key text, policy_value text,
			updated_at timestamptz);
		CREATE UNIQUE INDEX device_policy_device_key
			ON __SCHEMA__.device_policy(device_id, policy_key);
		CREATE TABLE __SCHEMA__.device_events(
			id bigint, device_id bigint, event_type text, severity text,
			details jsonb, occurred_at timestamptz,
			planted_insert_failure text NOT NULL);
		INSERT INTO __SCHEMA__.device_registry
		VALUES(7002, 555002, 'mam-policy-insert-fail', '88888888-8888-4888-8888-888888888889', now(), now());
		INSERT INTO __SCHEMA__.devices
		VALUES(8002, 555002, '88888888-8888-4888-8888-888888888889')`)

	h := NewMAMHandler(shadowPool, mailboxTestLogger())
	rec := httptest.NewRecorder()
	h.SetPerDevicePolicy(rec, mamDeviceReq(http.MethodPut, "/admin/mam/devices/x/policy", "7002", "", 0, `{"policies":{"require_pin":"true"}}`))
	if rec.Code < 500 {
		t.Fatalf("insertion failure: want 5xx, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	// The failure must be the EVENT branch: the policy write itself committed
	// before the handler reached the checked LogDeviceEvent call.
	if got := mamDevicePolicyCount(t, shadowPool, 8002, "require_pin"); got != 1 {
		t.Fatalf("policy write did not commit before the event failure: device_policy rows = %d, want 1 (the failure must be planted on device_events, not device_policy)", got)
	}
}

// openMAMNotifyFixturePool is openMAMListFixturePool with the fixture schema
// placed BEFORE pg_catalog on the search path, so the shadow schema can plant
// a failing pg_notify(text, text): NotifyPolicyChange's unqualified
// `SELECT pg_notify('device_policy', $1)` then resolves to the planted
// function, injecting a deterministic notification failure. This is the only
// injection seam — the notify does not ride the mutation's transaction and
// the handler offers no other hook.
func openMAMNotifyFixturePool(t *testing.T, setupSQL string) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		if os.Getenv("REQUIRE_DB") != "" {
			t.Fatal("DB_DSN is unset but REQUIRE_DB is set")
		}
		t.Skip("DB_DSN not set")
	}
	adminPool := testsupport.OpenTestPool(t)
	schema := fmt.Sprintf("mam_notify_test_%d", time.Now().UnixNano())
	if _, err := adminPool.Exec(t.Context(), `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create fixture schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = adminPool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	})
	setupSQL = strings.ReplaceAll(setupSQL, "__SCHEMA__", schema)
	if _, err := adminPool.Exec(t.Context(), setupSQL); err != nil {
		t.Fatalf("create notify fixture: %v", err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse DB_DSN: %v", err)
	}
	cfg.MaxConns = 1
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, `SET search_path=`+schema+`,pg_catalog,public`)
		return err
	}
	shadowPool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatalf("open notify fixture pool: %v", err)
	}
	t.Cleanup(shadowPool.Close)
	return shadowPool
}

// mamNotifyFailTables is the per-device shadow fixture for the notify-failure
// tests: resolution, policy and event statements all succeed; only the
// pg_notify call can fail (planted below per test).
const mamNotifyFailTables = `
	CREATE TABLE __SCHEMA__.device_registry(
		id bigint, user_id bigint, device_hash text, device_fingerprint uuid,
		last_seen timestamptz, first_seen timestamptz);
	CREATE TABLE __SCHEMA__.devices(id bigint, user_id bigint, fingerprint text);
	CREATE TABLE __SCHEMA__.device_policy(
		id bigint, device_id bigint, policy_key text, policy_value text,
		updated_at timestamptz);
	CREATE UNIQUE INDEX device_policy_device_key
		ON __SCHEMA__.device_policy(device_id, policy_key);
	CREATE TABLE __SCHEMA__.device_events(
		id bigint, device_id bigint, event_type text, severity text,
		details jsonb, occurred_at timestamptz);
	INSERT INTO __SCHEMA__.device_registry
	VALUES(7020, 555020, 'mam-notify-fail', '88888888-8888-4888-8888-888888888891', now(), now());
	INSERT INTO __SCHEMA__.devices
	VALUES(8020, 555020, '88888888-8888-4888-8888-888888888891');`

const mamPlantedNotifyFailureSQL = `
	CREATE FUNCTION __SCHEMA__.pg_notify(text, text) RETURNS integer
	LANGUAGE plpgsql AS $fn$ BEGIN RAISE EXCEPTION 'planted notify failure'; END $fn$;`

// TestMAMDevices_NotifyFailure_5xx proves the checked-propagation contract for
// the policy-change push: the notify does NOT ride the mutation's transaction,
// so a committed mutation cannot be rolled back — but a failed push must
// still surface as an ERROR response (never the old best-effort 200). Each
// case also pins the mutation side of that contract: the durable effect is
// present (the override/lock/delete committed) even though the response is a
// 5xx, so a client retry observes idempotent state, not a phantom failure.
func TestMAMDevices_NotifyFailure_5xx(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, pool *pgxpool.Pool) // extra seeded rows
		call  func(h *MAMHandler, consoleID string) *httptest.ResponseRecorder
		// committed asserts the durable effect survived the failed push.
		committed func(t *testing.T, pool *pgxpool.Pool)
	}{
		{
			name:  "lock",
			setup: func(t *testing.T, pool *pgxpool.Pool) {},
			call: func(h *MAMHandler, consoleID string) *httptest.ResponseRecorder {
				rec := httptest.NewRecorder()
				h.LockDevice(rec, mamDeviceReq(http.MethodPost, "/admin/mam/devices/x/lock", consoleID, "", 0, ""))
				return rec
			},
			committed: func(t *testing.T, pool *pgxpool.Pool) {
				if got := mamDeviceEventCount(t, pool, 8020, "device_locked"); got != 1 {
					t.Errorf("lock mutation did not survive the failed notify: %d rows, want 1", got)
				}
			},
		},
		{
			name:  "set_per_device_policy",
			setup: func(t *testing.T, pool *pgxpool.Pool) {},
			call: func(h *MAMHandler, consoleID string) *httptest.ResponseRecorder {
				rec := httptest.NewRecorder()
				h.SetPerDevicePolicy(rec, mamDeviceReq(http.MethodPut, "/admin/mam/devices/x/policy", consoleID, "", 0, `{"policies":{"require_pin":"true"}}`))
				return rec
			},
			committed: func(t *testing.T, pool *pgxpool.Pool) {
				if got := mamDevicePolicyCount(t, pool, 8020, "require_pin"); got != 1 {
					t.Errorf("policy mutation did not survive the failed notify: %d rows, want 1", got)
				}
				if got := mamDeviceEventCount(t, pool, 8020, "policy_applied"); got != 1 {
					t.Errorf("policy evidence did not survive the failed notify: %d rows, want 1", got)
				}
			},
		},
		{
			name: "unset_per_device_policy",
			setup: func(t *testing.T, pool *pgxpool.Pool) {
				if _, err := pool.Exec(context.Background(),
					`INSERT INTO device_policy (device_id, policy_key, policy_value, updated_at)
					 VALUES (8020, 'bait', '1', now())`); err != nil {
					t.Fatalf("seed bait policy row: %v", err)
				}
			},
			call: func(h *MAMHandler, consoleID string) *httptest.ResponseRecorder {
				rec := httptest.NewRecorder()
				h.UnsetPerDevicePolicy(rec, mamDeviceReq(http.MethodDelete, "/admin/mam/devices/x/policy/bait", consoleID, "bait", 0, ""))
				return rec
			},
			committed: func(t *testing.T, pool *pgxpool.Pool) {
				if got := mamDevicePolicyCount(t, pool, 8020, "bait"); got != 0 {
					t.Errorf("delete mutation did not survive the failed notify: %d rows left, want 0", got)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool := openMAMNotifyFixturePool(t, mamNotifyFailTables+mamPlantedNotifyFailureSQL)
			tc.setup(t, pool)
			h := NewMAMHandler(pool, mailboxTestLogger())
			rec := tc.call(h, "7020")
			if rec.Code < 500 {
				t.Fatalf("failed notify: want 5xx, got %d (body=%s)", rec.Code, rec.Body.String())
			}
			tc.committed(t, pool)
		})
	}

	// Control: the same fixture WITHOUT the planted pg_notify succeeds — the
	// 5xx above is caused by the injected notification failure alone.
	t.Run("notify_success_still_200", func(t *testing.T) {
		pool := openMAMNotifyFixturePool(t, mamNotifyFailTables)
		h := NewMAMHandler(pool, mailboxTestLogger())
		rec := httptest.NewRecorder()
		h.LockDevice(rec, mamDeviceReq(http.MethodPost, "/admin/mam/devices/x/lock", "7020", "", 0, ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("control lock with working notify: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
		}
	})
}

// TestMAMSetGlobalPolicy_NotifyFailure_5xx proves the same checked-propagation
// contract on the global policy path: the upsert commits, the planted
// pg_notify fails, and the handler answers 5xx — not the old best-effort 200
// — while the committed global policy row survives.
func TestMAMSetGlobalPolicy_NotifyFailure_5xx(t *testing.T) {
	pool := openMAMNotifyFixturePool(t, `
		CREATE TABLE __SCHEMA__.device_policy(
			id bigint, device_id bigint, policy_key text, policy_value text,
			updated_at timestamptz);
		CREATE UNIQUE INDEX device_policy_device_key
			ON __SCHEMA__.device_policy(device_id, policy_key);`+mamPlantedNotifyFailureSQL)

	h := NewMAMHandler(pool, mailboxTestLogger())
	rec := httptest.NewRecorder()
	h.SetGlobalPolicy(rec, mamDeviceReq(http.MethodPut, "/admin/mam/policies", "", "", 0, `{"policies":{"require_pin":"true"}}`))
	if rec.Code < 500 {
		t.Fatalf("failed notify: want 5xx, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var committed int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM device_policy WHERE device_id IS NULL AND policy_key = 'require_pin'`).Scan(&committed); err != nil {
		t.Fatalf("count committed global policy: %v", err)
	}
	if committed != 1 {
		t.Errorf("global policy mutation did not survive the failed notify: %d rows, want 1", committed)
	}
}

// mamGroupPolicyNotifyTables is the group-policy shadow fixture: only the
// device_policy_groups layer the group routes touch; the pg_notify shim is
// appended per test.
const mamGroupPolicyNotifyTables = `
	CREATE TABLE __SCHEMA__.device_policy_groups(
		id bigint, policy_key text, policy_value text,
		group_type text, group_id bigint, updated_at timestamptz);
	CREATE UNIQUE INDEX device_policy_groups_group_key
		ON __SCHEMA__.device_policy_groups(group_type, group_id, policy_key);`

func mamGroupPolicyCount(t *testing.T, pool *pgxpool.Pool, groupType string, groupID int64, key string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM device_policy_groups
		 WHERE group_type = $1 AND group_id = $2 AND policy_key = $3`,
		groupType, groupID, key).Scan(&n); err != nil {
		t.Fatalf("mamGroupPolicyCount(%s,%d,%s): %v", groupType, groupID, key, err)
	}
	return n
}

// mamGroupPolicyReq builds a group-policy route request carrying the
// {type}/{id}/{key} path values the DELETE route parses.
func mamGroupPolicyReq(method, path, groupType, groupID, key, body string) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, stringReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	if groupType != "" {
		r.SetPathValue("type", groupType)
	}
	if groupID != "" {
		r.SetPathValue("id", groupID)
	}
	if key != "" {
		r.SetPathValue("key", key)
	}
	return adminClaimsCtx(r, 1, 0)
}

// TestMAMGroupPolicies_NotifyFailure_5xx proves the checked-propagation contract
// on BOTH group-policy routes. Regression guard for the round-2 delta: these
// routes emit "group_policy_updated", which the mdm allowlist excluded, so
// NotifyPolicyChange failed validation BEFORE pg_notify was reached and every
// successful group mutation still answered 500. The vocabulary now accepts the
// action, so with working notify both routes answer 200 with the mutation
// present (the emit passed validation and reached real PostgreSQL), and with
// the planted pg_notify failure each route answers 5xx while the committed
// mutation survives.
func TestMAMGroupPolicies_NotifyFailure_5xx(t *testing.T) {
	const setBody = `{"group_type":"department","group_id":5,"policies":{"require_pin":"true"}}`

	t.Run("notify_failure_5xx", func(t *testing.T) {
		pool := openMAMNotifyFixturePool(t, mamGroupPolicyNotifyTables+mamPlantedNotifyFailureSQL)
		h := NewMAMHandler(pool, mailboxTestLogger())

		rec := httptest.NewRecorder()
		h.SetGroupPolicy(rec, mamGroupPolicyReq(http.MethodPut, "/admin/mam/policies/group", "", "", "", setBody))
		if rec.Code < 500 {
			t.Fatalf("set group policy with failed notify: want 5xx, got %d (body=%s)", rec.Code, rec.Body.String())
		}
		if got := mamGroupPolicyCount(t, pool, "department", 5, "require_pin"); got != 1 {
			t.Errorf("set mutation did not survive the failed notify: %d rows, want 1", got)
		}

		// Seed the row UnsetGroupPolicy deletes; the delete must commit even
		// though the push fails.
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO device_policy_groups (policy_key, policy_value, group_type, group_id, updated_at)
			 VALUES ('bait', '1', 'role', 9, now())`); err != nil {
			t.Fatalf("seed bait group policy row: %v", err)
		}
		rec = httptest.NewRecorder()
		h.UnsetGroupPolicy(rec, mamGroupPolicyReq(http.MethodDelete, "/admin/mam/policies/group/role/9/bait", "role", "9", "bait", ""))
		if rec.Code < 500 {
			t.Fatalf("unset group policy with failed notify: want 5xx, got %d (body=%s)", rec.Code, rec.Body.String())
		}
		if got := mamGroupPolicyCount(t, pool, "role", 9, "bait"); got != 0 {
			t.Errorf("unset mutation did not survive the failed notify: %d rows left, want 0", got)
		}
	})

	// Control: the same fixture WITHOUT the planted pg_notify succeeds — the
	// 5xx above is caused by the injected notification failure alone, and (the
	// round-2 regression this pins) "group_policy_updated" passes emit-side
	// validation instead of erroring before PostgreSQL was ever reached.
	t.Run("notify_success_still_200", func(t *testing.T) {
		pool := openMAMNotifyFixturePool(t, mamGroupPolicyNotifyTables)
		h := NewMAMHandler(pool, mailboxTestLogger())

		rec := httptest.NewRecorder()
		h.SetGroupPolicy(rec, mamGroupPolicyReq(http.MethodPut, "/admin/mam/policies/group", "", "", "", setBody))
		if rec.Code != http.StatusOK {
			t.Fatalf("set group policy with working notify: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
		}
		if got := mamGroupPolicyCount(t, pool, "department", 5, "require_pin"); got != 1 {
			t.Errorf("set mutation missing after 200: %d rows, want 1", got)
		}

		rec = httptest.NewRecorder()
		h.UnsetGroupPolicy(rec, mamGroupPolicyReq(http.MethodDelete, "/admin/mam/policies/group/department/5/require_pin", "department", "5", "require_pin", ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("unset group policy with working notify: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
		}
		if got := mamGroupPolicyCount(t, pool, "department", 5, "require_pin"); got != 0 {
			t.Errorf("unset mutation missing after 200: %d rows left, want 0", got)
		}
	})
}

// TestMAMGetDeviceEvents_ResolutionQueryFailure_5xx proves a resolution-query
// failure is a 5xx closed outcome, never an empty-but-successful read.
func TestMAMGetDeviceEvents_ResolutionQueryFailure_5xx(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	pool.Close()

	h := NewMAMHandler(pool, mailboxTestLogger())
	rec := httptest.NewRecorder()
	h.GetDeviceEvents(rec, mamDeviceReq(http.MethodGet, "/admin/mam/devices/x/events", "12345", "", 0, ""))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("resolution query failure: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}
