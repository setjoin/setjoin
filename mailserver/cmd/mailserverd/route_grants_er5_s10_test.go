package main

// ER5 slice er5-s10-gateway-main-2 route gates. The permission enforcement
// itself lives in middleware.RequirePermAudited / the console domain-scope
// contract (middleware/console_guard.go); the guards under test here
// (orgWideSurfaceOnly, impersonationTargetGuard, perUserResourceCap) are the
// main.go MOUNT-level bindings of those postures, which have no runnable seam
// short of booting the server — hence the same text-gate pattern as
// route_grants_er5_test.go, plus real request-level tests for the new guards.
//
// Occurrences covered:
//   - occ_52cb8fa…  audit CSV export must ride audit.export, never audit.read
//   - occ_69184439… quarantine preview streams message bodies → mail.export
//   - occ_514eb5d…/occ_c5ce2314… M365 consent mint is a pipeline WRITE, and the
//     whole /admin/migration surface is org-wide (installation-global trust
//     policy, cross-tenant jobs)
//   - occ_62067260… content-search, occ_8cc689c… eDiscovery, occ_d5977ef… mail
//     rules, occ_5102af9b… MDM policy writes: org-wide-by-design surfaces
//     refuse domain-scoped principals at the mount
//   - occ_7e3e4d5…/occ_b719c6b…/occ_e7edf58… impersonation target admission
//   - occ_cbb61a86…/occ_dcb71bd2… telemetry admission budget
//   - occ_d290fba… link-protect admission budget
//   - occ_6901b5b…/occ_eec575b… per-user fan-out caps

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
)

// ── text gates (mount wiring) ───────────────────────────────────────────────

// s10MountLine returns the unique mux.Handle mount line whose quoted pattern is
// exactly route (er5MountLine's Contains match is ambiguous for route
// prefixes like "GET /admin/rules" vs "GET /admin/rules/{id}").
func s10MountLine(t *testing.T, lines []string, route string) string {
	t.Helper()
	needle := "mux.Handle(\"" + route + "\""
	var found []string
	for _, line := range lines {
		if strings.Contains(line, needle) {
			found = append(found, line)
		}
	}
	if len(found) != 1 {
		t.Fatalf("expected exactly one mount line for %q, found %d", route, len(found))
	}
	return found[0]
}

func TestAuditCSVMountRidesAuditExportGrant(t *testing.T) {
	line := s10MountLine(t, er5MainSource(t), "GET /admin/audit/csv")
	if !strings.Contains(line, "requireAuditExport") {
		t.Fatalf("audit CSV export must ride requireAuditExport, got: %s", strings.TrimSpace(line))
	}
	if strings.Contains(line, "requireLogsPerm") {
		t.Fatalf("audit CSV export must not ride the Logs-console read grant: %s", strings.TrimSpace(line))
	}
}

func TestQuarantinePreviewMountRidesMailExportGrant(t *testing.T) {
	line := s10MountLine(t, er5MainSource(t), "GET /admin/quarantine/{id}/preview")
	if !strings.Contains(line, "requireMailExport") {
		t.Fatalf("quarantine preview streams message bodies and must ride requireMailExport, got: %s", strings.TrimSpace(line))
	}
	if strings.Contains(line, "requireMailPerm") {
		t.Fatalf("quarantine preview must not ride the Mail-console read grant: %s", strings.TrimSpace(line))
	}
	// Metadata surfaces stay readable with the Mail-console read grant.
	list := s10MountLine(t, er5MainSource(t), "GET /admin/quarantine")
	if !strings.Contains(list, "requireMailPerm") {
		t.Fatalf("quarantine List must stay on requireMailPerm, got: %s", strings.TrimSpace(list))
	}
}

func TestM365ConnectMountRidesPipelineGrant(t *testing.T) {
	// Connect MINTS server-side consent state (m365_consent_state_mint) and
	// starts the tenant-binding flow — a write, never a read-perm surface.
	line := s10MountLine(t, er5MainSource(t), "GET /admin/migration/m365/connect")
	if !strings.Contains(line, "requireMailPipeline") {
		t.Fatalf("M365 connect mints consent state and must ride requireMailPipeline, got: %s", strings.TrimSpace(line))
	}
	if strings.Contains(line, "requireMailPerm") {
		t.Fatalf("M365 connect must not ride the Mail-console read grant: %s", strings.TrimSpace(line))
	}
}

// orgWideSurfaceMounts are the org-wide-by-design surfaces whose mounts must
// carry requireOrgWideSurface (domain-scoped principals refused, audited).
var orgWideSurfaceMounts = []string{
	// org-wide transport rules
	"GET /admin/rules", "POST /admin/rules", "GET /admin/rules/{id}",
	"PUT /admin/rules/{id}", "DELETE /admin/rules/{id}", "POST /admin/rules/{id}/test",
	// cross-tenant content search / purge
	"POST /admin/content-search/search", "POST /admin/content-search/delete",
	// eDiscovery search/result reads/hold mutations/export/cases
	"POST /admin/ediscovery/search", "GET /admin/ediscovery/{id}",
	"POST /admin/ediscovery/hold", "POST /admin/ediscovery/release",
	"GET /admin/ediscovery/export", "GET /admin/ediscovery/cases",
	"POST /admin/ediscovery/cases", "GET /admin/ediscovery/cases/{id}",
	"PUT /admin/ediscovery/cases/{id}", "DELETE /admin/ediscovery/cases/{id}",
	"POST /admin/ediscovery/cases/{id}/close", "POST /admin/ediscovery/cases/associate",
	// installation-global migration trust policy + cross-tenant jobs + consent
	"GET /admin/migration/jobs", "GET /admin/migration/jobs/{id}",
	"POST /admin/migration/start", "POST /admin/migration/test-connection",
	"POST /admin/migration/jobs/{id}/cancel", "POST /admin/migration/jobs/{id}/retry",
	"POST /admin/migration/jobs/{id}/pause", "POST /admin/migration/jobs/{id}/resume",
	"DELETE /admin/migration/jobs/{id}", "PUT /admin/migration/source/imap",
	"PUT /admin/migration/source/ews", "PUT /admin/migration/source/m365",
	"GET /admin/migration/source/{type}", "DELETE /admin/migration/source/{type}",
	"GET /admin/migration/m365/connect", "GET /admin/migration/m365/callback",
	// global-effect MDM policy writes (device reads/wipe scope in the handler)
	"POST /admin/mdm/policies", "PUT /admin/mdm/policies/reorder",
	"PUT /admin/mdm/policies/{id}", "DELETE /admin/mdm/policies/{id}",
}

func TestOrgWideSurfacesRefuseScopedAdmins(t *testing.T) {
	lines := er5MainSource(t)
	for _, route := range orgWideSurfaceMounts {
		line := s10MountLine(t, lines, route)
		if !strings.Contains(line, "d.requireOrgWideSurface(") {
			t.Fatalf("org-wide surface %s must carry requireOrgWideSurface, got: %s", route, strings.TrimSpace(line))
		}
	}
	// MDM device surfaces keep serving domain-scoped admins (handler-level
	// scoping, pinned by internal/admin/admin_mdm_scope_test.go) — they must
	// NOT be classified org-wide at the mount.
	for _, route := range []string{"GET /admin/mdm/devices", "GET /admin/mdm/devices/{device_id}", "POST /admin/mdm/devices/{device_id}/wipe"} {
		line := s10MountLine(t, lines, route)
		if strings.Contains(line, "d.requireOrgWideSurface(") {
			t.Fatalf("per-domain MDM device surface %s must not refuse scoped admins: %s", route, strings.TrimSpace(line))
		}
	}
}

func TestImpersonateMountRidesTargetGuard(t *testing.T) {
	// The impersonate mount is wrapped onto two source lines (route + chain);
	// assert against the joined statement.
	lines := er5MainSource(t)
	stmt := ""
	for i, line := range lines {
		if strings.Contains(line, "POST /auth/admin/users/{id}/impersonate") && strings.Contains(line, "mux.Handle(") {
			stmt = line + lines[i+1]
			break
		}
	}
	if stmt == "" {
		t.Fatal("impersonate mount not found")
	}
	for _, want := range []string{"requireUsersImpersonate", "requireImpersonateTarget"} {
		if !strings.Contains(stmt, want) {
			t.Fatalf("impersonate mount must ride %s, got: %s", want, strings.TrimSpace(stmt))
		}
	}
}

func TestPublicAdmissionLimitsWired(t *testing.T) {
	lines := er5MainSource(t)
	// Unauthenticated telemetry ingest: per-source admission budget at the mount.
	tel := s10MountLine(t, lines, "POST /telemetry")
	if !strings.Contains(tel, "d.telemetryLimit(") {
		t.Fatalf("POST /telemetry must ride telemetryLimit, got: %s", strings.TrimSpace(tel))
	}
	// Unauthenticated link-protect click handling: per-source admission budget.
	lp := s10MountLine(t, lines, "GET /link-protect")
	if !strings.Contains(lp, "d.linkProtectLimit(") {
		t.Fatalf("GET /link-protect must ride linkProtectLimit, got: %s", strings.TrimSpace(lp))
	}
}

func TestUserFanOutCreatesRidePerUserCaps(t *testing.T) {
	lines := er5MainSource(t)
	wh := s10MountLine(t, lines, "POST /auth/me/webhooks")
	if !strings.Contains(wh, "d.requireWebhookCap(") {
		t.Fatalf("webhook subscription create must ride requireWebhookCap, got: %s", strings.TrimSpace(wh))
	}
	cal := s10MountLine(t, lines, "POST /calendar/subscriptions")
	if !strings.Contains(cal, "d.requireCalendarSubCap(") {
		t.Fatalf("calendar subscription create must ride requireCalendarSubCap, got: %s", strings.TrimSpace(cal))
	}
	// Deletes must stay uncapped (a full user must always be able to remove).
	whDel := s10MountLine(t, lines, "DELETE /auth/me/webhooks/{id}")
	if strings.Contains(whDel, "requireWebhookCap") {
		t.Fatalf("webhook delete must not ride the cap: %s", strings.TrimSpace(whDel))
	}
}

// ── request-level guard tests ───────────────────────────────────────────────

func TestNewER5S10GuardsConstructsAndShutsDown(t *testing.T) {
	pool := s10Pool(t)
	spy := &s10AuditSpy{}
	guards := newER5S10Guards(pool, spy.capture)
	if guards.telemetryLimit == nil || guards.linkProtectLimit == nil ||
		guards.orgWideSurface == nil || guards.impersonateTarget == nil ||
		guards.webhookCap == nil || guards.calendarSubCap == nil {
		t.Fatal("guard set must be fully constructed")
	}
	// The org-wide guard admits a global principal end-to-end from the
	// constructed set (the refusal paths are covered by their own tests).
	req := httptest.NewRequest(http.MethodGet, "/admin/rules", nil).
		WithContext(auth.ContextWithUser(context.Background(), s10Claims(nil)))
	rec := httptest.NewRecorder()
	guards.orgWideSurface(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("global principal through constructed guard got %d, want 200", rec.Code)
	}
	// Idempotent release with the gateway's other limiter shutdowns.
	guards.Shutdown()
}

type s10AuditSpy struct {
	events []middleware.AuditEvent
}

func (s *s10AuditSpy) capture(_ context.Context, ev middleware.AuditEvent) {
	s.events = append(s.events, ev)
}

func s10Claims(scope *int64) *auth.Claims {
	return &auth.Claims{UserID: 7, Email: "admin@example.test", IsAdmin: true, DomainScope: scope}
}

func TestOrgWideSurfaceOnlyRefusesScopedPrincipal(t *testing.T) {
	spy := &s10AuditSpy{}
	guard := orgWideSurfaceOnly(spy.capture)
	var reached bool
	h := guard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))

	scope := int64(3)
	req := httptest.NewRequest(http.MethodPost, "/admin/rules", nil).WithContext(
		auth.ContextWithUser(context.Background(), s10Claims(&scope)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("domain-scoped principal got %d, want 403", rec.Code)
	}
	if reached {
		t.Fatal("handler must not run for a domain-scoped principal")
	}
	if len(spy.events) != 1 || spy.events[0].Action != "console.denied" {
		t.Fatalf("refusal must be audited, got %+v", spy.events)
	}

	// Global admin passes unchanged.
	spy.events = nil
	reached = false
	req = httptest.NewRequest(http.MethodPost, "/admin/rules", nil).WithContext(
		auth.ContextWithUser(context.Background(), s10Claims(nil)))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !reached || len(spy.events) != 0 {
		t.Fatalf("global admin must pass unaudited: code=%d reached=%v events=%+v", rec.Code, reached, spy.events)
	}
}

func s10Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set — skipping DB-backed test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func s10TestDomain(t *testing.T, pool *pgxpool.Pool, name string) int64 {
	t.Helper()
	var id int64
	err := pool.QueryRow(context.Background(),
		`INSERT INTO domains (name) VALUES ($1)
		 ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
		 RETURNING id`, name).Scan(&id)
	if err != nil {
		t.Fatalf("s10TestDomain: %v", err)
	}
	return id
}

func s10TestUser(t *testing.T, pool *pgxpool.Pool, domainID int64, tag string, enabled bool) int64 {
	t.Helper()
	suffix := strings.ReplaceAll(t.Name(), "/", "_")
	email := tag + "-" + suffix + "@s10test.invalid"
	var id int64
	err := pool.QueryRow(context.Background(),
		`INSERT INTO users (username, email, display_name, password_hash, domain_id, enabled)
		 VALUES ($1, $2, $3, '$2a$10$placeholder', $4, $5) RETURNING id`,
		tag+"-"+suffix, email, "s10 test", domainID, enabled).Scan(&id)
	if err != nil {
		t.Fatalf("s10TestUser: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, id)
	})
	return id
}

func TestImpersonationTargetGuardRefusesDisabledAndOutOfDomain(t *testing.T) {
	pool := s10Pool(t)
	ctx := context.Background()

	domainA := s10TestDomain(t, pool, "s10-a.invalid")
	domainB := s10TestDomain(t, pool, "s10-b.invalid")
	enabledInDomain := s10TestUser(t, pool, domainA, "s10en", true)
	disabledInDomain := s10TestUser(t, pool, domainA, "s10dis", false)
	enabledOutOfDomain := s10TestUser(t, pool, domainB, "s10out", true)

	spy := &s10AuditSpy{}
	guard := impersonationTargetGuard(pool, spy.capture)
	var reached int
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached++ })

	run := func(scope *int64, target int64) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/auth/admin/users/0/impersonate", nil)
		req.SetPathValue("id", strconv.FormatInt(target, 10))
		req = req.WithContext(auth.ContextWithUser(ctx, s10Claims(scope)))
		rec := httptest.NewRecorder()
		guard(next).ServeHTTP(rec, req)
		return rec
	}

	// In-domain enabled target: admitted, handler reached, no audit.
	scopeA := domainA
	rec := run(&scopeA, enabledInDomain)
	if rec.Code != http.StatusOK || reached != 1 || len(spy.events) != 0 {
		t.Fatalf("in-domain enabled target must pass: code=%d reached=%d events=%+v", rec.Code, reached, spy.events)
	}

	// Disabled target (even in-domain): refused 403, audited, handler unreached.
	rec = run(&scopeA, disabledInDomain)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("disabled target got %d, want 403", rec.Code)
	}
	if reached != 1 || len(spy.events) != 1 {
		t.Fatalf("disabled-target refusal must be audited and not reach the proxy: reached=%d events=%+v", reached, spy.events)
	}

	// Out-of-domain target for a domain-scoped admin: refused 403, audited.
	spy.events = nil
	rec = run(&scopeA, enabledOutOfDomain)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("out-of-domain target got %d, want 403", rec.Code)
	}
	if reached != 1 || len(spy.events) != 1 {
		t.Fatalf("out-of-domain refusal must be audited: reached=%d events=%+v", reached, spy.events)
	}

	// Global admin: out-of-domain enabled target passes (no domain predicate).
	spy.events = nil
	rec = run(nil, enabledOutOfDomain)
	if rec.Code != http.StatusOK || reached != 2 || len(spy.events) != 0 {
		t.Fatalf("global admin must pass: code=%d reached=%d events=%+v", rec.Code, reached, spy.events)
	}

	// Unknown target: 404 (no existence oracle beyond the proxy's own shape).
	rec = run(&scopeA, 9223372036854775000)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown target got %d, want 404", rec.Code)
	}
}

func TestPerUserResourceCapAdmitsUnderAndRefusesAtCeiling(t *testing.T) {
	pool := s10Pool(t)
	ctx := context.Background()

	domainID := s10TestDomain(t, pool, "s10-cap.invalid")
	owner := s10TestUser(t, pool, domainID, "s10cap", true)
	other := s10TestUser(t, pool, domainID, "s10capother", true)

	// Isolate: start from a known count for both users.
	for _, uid := range []int64{owner, other} {
		_, _ = pool.Exec(ctx, `DELETE FROM webhook_subscriptions WHERE user_id = $1`, uid)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM webhook_subscriptions WHERE user_id = $1`, owner)
		_, _ = pool.Exec(ctx, `DELETE FROM webhook_subscriptions WHERE user_id = $1`, other)
	})

	guard := perUserResourceCap(pool, "webhook subscription",
		2, `SELECT count(*) FROM webhook_subscriptions WHERE user_id = $1`)
	var reached int
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached++ })

	run := func(uid int64) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/auth/me/webhooks", nil).
			WithContext(auth.ContextWithUser(ctx, &auth.Claims{UserID: uid, Email: "u@s10test.invalid"}))
		rec := httptest.NewRecorder()
		guard(next).ServeHTTP(rec, req)
		return rec
	}

	// Empty budget: admitted.
	if rec := run(owner); rec.Code != http.StatusOK || reached != 1 {
		t.Fatalf("under-cap create must pass: code=%d reached=%d", rec.Code, reached)
	}
	// Fill to the ceiling.
	for i := 0; i < 2; i++ {
		if _, err := pool.Exec(ctx,
			`INSERT INTO webhook_subscriptions (user_id, url, event_types, scope) VALUES ($1, 'https://s10test.invalid/hook', '[]', 'self')`,
			owner); err != nil {
			t.Fatalf("seed subscription: %v", err)
		}
	}
	// At ceiling: 409, handler unreached.
	rec := run(owner)
	if rec.Code != http.StatusConflict || reached != 1 {
		t.Fatalf("at-cap create must 409: code=%d reached=%d body=%s", rec.Code, reached, rec.Body.String())
	}
	// Another user's rows never count against this one (R1: ownership from auth).
	if rec := run(other); rec.Code != http.StatusOK || reached != 2 {
		t.Fatalf("other user must be unaffected: code=%d reached=%d", rec.Code, reached)
	}
}

func TestPerUserResourceCapFailsClosedOnCountError(t *testing.T) {
	// A counting failure must refuse (503), never admit unbounded work. The
	// broken query stands in for any count error (pool loss, schema drift):
	// the guard's contract is to refuse, not to guess the budget.
	pool := s10Pool(t)
	guard := perUserResourceCap(pool, "webhook subscription",
		2, `SELECT count(*) FROM s10_no_such_table WHERE user_id = $1`)
	req := httptest.NewRequest(http.MethodPost, "/auth/me/webhooks", nil).
		WithContext(auth.ContextWithUser(context.Background(), &auth.Claims{UserID: 1}))
	rec := httptest.NewRecorder()
	guard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler must not run when the count fails")
	})).ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("count failure got %d, want 503 (fail-closed)", rec.Code)
	}
}

func TestImpersonationTargetGuardRejectsUnauthenticatedAndBadID(t *testing.T) {
	pool := s10Pool(t)
	spy := &s10AuditSpy{}
	guard := impersonationTargetGuard(pool, spy.capture)
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler must not run for unauthenticated or malformed requests")
	})

	// No claims: 401 (the mount sits behind requireAuth; this is the guard's
	// own fail-closed floor).
	req := httptest.NewRequest(http.MethodPost, "/auth/admin/users/1/impersonate", nil)
	req.SetPathValue("id", "1")
	rec := httptest.NewRecorder()
	guard(next).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated got %d, want 401", rec.Code)
	}

	// Malformed / non-positive target id: 400, never a DB round trip.
	for _, bad := range []string{"abc", "0", "-5"} {
		req := httptest.NewRequest(http.MethodPost, "/auth/admin/users/x/impersonate", nil).
			WithContext(auth.ContextWithUser(context.Background(), s10Claims(nil)))
		req.SetPathValue("id", bad)
		rec := httptest.NewRecorder()
		guard(next).ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("bad target id %q got %d, want 400", bad, rec.Code)
		}
	}
	if len(spy.events) != 0 {
		t.Fatalf("no audit events expected for input-shape refusals, got %+v", spy.events)
	}
}

func TestImpersonationTargetGuardFailsClosedOnLookupError(t *testing.T) {
	pool := s10Pool(t)
	spy := &s10AuditSpy{}
	// A closed pool stands in for any lookup failure: the guard must refuse
	// (500) rather than proxy an unverifiable target.
	pool.Close()
	guard := impersonationTargetGuard(pool, spy.capture)
	req := httptest.NewRequest(http.MethodPost, "/auth/admin/users/1/impersonate", nil).
		WithContext(auth.ContextWithUser(context.Background(), s10Claims(nil)))
	req.SetPathValue("id", "1")
	rec := httptest.NewRecorder()
	guard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler must not run when the target lookup fails")
	})).ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("lookup failure got %d, want 503/500 (fail-closed)", rec.Code)
	}
}

func TestPerUserResourceCapRejectsUnauthenticated(t *testing.T) {
	pool := s10Pool(t)
	guard := perUserResourceCap(pool, "webhook subscription",
		2, `SELECT count(*) FROM webhook_subscriptions WHERE user_id = $1`)
	req := httptest.NewRequest(http.MethodPost, "/auth/me/webhooks", nil)
	rec := httptest.NewRecorder()
	guard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler must not run unauthenticated")
	})).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated got %d, want 401", rec.Code)
	}
}
