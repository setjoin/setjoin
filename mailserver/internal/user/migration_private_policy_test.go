package user

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/migration"
)

// The tests in this file pin the self-service ingress half of the
// migration-private-net-ssrf containment: caller-manufactured
// PrivateHosts/PrivateCIDRs are rejected (not silently stripped) on EVERY
// entry point — start (EWS + IMAP) and the IMAP connection test — with and
// without an admin global profile; the connection test refuses
// non-allowlisted origins (loopback/RFC1918) at the dial guard; and the admin
// global-profile saves validate the policy and normalize the legacy "ssl"
// tls_mode before anything is stored for later jobs to inherit.

const errUserSuppliedPrivatePolicyText = "administrator-owned"

// imapJobCount counts the IMAP migration jobs owned by userID.
func imapJobCount(t *testing.T, pool *pgxpool.Pool, userID int64) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM migration_jobs WHERE user_id = $1 AND source_type = 'imap'`, userID,
	).Scan(&n); err != nil {
		t.Fatalf("imapJobCount: %v", err)
	}
	return n
}

// restoreIMAPDefaults snapshots the imap.defaults system_config row (or its
// absence) and restores it on cleanup.
func restoreIMAPDefaults(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var oldValue []byte
	var had bool
	if err := pool.QueryRow(context.Background(),
		`SELECT value FROM system_config WHERE key='imap.defaults'`,
	).Scan(&oldValue); err == nil {
		had = true
	}
	t.Cleanup(func() {
		if had {
			pool.Exec(context.Background(),
				`INSERT INTO system_config(key,value,encrypted) VALUES('imap.defaults',$1,false)
				 ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value, encrypted=false`, oldValue)
		} else {
			pool.Exec(context.Background(), `DELETE FROM system_config WHERE key='imap.defaults'`)
		}
	})
}

// TestStartMigration_RejectsUserManufacturedPrivatePolicy pins the start
// entry point: privateHosts/privateCIDRs in a self-service config are the
// administrator-owned egress allowlist and are rejected unconditionally —
// with and without a global source profile — and no job row is created.
func TestStartMigration_RejectsUserManufacturedPrivatePolicy(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := newTestMigrationHandler(pool)

	ewsBodies := map[string]string{
		"privateHosts": `{"sourceType":"ews","config":{"serverURL":"https://exchange.example/EWS/Exchange.asmx","username":"alice@corp.example","password":"pw","privateHosts":["exchange.attacker.example"]}}`,
		"privateCIDRs": `{"sourceType":"ews","config":{"serverURL":"https://exchange.example/EWS/Exchange.asmx","username":"alice@corp.example","password":"pw","privateCIDRs":["192.168.0.0/16"]}}`,
	}
	imapBodies := map[string]string{
		"privateHosts": `{"sourceType":"imap","imapConfig":{"host":"imap.example","port":993,"tls_mode":"tls","private_hosts":["imap.attacker.example"]}}`,
		"privateCIDRs": `{"sourceType":"imap","imapConfig":{"host":"imap.example","port":993,"tls_mode":"tls","private_cidrs":["10.0.0.0/8"]}}`,
	}

	for _, profile := range []struct {
		name  string
		setUp func(t *testing.T)
	}{
		{"no global profile", func(t *testing.T) {
			restoreEWSGlobal(t, pool)
			restoreIMAPDefaults(t, pool)
			pool.Exec(context.Background(), `DELETE FROM system_config WHERE key IN ('ews.global','imap.defaults')`)
		}},
		{"global profile present", func(t *testing.T) {
			restoreEWSGlobal(t, pool)
			restoreIMAPDefaults(t, pool)
			seedEWSGlobalProfile(t, h, pool)
			seedIMAPDefaultsProfile(t, h, pool)
		}},
	} {
		t.Run(profile.name, func(t *testing.T) {
			profile.setUp(t)
			userID := mustTestUserWithMailbox(t, pool)

			for _, source := range []struct {
				kind   string
				bodies map[string]string
				count  func(t *testing.T) int
			}{
				{"ews", ewsBodies, func(t *testing.T) int { return ewsJobCount(t, pool, userID) }},
				{"imap", imapBodies, func(t *testing.T) int { return imapJobCount(t, pool, userID) }},
			} {
				for _, fieldName := range []string{"privateHosts", "privateCIDRs"} {
					t.Run(source.kind+"/"+fieldName, func(t *testing.T) {
						before := source.count(t)
						rec := postStartMigration(t, h, userID, source.bodies[fieldName])
						if rec.Code != http.StatusBadRequest {
							t.Fatalf("StartMigration (%s, %s) returned %d, want 400: %s",
								source.kind, fieldName, rec.Code, rec.Body.String())
						}
						if !strings.Contains(rec.Body.String(), errUserSuppliedPrivatePolicyText) {
							t.Fatalf("rejection body must name the administrator-ownership rule: %s", rec.Body.String())
						}
						if after := source.count(t); after != before {
							t.Fatalf("migration job created despite manufactured policy rejection: before=%d after=%d", before, after)
						}
					})
				}
			}
		})
	}
}

// TestStartMigration_PolicyFreeIMAPStillCreatesJob is the positive control:
// a self-service IMAP config WITHOUT private-network exceptions is still
// accepted with and without a global profile — the containment must not
// overblock the legitimate bare/global paths.
func TestStartMigration_PolicyFreeIMAPStillCreatesJob(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := newTestMigrationHandler(pool)
	restoreIMAPDefaults(t, pool)
	userID := mustTestUserWithMailbox(t, pool)

	body := `{"sourceType":"imap","imapConfig":{"host":"imap.example","port":993,"tls_mode":"tls"}}`

	for _, stage := range []struct {
		name  string
		seeds bool
	}{
		{"no global profile", false},
		{"global profile present", true},
	} {
		t.Run(stage.name, func(t *testing.T) {
			if stage.seeds {
				seedIMAPDefaultsProfile(t, h, pool)
			} else {
				pool.Exec(context.Background(), `DELETE FROM system_config WHERE key='imap.defaults'`)
			}
			rec := postStartMigration(t, h, userID, body)
			if rec.Code != http.StatusCreated {
				t.Fatalf("policy-free IMAP start (%s) returned %d, want 201: %s", stage.name, rec.Code, rec.Body.String())
			}
			var created struct {
				ID int64 `json:"id"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.ID == 0 {
				t.Fatalf("201 body missing job id: %s", rec.Body.String())
			}
			t.Cleanup(func() {
				pool.Exec(context.Background(), `DELETE FROM migration_jobs WHERE id = $1`, created.ID)
			})
		})
	}
}

// TestTestIMAPConnection_RejectsUserManufacturedPrivatePolicy pins the
// connection-test entry point: the allowlist content is administrator-owned,
// so a caller cannot attach privateHosts/privateCIDRs to have the test dial
// an otherwise-forbidden origin.
func TestTestIMAPConnection_RejectsUserManufacturedPrivatePolicy(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := newTestMigrationHandler(pool)
	userID := mustTestUserWithMailbox(t, pool)

	post := func(t *testing.T, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/auth/me/migration/test-imap", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID, Type: auth.TypeAccess}))
		rec := httptest.NewRecorder()
		h.TestIMAPConnection(rec, req)
		return rec
	}

	for _, body := range []string{
		`{"host":"imap.example","port":993,"tls_mode":"tls","private_hosts":["imap.attacker.example"]}`,
		`{"host":"imap.example","port":993,"tls_mode":"tls","private_cidrs":["10.0.0.0/8"]}`,
	} {
		rec := post(t, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("TestIMAPConnection with manufactured policy returned %d, want 400: %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), errUserSuppliedPrivatePolicyText) {
			t.Fatalf("rejection body must name the administrator-ownership rule: %s", rec.Body.String())
		}
	}
}

// TestTestIMAPConnection_RefusesNonAllowlistedOrigins is the entry-point half
// of the dial-refusal assertion (the dialer-level stand-in for the proposed
// disposable-network-namespace integration test): after the manufactured
// policy is rejected, the connector is built with an empty policy, so a live
// in-process loopback listener and an RFC1918 literal both refuse before the
// socket — the listener must record ZERO accepted connections.
func TestTestIMAPConnection_RefusesNonAllowlistedOrigins(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := newTestMigrationHandler(pool)
	userID := mustTestUserWithMailbox(t, pool)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on loopback: %v", err)
	}
	defer listener.Close()
	var accepted atomic.Int64
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			conn.Close()
		}
	}()
	// Positive control: the listener accepts ordinary connections.
	control, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("listener positive control failed: %v", err)
	}
	control.Close()
	waitForListenerAccepts(t, &accepted, 1)
	accepted.Store(0)

	port := listener.Addr().(*net.TCPAddr).Port
	for _, tc := range []struct {
		name string
		body string
	}{
		{"loopback listener", `{"host":"127.0.0.1","port":` + strconv.Itoa(port) + `,"tls_mode":"none"}`},
		{"rfc1918 literal", `{"host":"10.255.255.254","port":993,"tls_mode":"none"}`},
		{"metadata endpoint", `{"host":"169.254.169.254","port":80,"tls_mode":"none"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/me/migration/test-imap", bytes.NewBufferString(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID, Type: auth.TypeAccess}))
			rec := httptest.NewRecorder()
			h.TestIMAPConnection(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("TestIMAPConnection returned %d, want 200 with success=false: %s", rec.Code, rec.Body.String())
			}
			var resp struct {
				Success bool `json:"success"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("parse response %q: %v", rec.Body.String(), err)
			}
			if resp.Success {
				t.Fatalf("connection test to %s reported success, want refusal", tc.name)
			}
			// Settle before asserting zero: a guard regression would put a
			// connection in flight whose accept lands within milliseconds.
			time.Sleep(50 * time.Millisecond)
			if got := accepted.Load(); got != 0 {
				t.Fatalf("non-allowlisted origin reached the socket: listener accepted %d connections", got)
			}
		})
	}
}

// TestSaveGlobalIMAPConfig_NormalizesLegacySSLAndValidatesProfile pins the
// admin save path: the webmail console's legacy "ssl" tls_mode is normalized
// to the dialer-implemented "tls" BEFORE validation, unsupported modes are
// rejected, and the private-network policy must compile (permanent denials
// intact) so an unusable profile can never be stored for later jobs.
func TestSaveGlobalIMAPConfig_NormalizesLegacySSLAndValidatesProfile(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := newTestMigrationHandler(pool)
	restoreIMAPDefaults(t, pool)

	post := func(t *testing.T, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPut, "/admin/migration/sources/imap", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.SaveGlobalIMAPConfig(rec, req)
		return rec
	}
	stored := func(t *testing.T) migration.GlobalIMAPConfig {
		t.Helper()
		var raw []byte
		if err := pool.QueryRow(context.Background(),
			`SELECT value FROM system_config WHERE key='imap.defaults'`).Scan(&raw); err != nil {
			t.Fatalf("read imap.defaults: %v", err)
		}
		var cfg migration.GlobalIMAPConfig
		if err := json.Unmarshal(raw, &cfg); err != nil {
			t.Fatalf("parse imap.defaults: %v", err)
		}
		return cfg
	}

	// Legacy "ssl" from the console's SSL checkbox is normalized to "tls".
	if rec := post(t, `{"host":"imap.example","port":993,"tls_mode":"ssl"}`); rec.Code != http.StatusNoContent {
		t.Fatalf("ssl-mode save returned %d, want 204: %s", rec.Code, rec.Body.String())
	}
	if cfg := stored(t); cfg.TLSMode != "tls" {
		t.Fatalf("stored tls_mode = %q, want normalized \"tls\"", cfg.TLSMode)
	}

	for _, tc := range []struct {
		name string
		body string
	}{
		{"unsupported mode", `{"host":"imap.example","port":993,"tls_mode":"quic"}`},
		{"hosts without cidrs", `{"host":"imap.example","port":993,"tls_mode":"tls","private_hosts":["x.internal"]}`},
		{"cidrs without hosts", `{"host":"imap.example","port":993,"tls_mode":"tls","private_cidrs":["10.0.0.0/8"]}`},
		{"loopback not allowlistable", `{"host":"imap.example","port":993,"tls_mode":"tls","private_hosts":["x"],"private_cidrs":["127.0.0.0/8"]}`},
		{"metadata not allowlistable", `{"host":"imap.example","port":993,"tls_mode":"tls","private_hosts":["x"],"private_cidrs":["169.254.0.0/16"]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if rec := post(t, tc.body); rec.Code != http.StatusBadRequest {
				t.Fatalf("%s save returned %d, want 400: %s", tc.name, rec.Code, rec.Body.String())
			}
		})
	}

	// A legal admin profile (RFC1918 exception) is stored verbatim.
	valid := `{"host":"imap.internal","port":993,"tls_mode":"tls","private_hosts":["imap.internal"],"private_cidrs":["10.0.0.0/8"]}`
	if rec := post(t, valid); rec.Code != http.StatusNoContent {
		t.Fatalf("valid admin profile save returned %d, want 204: %s", rec.Code, rec.Body.String())
	}
	cfg := stored(t)
	if len(cfg.PrivateHosts) != 1 || cfg.PrivateHosts[0] != "imap.internal" ||
		len(cfg.PrivateCIDRs) != 1 || cfg.PrivateCIDRs[0] != "10.0.0.0/8" {
		t.Fatalf("admin-owned policy lost on save: %+v", cfg)
	}
}

// TestSaveGlobalEWSConfig_ValidatesPolicyAndURL pins the EWS admin save path:
// the same policy + https-URL checks the connector factory applies at
// construction run at save time, so a profile that could never build a
// connector is rejected instead of failing every later job.
func TestSaveGlobalEWSConfig_ValidatesPolicyAndURL(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := newTestMigrationHandler(pool)
	restoreEWSGlobal(t, pool)

	post := func(t *testing.T, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPut, "/admin/migration/sources/ews", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.SaveGlobalEWSConfig(rec, req)
		return rec
	}

	for _, tc := range []struct {
		name string
		body string
	}{
		{"plain http rejected", `{"serverURL":"http://exchange.example/EWS/Exchange.asmx","username":"svc-migration","password":"pw"}`},
		{"invalid cidr rejected", `{"serverURL":"https://exchange.example/EWS/Exchange.asmx","username":"svc-migration","password":"pw","privateCIDRs":["not-a-cidr"]}`},
		{"loopback literal rejected", `{"serverURL":"https://127.0.0.1/EWS/Exchange.asmx","username":"svc-migration","password":"pw"}`},
		{"metadata literal rejected", `{"serverURL":"https://169.254.169.254/EWS/Exchange.asmx","username":"svc-migration","password":"pw"}`},
		{"loopback policy not allowlistable", `{"serverURL":"https://exchange.example/EWS/Exchange.asmx","username":"svc-migration","password":"pw","privateHosts":["x"],"privateCIDRs":["127.0.0.0/8"]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if rec := post(t, tc.body); rec.Code != http.StatusBadRequest {
				t.Fatalf("%s save returned %d, want 400: %s", tc.name, rec.Code, rec.Body.String())
			}
		})
	}

	// A legal admin profile is stored with its policy intact.
	valid := `{"serverURL":"https://exchange.internal/EWS/Exchange.asmx","username":"svc-migration","password":"svc-secret","privateHosts":["exchange.internal"],"privateCIDRs":["10.0.0.0/8"]}`
	if rec := post(t, valid); rec.Code != http.StatusNoContent {
		t.Fatalf("valid admin profile save returned %d, want 204: %s", rec.Code, rec.Body.String())
	}
	cfg := storedEWSGlobal(t, h, pool)
	if len(cfg.PrivateHosts) != 1 || cfg.PrivateHosts[0] != "exchange.internal" ||
		len(cfg.PrivateCIDRs) != 1 || cfg.PrivateCIDRs[0] != "10.0.0.0/8" {
		t.Fatalf("admin-owned policy lost on save: %+v", cfg)
	}
}

// seedIMAPDefaultsProfile replaces the imap.defaults row with a policy-free
// plaintext profile; pair with restoreIMAPDefaults for cleanup.
func seedIMAPDefaultsProfile(t *testing.T, h *MigrationHandler, pool *pgxpool.Pool) {
	t.Helper()
	raw, err := json.Marshal(migration.GlobalIMAPConfig{
		Host: "imap.global.example", Port: 993, TLSMode: "tls",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO system_config(key,value,encrypted) VALUES('imap.defaults',$1,false)
		 ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value, encrypted=false`, raw); err != nil {
		t.Fatal(err)
	}
}

// waitForListenerAccepts polls until the listener has accepted want
// connections — accept counts land asynchronously relative to the
// client-side handshake.
func waitForListenerAccepts(t *testing.T, accepted *atomic.Int64, want int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if accepted.Load() >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("listener accepted %d connections after 2s, want %d", accepted.Load(), want)
}
