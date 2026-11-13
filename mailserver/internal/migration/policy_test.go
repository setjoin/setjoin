package migration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/testsupport"
)

// The tests in this file pin the migration-private-net-ssrf containment: the
// private-network exception policy (PrivateHosts/PrivateCIDRs) is
// ADMINISTRATOR-owned. It reaches a connector only through the admin global
// source profile; caller-manufactured exceptions are rejected on every entry
// point (self-service start/test ingress in internal/user, and the connector
// factories that reconstruct persisted jobs on start/resume/dial here), while
// the permanent denials of the shared policy layer (loopback,
// link-local/metadata, CGNAT, …) hold for everyone.

func TestRejectUserSuppliedPrivatePolicy(t *testing.T) {
	if err := RejectUserSuppliedPrivatePolicy(nil, nil); err != nil {
		t.Fatalf("policy-free config rejected: %v", err)
	}
	if err := RejectUserSuppliedPrivatePolicy([]string{}, []string{}); err != nil {
		t.Fatalf("empty policy rejected: %v", err)
	}
	for _, tc := range []struct {
		name  string
		hosts []string
		cidrs []string
	}{
		{"hosts only", []string{"imap.attacker.example"}, nil},
		{"cidrs only", nil, []string{"10.0.0.0/8"}},
		{"both", []string{"imap.attacker.example"}, []string{"192.168.0.0/16"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := RejectUserSuppliedPrivatePolicy(tc.hosts, tc.cidrs)
			if !errors.Is(err, ErrUserSuppliedPrivatePolicy) {
				t.Fatalf("RejectUserSuppliedPrivatePolicy(%v, %v) = %v, want ErrUserSuppliedPrivatePolicy", tc.hosts, tc.cidrs, err)
			}
		})
	}
}

func TestValidateGlobalProfilesAtSaveTime(t *testing.T) {
	t.Run("imap", func(t *testing.T) {
		valid := []GlobalIMAPConfig{
			{Host: "imap.example", Port: 993, TLSMode: "tls"},
			{Host: "imap.example", Port: 143, TLSMode: "starttls"},
			{Host: "imap.example", Port: 143, TLSMode: "none"},
			{Host: "imap.internal", Port: 993, TLSMode: "tls",
				PrivateHosts: []string{"imap.internal"}, PrivateCIDRs: []string{"10.0.0.0/8"}},
		}
		for _, cfg := range valid {
			if err := ValidateGlobalIMAPProfile(cfg); err != nil {
				t.Fatalf("valid profile %+v rejected: %v", cfg, err)
			}
		}
		invalid := []struct {
			cfg  GlobalIMAPConfig
			want string
		}{
			{GlobalIMAPConfig{Port: 993, TLSMode: "tls"}, "host is required"},
			{GlobalIMAPConfig{Host: "imap.example", TLSMode: "ssl"}, "unsupported tls_mode"},
			{GlobalIMAPConfig{Host: "imap.example", TLSMode: "quic"}, "unsupported tls_mode"},
			{GlobalIMAPConfig{Host: "x", TLSMode: "tls", PrivateHosts: []string{"x.internal"}}, "invalid private-network policy"},
			{GlobalIMAPConfig{Host: "x", TLSMode: "tls", PrivateCIDRs: []string{"10.0.0.0/8"}}, "invalid private-network policy"},
			{GlobalIMAPConfig{Host: "x", TLSMode: "tls", PrivateHosts: []string{"x"}, PrivateCIDRs: []string{"127.0.0.0/8"}}, "invalid private-network policy"},
			{GlobalIMAPConfig{Host: "x", TLSMode: "tls", PrivateHosts: []string{"x"}, PrivateCIDRs: []string{"169.254.0.0/16"}}, "invalid private-network policy"},
		}
		for _, tc := range invalid {
			err := ValidateGlobalIMAPProfile(tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("profile %+v err = %v, want %q", tc.cfg, err, tc.want)
			}
		}
	})

	t.Run("ews", func(t *testing.T) {
		valid := GlobalEWSConfig{
			ServerURL:    "https://exchange.internal/EWS/Exchange.asmx",
			PrivateHosts: []string{"exchange.internal"},
			PrivateCIDRs: []string{"10.0.0.0/8"},
		}
		if err := ValidateGlobalEWSProfile(valid); err != nil {
			t.Fatalf("valid profile rejected: %v", err)
		}
		invalid := []struct {
			cfg  GlobalEWSConfig
			want string
		}{
			{GlobalEWSConfig{ServerURL: "http://exchange.example/EWS/Exchange.asmx"}, "scheme"},
			{GlobalEWSConfig{ServerURL: "https://127.0.0.1/EWS/Exchange.asmx"}, "not allowed"},
			{GlobalEWSConfig{ServerURL: "https://169.254.169.254/EWS/Exchange.asmx"}, "not allowed"},
			{GlobalEWSConfig{ServerURL: "https://exchange.example/EWS/Exchange.asmx", PrivateCIDRs: []string{"not-a-cidr"}}, "invalid private-network policy"},
			{GlobalEWSConfig{ServerURL: "https://exchange.example/EWS/Exchange.asmx", PrivateHosts: []string{"exchange.example"}, PrivateCIDRs: []string{"100.64.0.0/10"}}, "invalid private-network policy"},
		}
		for _, tc := range invalid {
			err := ValidateGlobalEWSProfile(tc.cfg)
			if err == nil {
				t.Fatalf("profile %+v accepted, want rejection naming %q", tc.cfg, tc.want)
			}
		}
	})
}

// TestBarePathJobsRejectUserManufacturedPrivatePolicy pins the fail-closed
// reconstruction of persisted bare-path jobs (UseGlobalAuth=false): every
// entry point that rebuilds the connector — orchestrator start, resume, and
// each connector phase dial — goes through the factories, so a stored job
// whose config carries caller-manufactured PrivateHosts/PrivateCIDRs errors
// at reconstruction instead of dialing with a user-owned allowlist. Such jobs
// must be re-admitted under an admin profile or cancelled (drain posture).
func TestBarePathJobsRejectUserManufacturedPrivatePolicy(t *testing.T) {
	ctx := context.Background()
	o := NewOrchestrator(nil, nil, "", "bare-path-policy-root", testsupport.TestLogger(), ctx, nil)
	captureEWSConnector(t)

	encode := func(t *testing.T, job MigrationJobConfig) []byte {
		t.Helper()
		enc, err := EncryptConfigAny(job, o.encryptionKey)
		if err != nil {
			t.Fatalf("encrypt job config: %v", err)
		}
		return enc
	}

	for _, source := range []string{"imap", "ews"} {
		for _, tc := range []struct {
			name  string
			hosts []string
			cidrs []string
		}{
			{"hosts only", []string{"imap.attacker.example"}, nil},
			{"cidrs only", nil, []string{"192.168.0.0/16"}},
			{"both", []string{"imap.attacker.example"}, []string{"10.0.0.0/8"}},
		} {
			t.Run(source+"/"+tc.name, func(t *testing.T) {
				capturedEWSConfigs = nil
				var job MigrationJobConfig
				switch source {
				case "imap":
					job = MigrationJobConfig{
						SourceType:    "imap",
						UseGlobalAuth: false,
						SelfService:   CredentialProvenance(true),
						IMAP: &IMAPConfig{
							Host: "10.255.255.254", Port: 993, TLSMode: "tls",
							PrivateHosts: tc.hosts, PrivateCIDRs: tc.cidrs,
						},
					}
				case "ews":
					job = MigrationJobConfig{
						SourceType:    "ews",
						UseGlobalAuth: false,
						SelfService:   CredentialProvenance(true),
						EWS: &MigrationEWSConfig{
							ServerURL: "https://10.255.255.254/EWS/Exchange.asmx",
							Username:  "alice@corp.example", Password: "pw",
							PrivateHosts: tc.hosts, PrivateCIDRs: tc.cidrs,
						},
					}
				}
				_, err := o.connectorFactories()[source].Create(ctx, 1, encode(t, job), false)
				if !errors.Is(err, ErrUserSuppliedPrivatePolicy) {
					t.Fatalf("bare-path create err = %v, want ErrUserSuppliedPrivatePolicy", err)
				}
				if source == "ews" && len(capturedEWSConfigs) != 0 {
					t.Fatalf("EWS connector constructed %d times despite user-manufactured policy", len(capturedEWSConfigs))
				}
			})
		}
	}
}

// TestPersistedBarePathJobSemantics pins the drain/reconciliation semantics
// for jobs persisted before the containment: a persisted UseGlobalAuth=false
// job WITHOUT a private policy continues to bypass the global merge on
// reconstruction (no automatic convergence — bare retention of the caller's
// own origin and per-job TLS floor), while a persisted bare job WITH a
// manufactured policy is contained at reconstruction.
func TestPersistedBarePathJobSemantics(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	o := NewOrchestrator(pool, nil, "", "bare-path-semantics-root", testsupport.TestLogger(), ctx, nil)
	captureEWSConnector(t)

	// A global profile that would override everything IF the bare path
	// converged: different origin, admin policy, floor on.
	seedEWSGlobalConfig(t, pool, o, GlobalEWSConfig{
		ServerURL:          "https://exchange.global.example/EWS/Exchange.asmx",
		Username:           "svc-migration",
		Password:           "svc-secret",
		InsecureSkipVerify: true,
		PrivateHosts:       []string{"exchange.global.example"},
		PrivateCIDRs:       []string{"10.0.0.0/8"},
	})

	job := MigrationJobConfig{
		SourceType:    "ews",
		UseGlobalAuth: false,
		SelfService:   CredentialProvenance(true),
		EWS: &MigrationEWSConfig{
			ServerURL:          "https://ews.caller.example/EWS/Exchange.asmx",
			Username:           "alice@corp.example",
			Password:           "alice-pw",
			InsecureSkipVerify: true, // per-job TLS floor is allowed on the bare path
		},
	}
	enc, err := EncryptConfigAny(job, o.encryptionKey)
	if err != nil {
		t.Fatalf("encrypt job config: %v", err)
	}
	capturedEWSConfigs = nil
	sess, err := (ewsFactory{o}).Create(ctx, 1, enc, false)
	if err != nil {
		t.Fatalf("persisted bare job without policy must still reconstruct (bare retention): %v", err)
	}
	if len(capturedEWSConfigs) != 1 {
		t.Fatalf("connector constructed %d times, want 1", len(capturedEWSConfigs))
	}
	cfg := capturedEWSConfigs[0]
	if cfg.ServerURL != "https://ews.caller.example/EWS/Exchange.asmx" {
		t.Fatalf("bare job converged to the global origin %q — no automatic convergence allowed", cfg.ServerURL)
	}
	if cfg.Username != "alice@corp.example" || cfg.Password != "alice-pw" {
		t.Fatalf("bare job lost caller credentials: %q/%v", cfg.Username, cfg.Password != "")
	}
	if !cfg.InsecureSkipVerify {
		t.Fatal("bare job lost its per-job TLS floor")
	}
	if len(cfg.PrivateHosts) != 0 || len(cfg.PrivateCIDRs) != 0 {
		t.Fatalf("bare job inherited an allowlist it never owned: %+v", cfg)
	}
	if _, ok := sess.(*EWSConnector); !ok {
		t.Fatalf("session type = %T, want *EWSConnector", sess)
	}

	// The same persisted job WITH a manufactured policy no longer
	// reconstructs: re-admit under an admin profile or cancel.
	job.EWS.PrivateHosts = []string{"ews.caller.example"}
	job.EWS.PrivateCIDRs = []string{"10.0.0.0/8"}
	enc, err = EncryptConfigAny(job, o.encryptionKey)
	if err != nil {
		t.Fatalf("encrypt job config: %v", err)
	}
	capturedEWSConfigs = nil
	if _, err := (ewsFactory{o}).Create(ctx, 1, enc, false); !errors.Is(err, ErrUserSuppliedPrivatePolicy) {
		t.Fatalf("persisted bare job with manufactured policy err = %v, want ErrUserSuppliedPrivatePolicy", err)
	}
	if len(capturedEWSConfigs) != 0 {
		t.Fatal("connector constructed for a contained persisted bare job")
	}
}

// TestGlobalPathPolicyAndTLSFloorAreAdministratorOwned pins the InsecureSkipVerify
// provenance and allowlist ownership on the global path: the global source
// profile donates BOTH to every job, the per-job config can neither opt out of
// nor inject either one, and a caller-manufactured policy on the job is
// dropped in favor of the admin-owned one.
func TestGlobalPathPolicyAndTLSFloorAreAdministratorOwned(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	o := NewOrchestrator(pool, nil, "", "global-policy-ownership-root", testsupport.TestLogger(), ctx, nil)

	seedIMAPDefaults(t, pool, GlobalIMAPConfig{
		Host: "imap.global.example", Port: 993, TLSMode: "tls",
		PrivateHosts: []string{"imap.global.example"},
		PrivateCIDRs: []string{"10.0.0.0/8"},
	})

	t.Run("ews_floor_admin_owned", func(t *testing.T) {
		for _, tc := range []struct {
			name        string
			globalFloor bool
			jobFloor    bool
		}{
			{"job cannot opt out of admin floor", true, false},
			{"job cannot inject a floor", false, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				captureEWSConnector(t)
				seedEWSGlobalConfig(t, pool, o, GlobalEWSConfig{
					ServerURL:          "https://exchange.global.example/EWS/Exchange.asmx",
					Username:           "svc-migration",
					Password:           "svc-secret",
					InsecureSkipVerify: tc.globalFloor,
					PrivateHosts:       []string{"exchange.global.example"},
					PrivateCIDRs:       []string{"10.0.0.0/8"},
				})
				job := MigrationJobConfig{
					SourceType:    "ews",
					UseGlobalAuth: true,
					SelfService:   CredentialProvenance(true),
					EWS: &MigrationEWSConfig{
						ServerURL:          "https://exchange.global.example/EWS/Exchange.asmx",
						Username:           "alice@corp.example",
						Password:           "pw",
						InsecureSkipVerify: tc.jobFloor,
						// Manufactured policy must be dropped, never merged.
						PrivateHosts: []string{"exchange.attacker.example"},
						PrivateCIDRs: []string{"192.168.0.0/16"},
					},
				}
				enc, err := EncryptConfigAny(job, o.encryptionKey)
				if err != nil {
					t.Fatalf("encrypt job config: %v", err)
				}
				capturedEWSConfigs = nil
				if _, err := (ewsFactory{o}).Create(ctx, 1, enc, true); err != nil {
					t.Fatalf("global-path create: %v", err)
				}
				if len(capturedEWSConfigs) != 1 {
					t.Fatalf("connector constructed %d times, want 1", len(capturedEWSConfigs))
				}
				cfg := capturedEWSConfigs[0]
				if cfg.InsecureSkipVerify != tc.globalFloor {
					t.Fatalf("InsecureSkipVerify = %v, want admin-owned %v", cfg.InsecureSkipVerify, tc.globalFloor)
				}
				if len(cfg.PrivateHosts) != 1 || cfg.PrivateHosts[0] != "exchange.global.example" ||
					len(cfg.PrivateCIDRs) != 1 || cfg.PrivateCIDRs[0] != "10.0.0.0/8" {
					t.Fatalf("connector policy = %+v, want the admin-owned global policy only", cfg)
				}
			})
		}
	})

	t.Run("imap_policy_admin_owned", func(t *testing.T) {
		job := MigrationJobConfig{
			SourceType:    "imap",
			UseGlobalAuth: true,
			SelfService:   CredentialProvenance(true),
			IMAP: &IMAPConfig{
				Host: "imap.caller.example", Port: 143, TLSMode: "none",
				PrivateHosts: []string{"imap.caller.example"},
				PrivateCIDRs: []string{"192.168.0.0/16"},
			},
		}
		enc, err := EncryptConfigAny(job, o.encryptionKey)
		if err != nil {
			t.Fatalf("encrypt job config: %v", err)
		}
		sess, err := (imapFactory{o}).Create(ctx, 1, enc, true)
		if err != nil {
			t.Fatalf("global-path create: %v", err)
		}
		conn, ok := sess.(*IMAPConnector)
		if !ok {
			t.Fatalf("session type = %T, want *IMAPConnector", sess)
		}
		cfg := conn.config
		// The allowlist is exactly the admin-owned one; the manufactured
		// per-job policy never survives the merge.
		if len(cfg.PrivateHosts) != 1 || cfg.PrivateHosts[0] != "imap.global.example" ||
			len(cfg.PrivateCIDRs) != 1 || cfg.PrivateCIDRs[0] != "10.0.0.0/8" {
			t.Fatalf("merged policy = %+v, want admin-owned global policy only", cfg)
		}
		// Approved-origin selection (host/port/tls) remains the caller's.
		if cfg.Host != "imap.caller.example" || cfg.Port != 143 || cfg.TLSMode != "none" {
			t.Fatalf("merged origin = %s:%d/%s, want caller-selected origin", cfg.Host, cfg.Port, cfg.TLSMode)
		}
	})
}

// TestMigrationDialRefusesBlockedTargetsBeforeSocket is the dialer-level
// interception stand-in for the proposed disposable-network-namespace
// integration test (namespaces are unavailable in this environment): the
// production IMAP dial path (no test seams) is aimed at an in-process loopback
// listener, and the assertion is that the socket NEVER receives a connection —
// no dial to a blocked/non-allowlisted target happens, permanent denials hold
// even when admin exceptions are supplied, and an RFC1918 address inside an
// admin CIDR is still refused because exceptions require the allowlisted NAME.
func TestMigrationDialRefusesBlockedTargetsBeforeSocket(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on loopback: %v", err)
	}
	defer listener.Close()
	var accepted atomic.Int64
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			conn.Close()
		}
	}()

	// Positive control: the listener accepts ordinary connections, so a zero
	// count below is meaningful (the guarded dials never reached the socket).
	// The kernel backlog completes the handshake before the accept goroutine
	// runs, so poll for the count instead of asserting it synchronously.
	control, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("listener positive control failed: %v", err)
	}
	control.Close()
	waitForAccepts(t, &accepted, 1)
	accepted.Store(0)

	dial := func(t *testing.T, cfg IMAPConfig) error {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := NewIMAPConnector(cfg).dial(ctx)
		return err
	}

	port := listener.Addr().(*net.TCPAddr).Port
	// Legal admin exceptions (hostname + RFC1918 CIDR together) — permanent
	// denials and the name gate must still hold underneath them.
	adminExceptions := IMAPConfig{
		Port: port, TLSMode: "none",
		PrivateHosts: []string{"imap.fortest.example"},
		PrivateCIDRs: []string{"10.0.0.0/8"},
	}
	cases := []struct {
		name string
		cfg  IMAPConfig
	}{
		{
			name: "loopback listener with empty policy",
			cfg:  IMAPConfig{Host: "127.0.0.1", Port: port, TLSMode: "none"},
		},
		{
			name: "metadata endpoint",
			cfg:  IMAPConfig{Host: "169.254.169.254", Port: 80, TLSMode: "none"},
		},
		{
			name: "rfc1918 literal without policy",
			cfg:  IMAPConfig{Host: "10.255.255.254", Port: port, TLSMode: "none"},
		},
		{
			name: "loopback stays blocked despite admin exceptions",
			cfg:  withHost(adminExceptions, "127.0.0.1"),
		},
		{
			name: "metadata stays blocked despite admin exceptions",
			cfg:  withHost(adminExceptions, "169.254.169.254"),
		},
		{
			name: "rfc1918 inside admin CIDR still needs the allowlisted name",
			cfg:  withHost(adminExceptions, "10.255.255.254"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := dial(t, tc.cfg)
			if err == nil {
				t.Fatalf("dial to %s:%d succeeded, want refusal", tc.cfg.Host, tc.cfg.Port)
			}
			// Settle before asserting zero: a guard regression would put a
			// connection in flight, and its accept lands within milliseconds.
			time.Sleep(50 * time.Millisecond)
			if got := accepted.Load(); got != 0 {
				t.Fatalf("blocked target %s reached the socket: listener accepted %d connections", tc.cfg.Host, got)
			}
		})
	}

	// A user-manufactured exception covering loopback cannot even compile at
	// the dial boundary — the permanent denial is enforced before the socket.
	t.Run("loopback exception cannot compile at dial", func(t *testing.T) {
		err := dial(t, IMAPConfig{
			Host: "127.0.0.1", Port: port, TLSMode: "none",
			PrivateHosts: []string{"x"}, PrivateCIDRs: []string{"127.0.0.0/8"},
		})
		if err == nil || !strings.Contains(err.Error(), "invalid IMAP source policy") {
			t.Fatalf("loopback-covering policy dial err = %v, want invalid IMAP source policy", err)
		}
		if got := accepted.Load(); got != 0 {
			t.Fatalf("listener accepted %d connections", got)
		}
	})
}

func withHost(cfg IMAPConfig, host string) IMAPConfig {
	cfg.Host = host
	return cfg
}

// waitForAccepts polls until the listener has accepted want connections (or
// fails after a bounded wait) — accept counts land asynchronously relative to
// the client-side handshake.
func waitForAccepts(t *testing.T, accepted *atomic.Int64, want int64) {
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

// TestEWSClientDialGuardBlocksLoopbackServer pins the EWS sink containment:
// the connector's HTTP client dials through SafeHTTPClientWithPrivatePolicy,
// so a connector aimed at a live loopback HTTP server never delivers a request
// (empty policy — the self-service post-fix posture), and a connector handed a
// non-compilable manufactured policy short-circuits every request via initErr.
func TestEWSClientDialGuardBlocksLoopbackServer(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	// Empty policy (what a self-service connector carries after ingress
	// rejects manufactured exceptions): loopback is refused at dial.
	conn := NewEWSConnector(EWSConfig{ServerURL: server.URL, Username: "u", Password: "p"})
	if err := conn.TestConnection(context.Background()); err == nil {
		t.Fatal("EWS request to loopback server succeeded, want dial refusal")
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("loopback server received %d requests, want 0", got)
	}

	// A manufactured policy covering loopback cannot compile; the connector
	// short-circuits every SOAP request on initErr before any HTTP.
	blocked := NewEWSConnector(EWSConfig{
		ServerURL: server.URL, Username: "u", Password: "p",
		PrivateHosts: []string{"x"}, PrivateCIDRs: []string{"127.0.0.0/8"},
	})
	err := blocked.TestConnection(context.Background())
	if err == nil || !strings.Contains(err.Error(), "invalid EWS source policy") {
		t.Fatalf("manufactured loopback policy TestConnection err = %v, want invalid EWS source policy", err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("loopback server received %d requests, want 0", got)
	}
}

// TestM365DialSurfaceNamedUnreadGap keeps the M365 connector's dial surface an
// EXPLICITLY NAMED unread gap in the acceptance run, as the work package
// requires: m365_client.go graphGET issues requests through a raw
// http.Client{Timeout: 60s} with NO ssrf policy guard. The gap is accepted
// because the egress HOST is not caller-influenced — it is the compile-time
// graphEndpoint() constant selected by cfg.Cloud, and Cloud is admin-owned:
// neither the self-service route nor the factory merge lets a job steer it.
// This test pins that invariant; if it breaks (Cloud or any URL field becomes
// job-settable), the named gap is void and the surface must be re-adjudicated.
func TestM365DialSurfaceNamedUnreadGap(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	o := NewOrchestrator(pool, nil, "", "m365-named-gap-root", testsupport.TestLogger(), ctx, nil)

	seedM365AppGlobal(t, pool, o, MigrationM365Config{
		ClientID: "global-client", ClientSecret: "global-secret",
		TenantID: "global-tenant", Cloud: "china",
	})

	// A job manufacturing Cloud="global" (and every other field) must not
	// move the egress endpoint off the admin-owned one.
	job := MigrationJobConfig{
		SourceType:    "m365",
		UseGlobalAuth: true,
		SelfService:   CredentialProvenance(true),
		M365: &MigrationM365Config{
			ClientID: "job-client", ClientSecret: "job-secret",
			TenantID: "job-tenant", Cloud: "global",
			SourceEmail: "source@corp.example",
		},
	}
	enc, err := EncryptConfigAny(job, o.encryptionKey)
	if err != nil {
		t.Fatalf("encrypt job config: %v", err)
	}
	storedJob := jobCfgForMerge(t, o, enc)
	merged, err := (m365Factory{o}).merge(&storedJob)
	if err != nil {
		t.Fatalf("m365 merge: %v", err)
	}
	cfg := merged.(*MigrationM365Config)
	if cfg.Cloud != "china" {
		t.Fatalf("merged Cloud = %q, want admin-owned \"china\" — the M365 dial target must stay caller-uninfluenced", cfg.Cloud)
	}
	connector := &M365Connector{cfg: *cfg}
	if got := connector.graphEndpoint(); got != "https://microsoftgraph.chinacloudapi.cn" {
		t.Fatalf("graphEndpoint() = %q, want the admin-owned china constant", got)
	}
}

// jobCfgForMerge decrypts an encoded job config back into the wrapper the
// factory merge takes (the merge reads the job's own fields, not ciphertext).
func jobCfgForMerge(t *testing.T, o *Orchestrator, enc []byte) MigrationJobConfig {
	t.Helper()
	var jobCfg MigrationJobConfig
	if err := DecryptConfigAny(enc, o.encryptionKey, &jobCfg); err != nil {
		t.Fatalf("decrypt job config: %v", err)
	}
	return jobCfg
}

// ── seeding helpers (save/restore pattern of factory_security_test.go) ──

func seedIMAPDefaults(t *testing.T, pool *pgxpool.Pool, global GlobalIMAPConfig) {
	t.Helper()
	ctx := context.Background()

	var oldValue json.RawMessage
	var had bool
	if err := pool.QueryRow(ctx, `SELECT value FROM system_config WHERE key='imap.defaults'`).Scan(&oldValue); err == nil {
		had = true
	}
	t.Cleanup(func() {
		if had {
			_, _ = pool.Exec(ctx, `INSERT INTO system_config(key,value,encrypted) VALUES('imap.defaults',$1,false) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value, encrypted=false`, oldValue)
		} else {
			_, _ = pool.Exec(ctx, `DELETE FROM system_config WHERE key='imap.defaults'`)
		}
	})

	raw, err := json.Marshal(global)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO system_config(key,value,encrypted) VALUES('imap.defaults',$1,false) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value, encrypted=false`, raw); err != nil {
		t.Fatal(err)
	}
}

func seedM365AppGlobal(t *testing.T, pool *pgxpool.Pool, o *Orchestrator, global MigrationM365Config) {
	t.Helper()
	ctx := context.Background()

	var oldValue json.RawMessage
	var oldEncrypted bool
	var had bool
	if err := pool.QueryRow(ctx, `SELECT value, encrypted FROM system_config WHERE key='m365.app'`).Scan(&oldValue, &oldEncrypted); err == nil {
		had = true
	}
	t.Cleanup(func() {
		if had {
			_, _ = pool.Exec(ctx, `INSERT INTO system_config(key,value,encrypted) VALUES('m365.app',$1,$2) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value, encrypted=EXCLUDED.encrypted`, oldValue, oldEncrypted)
		} else {
			_, _ = pool.Exec(ctx, `DELETE FROM system_config WHERE key='m365.app'`)
		}
	})

	systemKey, err := DeriveKey(o.encryptionRoot, "system")
	if err != nil {
		t.Fatal(err)
	}
	encryptedGlobal, err := EncryptConfigAny(global, systemKey)
	if err != nil {
		t.Fatal(err)
	}
	wrapper, _ := json.Marshal(map[string]string{"_enc": base64.StdEncoding.EncodeToString(encryptedGlobal)})
	if _, err := pool.Exec(ctx, `INSERT INTO system_config(key,value,encrypted) VALUES('m365.app',$1,true) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value, encrypted=true`, wrapper); err != nil {
		t.Fatal(err)
	}
}
