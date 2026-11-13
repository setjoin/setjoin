package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/authserver/internal/middleware"
	"setjoin.com/authserver/internal/token"
	sharedauth "setjoin.com/shared/auth"
	sharedmw "setjoin.com/shared/middleware"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/pgnotify"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/threat"
	"setjoin.com/shared/toggle"
)

type fakeConfigChangeListener struct {
	reconnect func(context.Context) error
	handler   pgnotify.NotifyHandler
	channel   string
	err       error
}

func (f *fakeConfigChangeListener) OnReconnect(fn func(context.Context) error) {
	f.reconnect = fn
}

func (f *fakeConfigChangeListener) RegisterReconnect(fn func(context.Context) error) func() {
	f.reconnect = fn
	return func() { f.reconnect = nil }
}

func (f *fakeConfigChangeListener) SubscribeDurable(
	_ context.Context,
	channel string,
	handler pgnotify.NotifyHandler,
) (int, error) {
	f.channel = channel
	f.handler = handler
	return 1, f.err
}

func (f *fakeConfigChangeListener) Unsubscribe(string, int) {}

type fakeFeatureFlags struct {
	mu      sync.Mutex
	enabled map[string]bool
	notify  []string
	reloads int
	err     error
}

func (f *fakeFeatureFlags) IsEnabled(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.enabled[key]
}

func (f *fakeFeatureFlags) OnNotify(key string, enabled bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enabled[key] = enabled
	f.notify = append(f.notify, key)
}

func (f *fakeFeatureFlags) Reload(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reloads++
	return f.err
}

func TestOpenConfigListenerRejectsInvalidDSN(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	listener, err := openConfigListener(t.Context(), "%%%", "", "invalid", logger)
	if err == nil {
		t.Fatal("openConfigListener unexpectedly accepted an invalid DSN")
	}
	if listener != nil {
		t.Fatalf("listener=%v, want nil after connection failure", listener)
	}
}

func TestWaitConfigListenerRetryStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if waitConfigListenerRetry(ctx) {
		t.Fatal("waitConfigListenerRetry returned true after cancellation")
	}
}

type fakeConditionalAccessRuntime struct {
	invalidations int
	breakGlass    []int64
}

func (f *fakeConditionalAccessRuntime) InvalidateCache() { f.invalidations++ }
func (f *fakeConditionalAccessRuntime) SetBreakGlass(ids []int64) {
	f.breakGlass = append([]int64(nil), ids...)
}

func TestConditionalAccessReloaderClearsStaleExclusionsOnFailure(t *testing.T) {
	runtime := &fakeConditionalAccessRuntime{breakGlass: []int64{99}}
	loadErr := errors.New("database unavailable")
	reload := newConditionalAccessReloader(runtime, func(context.Context) ([]int64, error) {
		return nil, loadErr
	})
	if err := reload(t.Context()); !errors.Is(err, loadErr) {
		t.Fatalf("err=%v want=%v", err, loadErr)
	}
	if runtime.invalidations != 1 || runtime.breakGlass != nil {
		t.Fatalf("invalidations=%d breakGlass=%v", runtime.invalidations, runtime.breakGlass)
	}
}

func TestConditionalAccessListenerReloadsInitiallyAndOnNotify(t *testing.T) {
	listener := &fakeConfigChangeListener{}
	runtime := &fakeConditionalAccessRuntime{}
	reloads := 0
	reload := newConditionalAccessReloader(runtime, func(context.Context) ([]int64, error) {
		reloads++
		return []int64{7, 8}, nil
	})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := configureConditionalAccessListener(t.Context(), listener, reload, logger); err != nil {
		t.Fatal(err)
	}
	if listener.channel != threat.ConditionalAccessChannel || reloads != 1 {
		t.Fatalf("channel=%q reloads=%d", listener.channel, reloads)
	}
	listener.handler(&pgconn.Notification{Channel: threat.ConditionalAccessChannel})
	if reloads != 2 || !reflect.DeepEqual(runtime.breakGlass, []int64{7, 8}) {
		t.Fatalf("reloads=%d breakGlass=%v", reloads, runtime.breakGlass)
	}
}

func TestConditionalAccessListenerRejectsFailedSubscription(t *testing.T) {
	want := errors.New("listen refused")
	listener := &fakeConfigChangeListener{err: want}
	reloads := 0
	reload := func(context.Context) error {
		reloads++
		return nil
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	if err := configureConditionalAccessListener(t.Context(), listener, reload, logger); !errors.Is(err, want) {
		t.Fatalf("err=%v, want=%v", err, want)
	}
	if reloads != 0 {
		t.Fatalf("reloads=%d, want 0 after failed subscription", reloads)
	}
}

func TestConditionalAccessNotificationFailureStaysFailClosedAndKeepsListening(t *testing.T) {
	listener := &fakeConfigChangeListener{}
	runtime := &fakeConditionalAccessRuntime{}
	reloads := 0
	want := errors.New("break-glass snapshot unavailable")
	reload := newConditionalAccessReloader(runtime, func(context.Context) ([]int64, error) {
		reloads++
		if reloads == 2 {
			return nil, want
		}
		return []int64{12}, nil
	})
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	if err := configureConditionalAccessListener(t.Context(), listener, reload, logger); err != nil {
		t.Fatal(err)
	}

	listener.handler(&pgconn.Notification{Channel: threat.ConditionalAccessChannel})
	if runtime.breakGlass != nil {
		t.Fatalf("failed reload retained stale break-glass exclusions: %v", runtime.breakGlass)
	}
	if !bytes.Contains(logs.Bytes(), []byte(want.Error())) {
		t.Fatalf("failure was not logged: %s", logs.String())
	}

	// The same durable handler remains usable after the failed notification.
	listener.handler(&pgconn.Notification{Channel: threat.ConditionalAccessChannel})
	if reloads != 3 || !reflect.DeepEqual(runtime.breakGlass, []int64{12}) {
		t.Fatalf("reloads=%d breakGlass=%v", reloads, runtime.breakGlass)
	}
}

func TestOptionalListenerSupervisorRetriesWithFreshAttempt(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	opens := 0
	registers := 0
	var firstAttempt context.Context

	superviseOptionalConfigListener(
		ctx,
		logger,
		"oidc_rp",
		func(attemptCtx context.Context, name string) (configChangeListener, error) {
			if name != "oidc_rp" {
				t.Fatalf("name=%q", name)
			}
			opens++
			if opens == 1 {
				firstAttempt = attemptCtx
			}
			return &fakeConfigChangeListener{}, nil
		},
		func(configChangeListener) error {
			registers++
			if registers == 1 {
				return errors.New("invalid provider row")
			}
			return nil
		},
		func(context.Context) bool { return true },
	)

	if opens != 2 || registers != 2 {
		t.Fatalf("opens=%d registers=%d", opens, registers)
	}
	select {
	case <-firstAttempt.Done():
	default:
		t.Fatal("failed listener attempt was not cancelled before retry")
	}
}

func TestOptionalListenerSupervisorHonorsCancellationAndStoppedRetry(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	cancelledCtx, cancel := context.WithCancel(t.Context())
	cancel()
	opened := false
	superviseOptionalConfigListener(
		cancelledCtx,
		logger,
		"cancelled",
		func(context.Context, string) (configChangeListener, error) {
			opened = true
			return nil, nil
		},
		func(configChangeListener) error { return nil },
		func(context.Context) bool { return true },
	)
	if opened {
		t.Fatal("supervisor opened a listener after its context was cancelled")
	}

	waits := 0
	superviseOptionalConfigListener(
		t.Context(),
		logger,
		"stopped-retry",
		func(context.Context, string) (configChangeListener, error) {
			return nil, errors.New("connection refused")
		},
		func(configChangeListener) error {
			t.Fatal("register called after open failure")
			return nil
		},
		func(context.Context) bool {
			waits++
			return false
		},
	)
	if waits != 1 {
		t.Fatalf("waits=%d, want 1", waits)
	}
}

func TestCredentialRouteHandlersFollowLiveThreatToggles(t *testing.T) {
	flags := &fakeFeatureFlags{enabled: map[string]bool{}}
	var loginCalls, refreshCalls, threatCalls int
	login := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		loginCalls++
		w.WriteHeader(http.StatusNoContent)
	})
	refresh := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		refreshCalls++
		w.WriteHeader(http.StatusNoContent)
	})
	threatMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			threatCalls++
			next.ServeHTTP(w, r)
		})
	}
	loginHandler, refreshHandler := credentialRouteHandlers(login, refresh, flags, threatMiddleware)

	loginHandler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/auth/login", nil))
	if loginCalls != 1 || threatCalls != 0 {
		t.Fatalf("disabled: login=%d threat=%d", loginCalls, threatCalls)
	}
	flags.OnNotify(toggle.FeatureCaptcha, true)
	loginHandler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/auth/login", nil))
	refreshHandler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/auth/refresh", nil))
	if loginCalls != 2 || refreshCalls != 1 || threatCalls != 2 {
		t.Fatalf("enabled: login=%d refresh=%d threat=%d", loginCalls, refreshCalls, threatCalls)
	}
	flags.OnNotify(toggle.FeatureCaptcha, false)
	refreshHandler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/auth/refresh", nil))
	if refreshCalls != 2 || threatCalls != 2 {
		t.Fatalf("disabled again: refresh=%d threat=%d", refreshCalls, threatCalls)
	}
}

// TestCredentialRoutesKeepCSRFForEveryToggleState pins the credential-route
// middleware chain across the whole toggle matrix: CSRF must be mounted on
// login/refresh in EVERY state — including all five threat toggles off, the
// state that previously dropped the sole origin check
// (D-AUTHSERVER-CMD-AUTHSERVERD-001) — while the threat middleware is mounted
// whenever ANY admission control it owns is on. The admission-key set mirrors
// anyThreatFeatureEnabled exactly: the five threat toggles PLUS
// feature.rate_limit, whose omission was the ER5
// occ_c1905b449b2220c3d02fcf5e bypass — with only the (seeded-default-ON)
// rate limiter enabled, the middleware chain skipped the threat pipeline and
// login/refresh ran with no per-IP rate limiting at all.
func TestCredentialRoutesKeepCSRFForEveryToggleState(t *testing.T) {
	threatKeys := []string{
		toggle.FeatureThreatFeed,
		toggle.FeatureGeoBlock,
		toggle.FeatureSprayDetect,
		toggle.FeatureCaptcha,
		toggle.FeatureTarpit,
	}
	// Every key that must independently mount the threat middleware. This MUST
	// stay in lockstep with anyThreatFeatureEnabled — the deny-by-default
	// all-off state and the rate_limit_only state below are the two legs of the
	// sealed bypass.
	admissionKeys := append(append([]string{}, threatKeys...), toggle.FeatureRateLimit)
	type toggleState struct {
		name    string
		enabled map[string]bool
	}
	states := []toggleState{{name: "all_threat_toggles_off", enabled: map[string]bool{}}}
	for _, key := range admissionKeys {
		states = append(states, toggleState{name: key + "_only", enabled: map[string]bool{key: true}})
	}
	// A non-admission toggle must never mount the threat middleware.
	states = append(states, toggleState{
		name:    "non_threat_toggle_only",
		enabled: map[string]bool{toggle.FeatureAppPasswords: true},
	})

	for _, state := range states {
		t.Run(state.name, func(t *testing.T) {
			wantThreat := 0
			for _, key := range admissionKeys {
				if state.enabled[key] {
					wantThreat = 1
				}
			}
			flags := &fakeFeatureFlags{enabled: state.enabled}
			calls := map[string]int{"login": 0, "refresh": 0}
			var threatCalls int
			handlerFor := func(route string) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					calls[route]++
					w.WriteHeader(http.StatusNoContent)
				})
			}
			loginHandler, refreshHandler := credentialRouteHandlers(
				handlerFor("login"), handlerFor("refresh"), flags,
				func(next http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						threatCalls++
						next.ServeHTTP(w, r)
					})
				},
			)

			probe := func(h http.Handler, route, origin string) *httptest.ResponseRecorder {
				req := httptest.NewRequest(http.MethodPost, "/auth/"+route, nil)
				req.Host = "auth.example.com"
				if origin != "" {
					req.Header.Set("Origin", origin)
					// The ER5 CSRF tuple compares the Origin's scheme against
					// the CLIENT-FACING scheme, which behind the gateway is
					// the re-derived X-Forwarded-Proto (client-supplied
					// X-Forwarded-* are stripped by the authproxy before
					// re-derivation). Model that contract: the probe represents
					// a browser request that reached the server as https.
					req.Header.Set("X-Forwarded-Proto", "https")
				}
				rr := httptest.NewRecorder()
				h.ServeHTTP(rr, req)
				return rr
			}

			for route, h := range map[string]http.Handler{"login": loginHandler, "refresh": refreshHandler} {
				// Cross-site POST: the origin check must hold in every toggle state.
				if rr := probe(h, route, "https://evil.invalid"); rr.Code != http.StatusForbidden {
					t.Fatalf("%s cross-site POST: status=%d, want 403 csrf rejection", route, rr.Code)
				}
				if calls[route] != 0 {
					t.Fatalf("%s cross-site POST reached the credential handler without CSRF validation", route)
				}
				// Same-origin POST flows through the identical chain.
				if rr := probe(h, route, "https://auth.example.com"); rr.Code != http.StatusNoContent {
					t.Fatalf("%s same-origin POST: status=%d, want 204", route, rr.Code)
				}
				if calls[route] != 1 {
					t.Fatalf("%s same-origin POST calls=%d, want 1", route, calls[route])
				}
			}
			// Two requests per route; the threat middleware only runs when an
			// admission toggle is on (and stays OUTSIDE CSRF in that case).
			if threatCalls != 4*wantThreat {
				t.Fatalf("threat middleware calls=%d, want %d", threatCalls, 4*wantThreat)
			}
		})
	}
}

// ── requireImpersonatePermission (ER5 occ_beacdec12aebffd6bf626c41) ──────────

const impersonateGateTestSecret = "test-secret-key-at-least-32-chars-long!!"

func newImpersonateGateTestAuthenticator(t *testing.T) (sharedauth.Authenticator, string, string) {
	t.Helper()
	jwt := token.NewJWTProvider(impersonateGateTestSecret, nil, "",
		1*time.Hour, 30*24*time.Hour, "test")
	access, err := jwt.IssueAccess(42, "admin@example.com", true)
	if err != nil {
		t.Fatalf("issue access token: %v", err)
	}
	return token.NewBearerAuthenticator(jwt), access, jwt.Issuer()
}

func impersonateGateRequest(token string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/auth/admin/users/7/impersonate", nil)
	r.Host = "auth.example.com"
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

// TestRequireImpersonatePermission exercises the mount gate decision table:
// a governed users.impersonate grant admits; its absence (the sealed bypass —
// any governed admin could previously mint an impersonation session), a
// resolver failure, a non-admin principal, and missing/invalid credentials
// all deny with the handler never reached. Denials for missing permission are
// audited; resolution errors fail closed WITHOUT audit noise beyond the log.
func TestRequireImpersonatePermission(t *testing.T) {
	authn, access, _ := newImpersonateGateTestAuthenticator(t)

	refreshJWT := token.NewJWTProvider(impersonateGateTestSecret, nil, "",
		1*time.Hour, 30*24*time.Hour, "test")
	refresh, err := refreshJWT.IssueRefresh(42, "admin@example.com")
	if err != nil {
		t.Fatalf("issue refresh token: %v", err)
	}

	handlerReached := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handlerReached++
		w.WriteHeader(http.StatusNoContent)
	})

	run := func(resolver impersonationPermissionResolver, req *http.Request) *httptest.ResponseRecorder {
		t.Helper()
		handlerReached = 0
		audited := 0
		var auditUserID int64
		gate := requireImpersonatePermission(authn, resolver,
			func(r *http.Request, userID int64) {
				audited++
				auditUserID = userID
			}, slog.New(slog.NewTextHandler(io.Discard, nil)))
		rr := httptest.NewRecorder()
		gate(next).ServeHTTP(rr, req)
		if audited == 0 {
			return rr
		}
		if audited != 1 || auditUserID != 42 {
			t.Fatalf("audit calls=%d userID=%d, want 1 call for actor 42", audited, auditUserID)
		}
		return rr
	}

	granted := func(context.Context, int64) (permissions.Authority, error) {
		return permissions.Authority{Permissions: []string{"users.read", "users.impersonate"}}, nil
	}
	ungranted := func(context.Context, int64) (permissions.Authority, error) {
		return permissions.Authority{Permissions: []string{"users.read"}}, nil
	}
	unavailable := func(context.Context, int64) (permissions.Authority, error) {
		return permissions.Authority{}, errors.New("database unavailable")
	}

	t.Run("governed grant admits", func(t *testing.T) {
		rr := run(granted, impersonateGateRequest(access))
		if rr.Code != http.StatusNoContent || handlerReached != 1 {
			t.Fatalf("status=%d handler=%d, want 204 with handler reached", rr.Code, handlerReached)
		}
	})

	t.Run("admin without users.impersonate is denied and audited", func(t *testing.T) {
		rr := run(ungranted, impersonateGateRequest(access))
		if rr.Code != http.StatusForbidden || handlerReached != 0 {
			t.Fatalf("status=%d handler=%d, want 403 with handler unreached", rr.Code, handlerReached)
		}
	})

	t.Run("resolver failure fails closed without admitting", func(t *testing.T) {
		rr := run(unavailable, impersonateGateRequest(access))
		if rr.Code != http.StatusForbidden || handlerReached != 0 {
			t.Fatalf("status=%d handler=%d, want fail-closed 403", rr.Code, handlerReached)
		}
	})

	t.Run("non-admin principal denied before resolution", func(t *testing.T) {
		nonAdminJWT := token.NewJWTProvider(impersonateGateTestSecret, nil, "",
			1*time.Hour, 30*24*time.Hour, "test")
		nonAdmin, ierr := nonAdminJWT.IssueAccess(42, "member@example.com", false)
		if ierr != nil {
			t.Fatalf("issue non-admin token: %v", ierr)
		}
		called := false
		rr := run(func(context.Context, int64) (permissions.Authority, error) {
			called = true
			return permissions.Authority{}, nil
		}, impersonateGateRequest(nonAdmin))
		if rr.Code != http.StatusForbidden || handlerReached != 0 || called {
			t.Fatalf("status=%d handler=%d resolverCalled=%v, want 403 without resolution", rr.Code, handlerReached, called)
		}
	})

	t.Run("refresh token is a wrong token type", func(t *testing.T) {
		rr := run(granted, impersonateGateRequest(refresh))
		if rr.Code != http.StatusForbidden || handlerReached != 0 {
			t.Fatalf("status=%d handler=%d, want 403 for non-access token", rr.Code, handlerReached)
		}
	})

	t.Run("missing credentials are unauthorized", func(t *testing.T) {
		rr := run(granted, impersonateGateRequest(""))
		if rr.Code != http.StatusUnauthorized || handlerReached != 0 {
			t.Fatalf("status=%d handler=%d, want 401", rr.Code, handlerReached)
		}
		if rr.Header().Get("WWW-Authenticate") == "" {
			t.Fatal("401 must carry the WWW-Authenticate challenge (RequireAuth parity)")
		}
	})
}

// TestWebAuthnRegisterFinishMountBoundsAndCSRF proves the mount legs the ER5
// passkey-registration closure adds, in the exact composition main.go wires
// (limitRequestBody outermost → authenticated CSRF chain): an oversized
// attestation body is refused 413 before any inner middleware reads it, a
// cross-site browser POST is refused 403 by the CSRF invariant before the
// handler runs, and a same-origin POST with a valid access session reaches the
// handler. Before the patch this route carried requireAuth ONLY — no body
// bound and no origin check.
func TestWebAuthnRegisterFinishMountBoundsAndCSRF(t *testing.T) {
	jwt := token.NewJWTProvider(impersonateGateTestSecret, nil, "",
		1*time.Hour, 30*24*time.Hour, "test")
	access, err := jwt.IssueAccess(42, "admin@example.com", true)
	if err != nil {
		t.Fatalf("issue access token: %v", err)
	}
	requireAuth := middleware.RequireAuth(token.NewBearerAuthenticator(jwt), slog.New(slog.NewTextHandler(io.Discard, nil)))

	handlerReached := 0
	mount := limitRequestBody(webauthnRegistrationBodyLimit,
		requireAuth(sharedmw.CSRF(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			handlerReached++
			w.WriteHeader(http.StatusNoContent)
		}))))

	post := func(body []byte, origin string) *httptest.ResponseRecorder {
		t.Helper()
		handlerReached = 0
		r := httptest.NewRequest(http.MethodPost, "/auth/webauthn/register/finish", bytes.NewReader(body))
		r.Host = "auth.example.com"
		r.Header.Set("Authorization", "Bearer "+access)
		r.Header.Set("X-Forwarded-Proto", "https")
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		rr := httptest.NewRecorder()
		mount.ServeHTTP(rr, r)
		return rr
	}

	oversized := bytes.Repeat([]byte("a"), int(webauthnRegistrationBodyLimit)+4096)
	if rr := post(oversized, ""); rr.Code != http.StatusRequestEntityTooLarge || handlerReached != 0 {
		t.Fatalf("oversized body: status=%d handler=%d, want 413 before the handler", rr.Code, handlerReached)
	}

	valid := []byte(`{"attestation":"e30="}`)
	if rr := post(valid, "https://evil.invalid"); rr.Code != http.StatusForbidden || handlerReached != 0 {
		t.Fatalf("cross-site POST: status=%d handler=%d, want 403 csrf rejection", rr.Code, handlerReached)
	}
	if rr := post(valid, "https://auth.example.com"); rr.Code != http.StatusNoContent || handlerReached != 1 {
		t.Fatalf("same-origin POST: status=%d handler=%d, want 204", rr.Code, handlerReached)
	}
}

// TestDeviceRegisterMountAdmissionBound proves the ER5 push-device
// registration closure's bound leg in the composition main.go wires: an
// oversized registration body is refused 413 before anything downstream reads
// it. push_devices has no per-user row cap and no token-uniqueness constraint,
// so this body bound is the per-request storage ceiling of the registration
// amplification (the fan-out side rides the threat interceptor's per-IP
// admission cap, pinned on the credential routes).
func TestDeviceRegisterMountAdmissionBound(t *testing.T) {
	jwt := token.NewJWTProvider(impersonateGateTestSecret, nil, "",
		1*time.Hour, 30*24*time.Hour, "test")
	access, err := jwt.IssueAccess(42, "user@example.com", false)
	if err != nil {
		t.Fatalf("issue access token: %v", err)
	}
	requireAuth := middleware.RequireAuth(token.NewBearerAuthenticator(jwt), slog.New(slog.NewTextHandler(io.Discard, nil)))

	handlerReached := 0
	mount := limitRequestBody(pushDeviceRegistrationBodyLimit,
		requireAuth(sharedmw.CSRF(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			handlerReached++
			w.WriteHeader(http.StatusNoContent)
		}))))

	r := httptest.NewRequest(http.MethodPost, "/auth/device/register",
		bytes.NewReader(bytes.Repeat([]byte("a"), int(pushDeviceRegistrationBodyLimit)+4096)))
	r.Header.Set("Authorization", "Bearer "+access)
	rr := httptest.NewRecorder()
	mount.ServeHTTP(rr, r)
	if rr.Code != http.StatusRequestEntityTooLarge || handlerReached != 0 {
		t.Fatalf("oversized registration body: status=%d handler=%d, want 413 before the handler", rr.Code, handlerReached)
	}
}

// TestMFAManagementMountsCarryAdmissionBounds is the source-level text gate
// for the ER5 factor-management closures (the s01 route-inventory pattern):
// the mounts minting or activating persistent authentication capability —
// TOTP setup/confirm, recovery-code regeneration, WebAuthn registration, push
// device registration — and the impersonation gate must keep their admission
// bounds (threat interceptor per-IP pipeline, body caps, CSRF, permission
// gate). A drive-by refactor that drops one leg fails here instead of
// silently reopening the sealed occurrences.
func TestMFAManagementMountsCarryAdmissionBounds(t *testing.T) {
	mainSrc, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go (go test runs in the package dir): %v", err)
	}
	runtimeSrc, err := os.ReadFile("security_runtime.go")
	if err != nil {
		t.Fatalf("read security_runtime.go: %v", err)
	}
	// Each fragment pins ONE leg of one mount chain.
	type fragment struct {
		src  []byte
		text string
	}
	fragments := []fragment{
		// TOTP enrollment/activation + recovery regeneration ride the per-IP
		// admission pipeline outside requireAuth/CSRF.
		{mainSrc, "threatInterceptor.Middleware(requireAuth(http.HandlerFunc(authH.TOTPSetup)))"},
		{mainSrc, "threatInterceptor.Middleware(requireAuth(sharedmw.CSRF(http.HandlerFunc(authH.TOTPConfirm))))"},
		{mainSrc, "threatInterceptor.Middleware(requireAuth(sharedmw.CSRF(http.HandlerFunc(authH.GenerateBackupCodes))))"},
		// First-factor step-up re-auth challenge (ER5 s07): mints the
		// reauth_token the setup/confirm/generate gates consume, so it rides
		// the same admission pipeline. REVISED (possession scheme v7 §3.2 T2):
		// the issuance surfaces add the strict application/json gate (415 at
		// the mount, before the decoder); the C1 possession endpoints carry
		// the same admission pipeline (begin/finish resolve their dual token
		// admission in-handler, so they mount without requireAuth but keep
		// CSRF + the strict media type).
		{mainSrc, "threatInterceptor.Middleware(requireAuth(sharedmw.CSRF(handlers.RequireJSONContentType(http.HandlerFunc(authH.MFAReauthBegin)))))"},
		{mainSrc, "threatInterceptor.Middleware(requireAuth(sharedmw.CSRF(handlers.RequireJSONContentType(http.HandlerFunc(authH.MFAPossessionTOTP)))))"},
		{mainSrc, "threatInterceptor.Middleware(sharedmw.CSRF(handlers.RequireJSONContentType(http.HandlerFunc(authH.MFAPossessionWebAuthnBegin))))"},
		{mainSrc, "threatInterceptor.Middleware(sharedmw.CSRF(handlers.RequireJSONContentType(http.HandlerFunc(authH.MFAPossessionWebAuthnFinish))))"},
		// WebAuthn registration begin rides admission; finish carries the full
		// body-cap chain.
		{mainSrc, "threatInterceptor.Middleware(requireAuth(http.HandlerFunc(authH.WebAuthnRegisterBegin)))"},
		{mainSrc, "limitRequestBody(webauthnRegistrationBodyLimit,"},
		{mainSrc, "threatInterceptor.Middleware(requireAuth(sharedmw.CSRF(http.HandlerFunc(authH.WebAuthnRegisterFinish))))"},
		// Push device registration body cap (occ_fd402745).
		{mainSrc, "limitRequestBody(pushDeviceRegistrationBodyLimit,"},
		{mainSrc, "threatInterceptor.Middleware(requireAuth(sharedmw.CSRF(http.HandlerFunc(authH.DeviceRegister))))"},
		// Impersonation permission gate (occ_beacdec) stays mounted inside
		// requireAuth/CSRF, before the handler.
		{mainSrc, "requireImpersonatePermission("},
		{mainSrc, "http.HandlerFunc(authH.AdminImpersonate)"},
		// The credential-route dispatch must keep the rate-limit admission key
		// (occ_c1905) — the dispatch predicate lives in security_runtime.go.
		{runtimeSrc, "flags.IsEnabled(toggle.FeatureRateLimit)"},
	}
	for _, f := range fragments {
		if !bytes.Contains(f.src, []byte(f.text)) {
			t.Errorf("mount gate fragment missing: %q", f.text)
		}
	}
}

// seedGateTestUser plants a real users+mailboxes row (users.is_admin FALSE —
// the modern model: admin authority is DERIVED from governed assignments) and
// returns its id and email. Mirrors the handlers package's fixture SQL, but
// plants its own local domain first so the test is self-sufficient on a freshly
// loaded schema.
func seedGateTestUser(t *testing.T, pool *pgxpool.Pool, ctx context.Context, tag string) (int64, string) {
	t.Helper()
	const gateDomain = "er5s07-gate.test"
	if _, err := pool.Exec(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE)
		 ON CONFLICT (name) DO NOTHING`,
		gateDomain,
	); err != nil {
		t.Fatalf("seed domain: %v", err)
	}
	var userID int64
	var email string
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, sync_source, enabled, is_admin, password_hash)
		 SELECT $1||'-'||floor(random()*1e9)::text,
		        $1||'-'||floor(random()*1e9)::text||'@`+gateDomain+`',
		        'ER5S07 Gate '||$1,
		        d.id, 'local', TRUE, FALSE, ''
		 FROM domains d WHERE d.name = $2
		 RETURNING id, email`,
		tag, gateDomain,
	).Scan(&userID, &email); err != nil {
		t.Skipf("seed user (%s) failed (schema not loaded?): %v", tag, err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary)
		 SELECT u.id, u.domain_id, u.email, u.display_name, 'personal', TRUE
		 FROM users u WHERE u.id = $1`,
		userID,
	); err != nil {
		pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
		t.Skipf("seed mailbox (%s) failed: %v", tag, err)
	}
	return userID, email
}

// cleanGateTestUser removes every row the gate fixtures created (assignment →
// group → mailbox → user), mirroring the handlers package's cleanup contract.
func cleanGateTestUser(t *testing.T, pool *pgxpool.Pool, ctx context.Context, userID int64, groupIDs []int64) {
	t.Helper()
	pool.Exec(ctx, `DELETE FROM admin_role_assignments WHERE user_id = $1`, userID)
	for _, id := range groupIDs {
		pool.Exec(ctx, `DELETE FROM admin_role_groups WHERE id = $1`, id)
	}
	var mailboxIDs []int64
	rows, _ := pool.Query(ctx, `SELECT id FROM mailboxes WHERE user_id = $1`, userID)
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			mailboxIDs = append(mailboxIDs, id)
		}
	}
	rows.Close()
	pool.Exec(ctx, `UPDATE mailboxes SET is_primary = FALSE, user_id = NULL WHERE user_id = $1`, userID)
	for _, id := range mailboxIDs {
		pool.Exec(ctx, `DELETE FROM mailboxes WHERE id = $1`, id)
	}
	pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
	pool.Exec(ctx, `DELETE FROM domains WHERE name = 'er5s07-gate.test'`)
}

// seedGateTestRoleGroup plants a non-builtin admin_role_groups row with the
// given permission set and returns its id.
func seedGateTestRoleGroup(t *testing.T, pool *pgxpool.Pool, ctx context.Context, name string, perms []string) int64 {
	t.Helper()
	var id int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO admin_role_groups (name, description, permissions, domain_scope, is_builtin)
		 VALUES ($1, 'er5-s07 gate test group', $2::text[], NULL, FALSE)
		 RETURNING id`,
		name, perms,
	).Scan(&id); err != nil {
		t.Fatalf("seed role group %s: %v", name, err)
	}
	return id
}

// grantGateTestAssignment writes an unexpired governed assignment (expires_at
// NULL = permanent) of the given group to the user, exactly what AssignMember
// / SSO do.
func grantGateTestAssignment(t *testing.T, pool *pgxpool.Pool, ctx context.Context, userID, groupID int64) {
	t.Helper()
	if _, err := pool.Exec(ctx,
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by)
		 VALUES ($1, $2, NULL) ON CONFLICT (user_id, role_group_id) DO NOTHING`,
		userID, groupID,
	); err != nil {
		t.Fatalf("grant governed assignment: %v", err)
	}
}

// TestRequireImpersonatePermission_ResolvesLiveGovernedGrant is the DB-backed
// leg of the ER5 impersonation closure: the mount gate wired in main.go
// resolves the actor's permission through permissions.ResolveAuthority — the
// same governed-assignment resolver the login mint uses — against REAL rows.
// A governed admin WITHOUT the users.impersonate grant (the sealed bypass:
// the handler's "is an admin" re-validation alone let them through) is denied
// with an admin_impersonate_denied audit row; granting the permission admits;
// expiring the assignment revokes the authority live.
func TestRequireImpersonatePermission_ResolvesLiveGovernedGrant(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	userID, _ := seedGateTestUser(t, pool, ctx, "er5s07-gate")
	reader := seedGateTestRoleGroup(t, pool, ctx, "er5s07-gate-reader", []string{"users.read"})
	impersonator := seedGateTestRoleGroup(t, pool, ctx, "er5s07-gate-impersonator", []string{"users.impersonate"})
	defer cleanGateTestUser(t, pool, ctx, userID, []int64{reader, impersonator})
	grantGateTestAssignment(t, pool, ctx, userID, reader)

	jwt := token.NewJWTProvider(impersonateGateTestSecret, nil, "",
		1*time.Hour, 30*24*time.Hour, "test")
	access, err := jwt.IssueAccess(userID, "gate-admin@er5s07.internal", true)
	if err != nil {
		t.Fatalf("issue access token: %v", err)
	}
	// The gate wired in main.go: live governed-assignment resolution.
	resolve := func(ctx context.Context, id int64) (permissions.Authority, error) {
		return permissions.ResolveAuthority(ctx, pool, id)
	}
	handlerReached := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handlerReached++
		w.WriteHeader(http.StatusNoContent)
	})
	gate := requireImpersonatePermission(token.NewBearerAuthenticator(jwt), resolve,
		func(r *http.Request, uid int64) {
			if _, err := pool.Exec(r.Context(),
				`INSERT INTO audit_log (user_id, source_ip, event_type, metadata)
				 VALUES ($1, $2::INET, 'admin_impersonate_denied',
				         jsonb_build_object('reason','missing_permission','permission',$3::text))`,
				uid, "127.0.0.1", permissions.PermUsersImpersonate); err != nil {
				t.Fatalf("audit insert: %v", err)
			}
		}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	serve := func() *httptest.ResponseRecorder {
		t.Helper()
		handlerReached = 0
		rr := httptest.NewRecorder()
		gate(next).ServeHTTP(rr, impersonateGateRequest(access))
		return rr
	}

	// Governed admin WITHOUT the permission: denied, audited, handler unreached.
	rr := serve()
	if rr.Code != http.StatusForbidden || handlerReached != 0 {
		t.Fatalf("ungranted governed admin: status=%d handler=%d, want 403 (the sealed bypass)", rr.Code, handlerReached)
	}
	var reason string
	if err := pool.QueryRow(ctx,
		`SELECT metadata->>'reason' FROM audit_log
		  WHERE user_id = $1 AND event_type = 'admin_impersonate_denied'
		  ORDER BY id DESC LIMIT 1`,
		userID,
	).Scan(&reason); err != nil {
		t.Fatalf("expected an admin_impersonate_denied audit row for user %d: %v", userID, err)
	}
	if reason != "missing_permission" {
		t.Fatalf("audit reason = %q, want %q", reason, "missing_permission")
	}

	// Grant users.impersonate through a second governed group: admitted.
	grantGateTestAssignment(t, pool, ctx, userID, impersonator)
	rr = serve()
	if rr.Code != http.StatusNoContent || handlerReached != 1 {
		t.Fatalf("granted governed admin: status=%d handler=%d, want 204", rr.Code, handlerReached)
	}

	// Expire the impersonator assignment: the authority is revoked LIVE (the
	// resolver honors expires_at) — this is why the gate re-resolves per
	// request instead of trusting the mint-time projection.
	if _, err := pool.Exec(ctx,
		`UPDATE admin_role_assignments SET expires_at = now() - interval '1 second'
		  WHERE user_id = $1 AND role_group_id = $2`,
		userID, impersonator,
	); err != nil {
		t.Fatalf("expire assignment: %v", err)
	}
	rr = serve()
	if rr.Code != http.StatusForbidden || handlerReached != 0 {
		t.Fatalf("expired impersonate grant: status=%d handler=%d, want 403", rr.Code, handlerReached)
	}
}
