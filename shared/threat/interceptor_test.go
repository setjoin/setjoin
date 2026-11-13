package threat

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"setjoin.com/shared/clientip"
	"setjoin.com/shared/toggle"
)

type failingRequestBody struct{}

func (failingRequestBody) Read([]byte) (int, error) { return 0, fmt.Errorf("synthetic read failure") }
func (failingRequestBody) Close() error             { return nil }

func TestClientIP(t *testing.T) {
	// threatClientIP delegates to the shared clientip leaf package; set the
	// trusted proxy there so the XFF-trust branch is exercised.
	clientip.SetTrustedProxy("1.2.3.4")
	t.Cleanup(func() { clientip.SetTrustedProxy("") })

	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		want       string
	}{
		{"plain remote addr", "1.2.3.4:12345", nil, "1.2.3.4"},
		{"ipv6 remote addr", "[::1]:54321", nil, "::1"},
		{"x-forwarded-for", "1.2.3.4:12345", map[string]string{"X-Forwarded-For": "10.0.0.1, 10.0.0.2"}, "10.0.0.2"},
		{"x-forwarded-for from untrusted proxy", "2.2.2.2:12345", map[string]string{"X-Forwarded-For": "10.0.0.5"}, "2.2.2.2"},
		{"remote addr without port", "1.2.3.4", nil, "1.2.3.4"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			got := threatClientIP(req)
			if got != tt.want {
				t.Errorf("ClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMaskIP(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"192.168.1.100", "192.168.1.0"},
		{"10.0.0.1", "10.0.0.0"},
		{"2001:db8:85a3::8a2e:370:7334", "2001:db8:85a3::"},
		{"::1", "::1"},
		{"single", "single"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := MaskIP(tt.input)
			if got != tt.want {
				t.Errorf("MaskIP(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestMakeDeviceFP_ForgeableSurfacePinned pins the exact composition and the
// forgeability boundary of the device fingerprint
// (occ_a2f0b8dcd018479c87ead765). The FP is "<UA>|<masked-IP>": everything is
// reproducible from a client-set header plus an IP masked to a /24 (v4) or
// /48 (v6), so a caller in the same masked range with the same UA reproduces
// a victim's FP. The test documents that reproduction, pins the divergent
// inputs, and single-sources the interceptor's recording path, so any future
// change to the composition (which would invalidate seeded
// managed_devices.device_hash rows) cannot land silently.
func TestMakeDeviceFP_ForgeableSurfacePinned(t *testing.T) {
	const victimUA = "SetjoiniOS/3.2 (iPhone17,2)"

	victim := MakeDeviceFP(victimUA, "203.0.113.10")
	if want := victimUA + "|203.0.113.0"; victim != want {
		t.Fatalf("MakeDeviceFP = %q, want %q", victim, want)
	}

	// Reproduction from the same masked range + UA (the forgery surface).
	if attacker := MakeDeviceFP(victimUA, "203.0.113.77"); attacker != victim {
		t.Fatalf("same /24 + UA must reproduce the FP: %q != %q", attacker, victim)
	}

	// Divergent inputs diverge the FP.
	if fp := MakeDeviceFP("Other/1.0", "203.0.113.10"); fp == victim {
		t.Error("different UA collided with the victim FP")
	}
	if fp := MakeDeviceFP(victimUA, "198.51.100.10"); fp == victim {
		t.Error("different /24 collided with the victim FP")
	}
	// The last v4 octet is MASKED, so it must NOT diverge.
	if fp := MakeDeviceFP(victimUA, "203.0.113.11"); fp != victim {
		t.Errorf("masked octet changed the FP: %q", fp)
	}

	// IPv6 masks to /48: same /48 reproduces, a different /48 diverges.
	if MakeDeviceFP(victimUA, "2001:db8:85a3::1") != MakeDeviceFP(victimUA, "2001:db8:85a3:0:aaaa::") {
		t.Error("same IPv6 /48 did not reproduce the FP")
	}
	if MakeDeviceFP(victimUA, "2001:db8:85a3::1") == MakeDeviceFP(victimUA, "2001:db8:9999::1") {
		t.Error("different IPv6 /48 collided")
	}

	// The stored/lookup identity is sha256-hex of the FP (managed_devices and
	// device_registry key on exactly this derivation).
	sum := sha256.Sum256([]byte(victim))
	wantHash := hex.EncodeToString(sum[:])
	if len(wantHash) != 64 {
		t.Fatalf("device_hash derivation produced %d hex chars", len(wantHash))
	}

	// The interceptor's recording path is single-sourced on MakeDeviceFP: the
	// two compositions cannot drift.
	ti := &ThreatInterceptor{}
	if ti.deviceFingerprint(ConnectionMeta{UserAgent: victimUA, SourceIP: "203.0.113.10"}) != victim {
		t.Error("deviceFingerprint drifted from MakeDeviceFP")
	}
}

func TestCaptchaSignAndVerify(t *testing.T) {
	secret := []byte("test-captcha-secret-32bytes!!")
	ti := &ThreatInterceptor{captchaSecret: secret}

	t.Run("valid captcha", func(t *testing.T) {
		token, a, b := ti.generateCaptcha()
		answer := a + b
		if !ti.verifyCaptcha(token, fmt.Sprintf("%d", answer)) {
			t.Error("verifyCaptcha should succeed for correct answer")
		}
	})

	t.Run("wrong answer", func(t *testing.T) {
		token, a, b := ti.generateCaptcha()
		wrongAnswer := a + b + 1
		if ti.verifyCaptcha(token, fmt.Sprintf("%d", wrongAnswer)) {
			t.Error("verifyCaptcha should fail for wrong answer")
		}
	})

	t.Run("tampered token", func(t *testing.T) {
		token, _, _ := ti.generateCaptcha()
		parts := strings.SplitN(token, ".", 2)
		if len(parts) == 2 {
			tampered := parts[0] + ".AAAA"
			if ti.verifyCaptcha(tampered, "3") {
				t.Error("verifyCaptcha should fail for tampered token")
			}
		}
	})

	t.Run("malformed token", func(t *testing.T) {
		if ti.verifyCaptcha("not-a-valid-token", "3") {
			t.Error("verifyCaptcha should fail for malformed token")
		}
	})

	t.Run("empty answer", func(t *testing.T) {
		token, _, _ := ti.generateCaptcha()
		if ti.verifyCaptcha(token, "") {
			t.Error("verifyCaptcha should fail for empty answer")
		}
	})
}

func TestWriteThreatResponse(t *testing.T) {
	tests := []struct {
		name  string
		code  int
		delay time.Duration
	}{
		{"reject", http.StatusForbidden, 0},
		{"rate_limit", http.StatusTooManyRequests, 0},
		{"tarpit with delay", http.StatusOK, 5 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			writeThreatResponse(w, tt.code, "test_reason", "test prompt", "test-token", tt.delay)

			if w.Code != tt.code {
				t.Errorf("status = %d, want %d", w.Code, tt.code)
			}
			if w.Header().Get("X-Threat-Reason") != "test_reason" {
				t.Errorf("X-Threat-Reason = %q, want %q", w.Header().Get("X-Threat-Reason"), "test_reason")
			}
			if tt.delay > 0 {
				if w.Header().Get("X-Threat-Delay") != tt.delay.String() {
					t.Errorf("X-Threat-Delay = %q, want %q", w.Header().Get("X-Threat-Delay"), tt.delay.String())
				}
			}
			if w.Header().Get("Content-Type") != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", w.Header().Get("Content-Type"))
			}
		})
	}
}

func TestInterceptorResultString(t *testing.T) {
	tests := []struct {
		result InterceptorResult
		want   string
	}{
		{ActionProceed, "proceed"},
		{ActionReject, "reject"},
		{ActionCaptchaNeeded, "captcha"},
		{ActionRateLimited, "rate_limit"},
		{ActionTarpitted, "tarpit"},
		{InterceptorResult(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.result.String()
			if got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStatusCodeRecorder(t *testing.T) {
	w := httptest.NewRecorder()
	rec := &statusCodeRecorder{ResponseWriter: w, statusCode: 0}

	if rec.statusCode != 0 {
		t.Errorf("initial statusCode = %d, want 0", rec.statusCode)
	}

	rec.WriteHeader(http.StatusTeapot)

	if rec.statusCode != http.StatusTeapot {
		t.Errorf("statusCode after WriteHeader = %d, want %d", rec.statusCode, http.StatusTeapot)
	}
	if w.Code != http.StatusTeapot {
		t.Errorf("underlying status = %d, want %d", w.Code, http.StatusTeapot)
	}
}

func TestFeedParse(t *testing.T) {
	// Test CIDR line parsing from the Spamhaus DROP format
	tests := []struct {
		line string
		want string
	}{
		{"1.2.3.0/24 ; SBL123456", "1.2.3.0/24"},
		{"10.0.0.0/8 ; SBL789", "10.0.0.0/8"},
		{"192.168.0.0/16 SBL000", "192.168.0.0/16"},
		{"; comment only", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			cidr := parseCIDRFromLine(tt.line)
			if cidr != tt.want {
				t.Errorf("parseCIDRFromLine(%q) = %q, want %q", tt.line, cidr, tt.want)
			}
		})
	}
}

func TestCaptchaExpired(t *testing.T) {
	secret := []byte("test-secret-32-bytes-long!!!!!")
	ti := &ThreatInterceptor{captchaSecret: secret}
	token := captchaToken(secret, "42", time.Now().Add(-1*time.Hour).Unix())
	if ti.verifyCaptcha(token, "42") {
		t.Error("expired token should be rejected")
	}
}

func TestCaptchaNotExpired(t *testing.T) {
	secret := []byte("test-secret-32-bytes-long!!!!!")
	ti := &ThreatInterceptor{captchaSecret: secret}
	token := captchaToken(secret, "42", time.Now().Add(5*time.Minute).Unix())
	if !ti.verifyCaptcha(token, "42") {
		t.Error("non-expired token should be accepted")
	}
}

// TestCaptchaTokenHidesAnswer is the regression for the cleartext-answer leak:
// the answer must NOT be recoverable from the token alone. An attacker who
// base64-decodes the token (the trivial bypass the old format allowed) must not
// find the answer, and submitting a token with no/another answer must fail.
func TestCaptchaTokenHidesAnswer(t *testing.T) {
	secret := []byte("test-secret-32-bytes-long!!!!!")
	ti := &ThreatInterceptor{captchaSecret: secret}

	const answer = "5"
	exp := time.Now().Add(2 * time.Minute).Unix()
	token := captchaToken(secret, answer, exp)

	// Decoding the token must not reveal the answer as a readable field. The OLD
	// format was "answer|exp.<mac>" — an attacker base64-decoded it and read the
	// value before "|". The NEW format is "exp.<mac>": the only cleartext field is
	// the (already public) expiry, and the answer survives only inside the keyed,
	// one-way MAC. Asserting the decoded token has NO "|" and its prefix is exactly
	// the expiry precisely distinguishes the two formats (and is deterministic —
	// a substring check on the answer would false-positive on the exp's digits).
	decoded, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("token should be base64: %v", err)
	}
	if strings.Contains(string(decoded), "|") {
		t.Fatalf("token still carries the cleartext 'answer|exp' payload: %q", string(decoded))
	}
	parts := strings.SplitN(string(decoded), ".", 2)
	if len(parts) != 2 || parts[0] != fmt.Sprintf("%d", exp) {
		t.Fatalf("cleartext prefix must be exactly the expiry, got %q", parts[0])
	}

	// The committed answer still verifies; a wrong answer does not.
	if !ti.verifyCaptcha(token, answer) {
		t.Error("correct answer should verify")
	}
	if ti.verifyCaptcha(token, "6") {
		t.Error("wrong answer must not verify")
	}
}

// TestMiddleware_CaptchaPathRestoresBody is the regression for the dropped-body
// bug: extractMeta drains r.Body into meta.rawBody, so the CAPTCHA-verified path
// must re-inject it before calling the handler. Without the restore the downstream
// login handler sees an empty body and the captcha-retry login can never succeed.
func TestMiddleware_CaptchaPathRestoresBody(t *testing.T) {
	secret := []byte("test-secret-32-bytes-long!!!!!")
	ti := &ThreatInterceptor{
		captchaSecret: secret,
		// All controls off + nil policyEngine -> fast-path proceed (no DB). Every
		// key must be explicit: toggle.IsEnabled returns true for UNKNOWN keys.
		toggles: toggle.NewStatic(map[string]bool{
			toggle.FeatureThreatFeed:  false,
			toggle.FeatureGeoBlock:    false,
			toggle.FeatureSprayDetect: false,
			toggle.FeatureCaptcha:     false,
			toggle.FeatureTarpit:      false,
			toggle.FeatureRateLimit:   false,
		}),
	}

	var gotBody string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	})

	body := `{"email":"u@x.com","password":"p"}`
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	req.Header.Set("X-Captcha-Token", captchaToken(secret, "5", time.Now().Add(2*time.Minute).Unix()))
	req.Header.Set("X-Captcha-Answer", "5")
	rec := httptest.NewRecorder()

	ti.Middleware(next).ServeHTTP(rec, req)

	if gotBody != body {
		t.Fatalf("captcha path must restore body for the handler; handler saw %q, want %q", gotBody, body)
	}
}

func TestMiddlewareRejectsOversizedBodyBeforeHandler(t *testing.T) {
	ti := &ThreatInterceptor{toggles: toggle.NewStatic(map[string]bool{})}
	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(strings.Repeat("x", int(threatHTTPBodyLimit)+1)))
	rec := httptest.NewRecorder()
	ti.Middleware(next).ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
	if called {
		t.Fatal("oversized request reached downstream handler")
	}
}

func TestMiddlewareRejectsUnreadableBody(t *testing.T) {
	ti := &ThreatInterceptor{}
	reached := false
	handler := ti.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req.Body = failingRequestBody{}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || reached || !strings.Contains(rec.Body.String(), "invalid_body") {
		t.Fatalf("status=%d reached=%v body=%s", rec.Code, reached, rec.Body.String())
	}
}

// TestFastPath_RateLimitNotBypassed is the regression for the fail-open fast
// path: enabling ONLY the rate limiter must keep the pipeline live so the limit
// is enforced. Before the fix the fast path omitted FeatureRateLimit, returned
// ActionProceed, and silently skipped rate limiting.
func TestFastPath_RateLimitNotBypassed(t *testing.T) {
	flags := toggle.NewStatic(map[string]bool{
		toggle.FeatureThreatFeed:  false,
		toggle.FeatureGeoBlock:    false,
		toggle.FeatureSprayDetect: false,
		toggle.FeatureCaptcha:     false,
		toggle.FeatureTarpit:      false,
		toggle.FeatureRateLimit:   true, // the ONLY enabled control
	})
	ti := &ThreatInterceptor{
		pool:    nil, // step-2 ip_rules no-ops on nil pool; no DB needed
		toggles: flags,
		cfg:     cfgForSpray(), // RateLimitPerMin == 0
		lockout: NewLockoutManager(&fakeLockoutStore{}, nil),
		spray:   NewSprayDetector(&fakeSprayStore{detect: false}, cfgForSpray(), nil),
		// count 1 > RateLimitPerMin 0 -> Allow returns false (rate limited)
		rateLimit: NewRateLimiter(&fakeRLStore{count: 1}, cfgForSpray(), nil),
	}
	res, reason, _ := ti.intercept(context.Background(), ConnectionMeta{SourceIP: "1.2.3.4", Username: "bob@x"}, true)
	if res != ActionRateLimited || reason != "rate_limited" {
		t.Fatalf("rate-limit-only config must enforce the limit; got %v %q", res, reason)
	}
}

// newToggledInterceptor builds a pipeline-active ThreatInterceptor with a nil
// pool and the three adapters injected, so the lockout/spray/rate-limit decisions
// can be driven from fakes without a live DB. SprayDetect is enabled (skips the
// all-disabled fast-path); ThreatFeed/GeoBlock/Captcha/Tarpit/RateLimit are off so
// only the adapter paths run. The nil-pool guard at step 2 keeps it DB-free.
func newToggledInterceptor(t *testing.T) *ThreatInterceptor {
	t.Helper()
	flags := toggle.NewStatic(map[string]bool{
		toggle.FeatureThreatFeed:  false,
		toggle.FeatureGeoBlock:    false,
		toggle.FeatureSprayDetect: true,
		toggle.FeatureCaptcha:     false,
		toggle.FeatureTarpit:      false,
		toggle.FeatureRateLimit:   false,
	})
	return &ThreatInterceptor{
		pool:      nil,
		toggles:   flags,
		cfg:       cfgForSpray(),
		spray:     NewSprayDetector(&fakeSprayStore{detect: false}, cfgForSpray(), nil),
		rateLimit: NewRateLimiter(&fakeRLStore{count: 0}, cfgForSpray(), nil),
		// lockout is set by the individual test.
	}
}

// TestIntercept_LockoutPath_UsesLockoutManager proves the lockout decision now
// flows through the injected LockoutManager adapter: a "locked" store makes
// intercept reject with the remaining time — clamped to the tarpit-convention
// cap when the remainder exceeds it (med-shard3-023: an uncapped exponential
// remainder would hold the connection minutes-to-hours per rejected request).
// Sub-cap passthrough is covered in lockout_bound_test.go.
func TestIntercept_LockoutPath_UsesLockoutManager(t *testing.T) {
	ti := newToggledInterceptor(t)
	lf := &fakeLockoutStore{lockedKeys: map[string]time.Duration{"user:bob@x": 42 * time.Second}}
	ti.lockout = NewLockoutManager(lf, nil)
	res, reason, delay := ti.intercept(context.Background(), ConnectionMeta{SourceIP: "1.2.3.4", Username: "bob@x"}, true)
	if res != ActionReject || reason != "lockout" || delay != maxThreatResponseDelay {
		t.Fatalf("lockout path must reject with the capped remaining; got %v %q %v", res, reason, delay)
	}
}

// TestIntercept_NotLocked_ProceedsPastLockout proves a not-locked store lets the
// pipeline fall through the lockout + spray + rate-limit adapter steps to proceed.
func TestIntercept_NotLocked_ProceedsPastLockout(t *testing.T) {
	ti := newToggledInterceptor(t)
	ti.lockout = NewLockoutManager(&fakeLockoutStore{}, nil)
	res, reason, _ := ti.intercept(context.Background(), ConnectionMeta{SourceIP: "1.2.3.4", Username: "bob@x"}, true)
	if res != ActionProceed || reason != "" {
		t.Fatalf("not-locked path must proceed; got %v %q", res, reason)
	}
}

func parseCIDRFromLine(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, ";") {
		return ""
	}
	cidr := line
	if idx := strings.IndexByte(line, ';'); idx >= 0 {
		cidr = strings.TrimSpace(line[:idx])
	} else if idx := strings.IndexByte(line, ' '); idx >= 0 {
		cidr = strings.TrimSpace(line[:idx])
	}
	if cidr != "" && strings.Contains(cidr, "/") {
		return cidr
	}
	return ""
}
