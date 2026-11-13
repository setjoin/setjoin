package handlers

// ER5 er5-s08 occurrence test (account-enumeration.password-recovery-mfa-oracle):
// the forgot-password begin response must be timing-uniform between the decoy
// (unknown account / no-MFA account) and a REAL TOTP-enrolled account. The old
// constant delay was one-sided — only the decoy slept — so the ~100ms latency
// delta itself answered "does this account exist".

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func postForgotBegin(h *AuthHandler, email string) (*httptest.ResponseRecorder, time.Duration) {
	body, _ := json.Marshal(map[string]string{"email": email})
	req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	start := time.Now()
	h.ForgotPasswordBegin(rr, req)
	return rr, time.Since(start)
}

// TestForgotPasswordBegin_UniformLatencyDecoyVsRealAccount drives the REAL
// begin handler against a loaded DB: a real TOTP-enrolled account and an
// unknown address must both take at least the constant floor, so wall-clock
// time cannot separate them (content is already byte-identical).
func TestForgotPasswordBegin_UniformLatencyDecoyVsRealAccount(t *testing.T) {
	dsn := liveDSN(t)
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	userID := seedPushUser(t, pool, "forgot-latency@example.com")
	if _, err := pool.Exec(context.Background(),
		`UPDATE users SET totp_enabled = TRUE WHERE id = $1`, userID); err != nil {
		t.Fatal(err)
	}

	h := NewAuthHandler(AuthHandlerConfig{
		Pool:   pool,
		JWT:    newTestJWT(),
		Logger: discardLogger(),
	})

	// Warm connections so the first-request cost does not skew the sample.
	postForgotBegin(h, "warmup@example.com")

	_, realElapsed := postForgotBegin(h, "forgot-latency@example.com")
	_, decoyElapsed := postForgotBegin(h, "no-such-account@example.com")

	floor := enumConstantDelay - 15*time.Millisecond
	if realElapsed < floor {
		t.Fatalf("real TOTP account responded in %v, below the uniform floor (%v) — the latency delta is an existence oracle", realElapsed, enumConstantDelay)
	}
	if decoyElapsed < floor {
		t.Fatalf("decoy responded in %v, below the uniform floor (%v)", decoyElapsed, enumConstantDelay)
	}
}

// TestForgotPasswordBegin_DecoyBodyIdenticalToRealTOTP pins the content half of
// the uniformity contract: a real TOTP account's begin response is
// byte-identical to the decoy (method "totp", generic message, no nonce).
func TestForgotPasswordBegin_DecoyBodyIdenticalToRealTOTP(t *testing.T) {
	dsn := liveDSN(t)
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	userID := seedPushUser(t, pool, "forgot-body@example.com")
	if _, err := pool.Exec(context.Background(),
		`UPDATE users SET totp_enabled = TRUE WHERE id = $1`, userID); err != nil {
		t.Fatal(err)
	}

	h := NewAuthHandler(AuthHandlerConfig{
		Pool:   pool,
		JWT:    newTestJWT(),
		Logger: discardLogger(),
	})

	rrReal, _ := postForgotBegin(h, "forgot-body@example.com")
	rrDecoy, _ := postForgotBegin(h, "still-not-here@example.com")

	if rrReal.Code != http.StatusOK || rrDecoy.Code != http.StatusOK {
		t.Fatalf("statuses: real=%d decoy=%d, want 200/200", rrReal.Code, rrDecoy.Code)
	}
	var realBody, decoyBody map[string]string
	_ = json.Unmarshal(rrReal.Body.Bytes(), &realBody)
	_ = json.Unmarshal(rrDecoy.Body.Bytes(), &decoyBody)
	if realBody["method"] != decoyBody["method"] || realBody["message"] != decoyBody["message"] {
		t.Fatalf("real account body %v differs from decoy %v — existence oracle", realBody, decoyBody)
	}
	if _, hasNonce := realBody["nonce"]; hasNonce {
		t.Fatal("a TOTP account's begin response must not carry a nonce")
	}
}
