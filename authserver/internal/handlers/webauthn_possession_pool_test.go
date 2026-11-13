package handlers

// webauthn_possession_pool_test.go — the r2 defect 2 regression: the
// possession ceremonies' user/credential loads ride the CALLER'S fenced
// transaction, never a second pooled connection.
//
// The dependency this pins: begin/finish open their §2.2-fenced transaction
// FIRST (pool.Begin → users/person fences), and the ceremony's user load used
// to be issued through the POOL — a second connection acquired while the
// first is held for the whole transaction. With ONE pooled connection the
// old shape can never terminate: the handler's own transaction holds the only
// connection and its user load waits forever for a second one — the same
// self-deadlock pool saturation produces in production (N concurrent
// ceremony holders each waiting for a connection another holds). After the
// fix the load rides the transaction's connection and the begin completes.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"setjoin.com/authserver/internal/authn"
	"setjoin.com/shared/pgxutil"
)

func TestPossessionBeginCompletesOnSingleConnectionPool(t *testing.T) {
	// A dedicated ONE-connection pool: the fenced transaction and any
	// pool-issued statement inside it contend for this single connection.
	oneConn, err := pgxutil.OpenPool(context.Background(), liveDSN(t), 1, enrollmentHandlerTestKey, "")
	if err != nil {
		t.Fatalf("open one-connection pool: %v", err)
	}
	t.Cleanup(oneConn.Close)

	passkey, err := authn.NewPasskeyProvider(oneConn, "localhost", "SetJoin", "http://localhost:8080")
	if err != nil {
		t.Fatalf("build passkey provider: %v", err)
	}
	h := NewAuthHandler(AuthHandlerConfig{Pool: oneConn, JWT: newTestJWT(), Logger: discardLogger(), Passkey: passkey})
	ensureEnrollmentLocalDomain(t, oneConn)

	// C1 fixture: an enabled user with one UV-capable credential, and a REAL
	// access bearer (the begin endpoint resolves admission through the bearer
	// authenticator — no context claims). The email is unique per run (the
	// identity-admission guard rejects a re-used address).
	email := fmt.Sprintf("poss-1conn-%d@example.test", time.Now().UnixNano())
	userID := seedLocalUser(t, oneConn, email)
	seedUVPasskey(t, h, userID, "", true)
	bearer, err := h.jwt.IssueAccess(userID, email, false)
	if err != nil {
		t.Fatalf("issue access bearer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/possession/webauthn/begin",
		strings.NewReader(`{"operation":"recovery.regenerate"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	rr := httptest.NewRecorder()

	// The handler is expected to COMPLETE on the single connection: its tx
	// holds it, and the user load rides the same transaction. A hang here is
	// the defect (the pool-issued load waits for a connection the handler's
	// own transaction holds until the load returns — a cycle).
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- func() *httptest.ResponseRecorder { h.MFAPossessionWebAuthnBegin(rr, req); return rr }()
	}()

	select {
	case rr := <-done:
		if rr.Code != http.StatusOK {
			t.Fatalf("begin status = %d body %s, want 200 — the ceremony begin must complete on one pooled connection", rr.Code, rr.Body.String())
		}
		var options struct {
			PublicKey struct {
				Challenge string `json:"challenge"`
			} `json:"publicKey"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &options); err != nil || options.PublicKey.Challenge == "" {
			t.Fatalf("begin body %s carries no assertion options (%v)", rr.Body.String(), err)
		}
		// The tx committed and released the connection before the response —
		// the ceremony row is durably live.
		var n int
		if err := oneConn.QueryRow(context.Background(),
			`SELECT count(*) FROM webauthn_ceremonies WHERE user_id = $1 AND kind = 'management_assertion'`,
			userID).Scan(&n); err != nil || n != 1 {
			t.Fatalf("management_assertion rows = %d (%v), want 1", n, err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("begin never completed on the 1-connection pool — the ceremony's user load waited for a SECOND pooled connection while the fenced transaction held the only one (r2 defect 2 self-deadlock)")
	}
}
