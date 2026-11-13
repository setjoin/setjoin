package handlers

// possession_tx_seam_arms_test.go — statement-fault injection at the
// possession gate's transaction seam (TODOS: possession surface coverage
// seams). deps.possessionTxBeginner substitutes a scripted pgx.Tx for the
// concrete pool's Begin, so the previously unreachable SELECT/Exec failure
// arms INSIDE the §2.2 transactions of mfa_possession.go and totp.go are
// driven deterministically — several without any database (the TOTP/possession
// endpoints admit from the context, so a pool-less handler composes; the
// admission-funnel endpoints and the fenced-confirm user lookup still use the
// DB-backed harness). Every test asserts the OBSERVABLE production handling:
// the status contract, commit/rollback behaviour on the scripted tx, and
// (for the DB-backed cases) surviving ceremony rows — never line execution.
//
// Classes NOT covered here (recorded honestly). Astra-review r1 moved two
// former "order-protected" entries into covered — the finish consume-miss
// (mfa_possession.go writeReauthRequired after ConsumeCeremony) is reached
// with a crypto-VALID UV assertion through the scripted tx (a fixture ECDSA
// keypair the loader returns, RPID/origin/challenge bound to the seeded
// ceremony), and webauthn.go's registration-resume live-ceremony recheck
// rides the SAME seamed fencedFactorTx; both are covered below. Still open:
//   - entropy arms (NewTOTPProvisioningSecret / rand-backed key minting):
//     crypto/rand is not a seam without a production change beyond
//     interface extraction;
//   - dead fallbacks: the ProvisioningURIForSecret error arms can never
//     fire (the helper always returns a URI, nil error);
//   - arms behind a user row that vanishes between acceptance and re-read;
//   - the finish GRANT-ISSUANCE halves (past a valid assertion, when the
//     consume succeeds) — covered on the refusal arm only; the success-path
//     grant halves remain for the software-authenticator e2e work;
//   - the begin-arm base64 re-decode (already canonicalized upstream —
//     defensive).
// Note for a follow-up unit: webauthn.go's only seam-reachable residual was
// the registration-resume recheck now covered here — its remaining arms are
// entropy/lib-internal, so its ratchet-file exclusion may be shrinkable once
// audited against those classes (thresholds file deliberately untouched in
// this unit).

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pquerna/otp/totp"

	"setjoin.com/authserver/internal/authn"
	"setjoin.com/authserver/internal/token"
)

// --- scripted tx seam ---

// armRowFn is a pgx.Row whose Scan is a closure.
type armRowFn func(dest ...any) error

func (r armRowFn) Scan(dest ...any) error { return r(dest...) }

func armErrRow() armRowFn { return armRowFn(func(...any) error { return errInjectedRows }) }

func armNoRowsRow() armRowFn {
	return armRowFn(func(...any) error { return pgx.ErrNoRows })
}

// errInjectedRows is the seam's injected statement failure (distinct name
// from the authn package's sentinel).
var errInjectedRows = errorString("injected statement failure (possession tx seam)")

type errorString string

func (e errorString) Error() string { return string(e) }

// seamGateTx is the scripted pgx.Tx installed behind deps.possessionTxBeginner.
type seamGateTx struct {
	pgx.Tx    // nil embed — any unstubbed statement panics loudly
	exec      func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	row       func(ctx context.Context, sql string, args ...any) pgx.Row
	query     func(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	commitErr error
	commits   int
	rollbacks int
}

func (t *seamGateTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return t.exec(ctx, sql, args...)
}

func (t *seamGateTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return t.row(ctx, sql, args...)
}

func (t *seamGateTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return t.query(ctx, sql, args...)
}

func (t *seamGateTx) Commit(context.Context) error {
	t.commits++
	return t.commitErr
}

func (t *seamGateTx) Rollback(context.Context) error {
	t.rollbacks++
	return nil
}

type seamBeginner struct {
	tx  *seamGateTx
	err error
}

func (b seamBeginner) Begin(context.Context) (pgx.Tx, error) { return b.tx, b.err }

// installSeam bolts the scripted tx onto the handler's deps seam.
func installSeam(h *AuthHandler, tx *seamGateTx, err error) {
	h.deps.possessionTxBeginner = seamBeginner{tx: tx, err: err}
}

// okTag is a successful single-row write.
var okTag = pgconn.NewCommandTag("UPDATE 1")

var zeroTag = pgconn.NewCommandTag("UPDATE 0")

// rowDispatcher routes QueryRow by SQL marker with per-marker queues (two
// statements in one flow share an SQL shape — e.g. the confirm user read and
// the proving-factor read — so each marker pops its scripted responses in
// order).
type rowDispatcher struct {
	queues map[string][]func(dest ...any) error
}

func newRowDispatcher() *rowDispatcher {
	return &rowDispatcher{queues: map[string][]func(dest ...any) error{}}
}

func (d *rowDispatcher) push(marker string, scans ...func(dest ...any) error) {
	d.queues[marker] = append(d.queues[marker], scans...)
}

func (d *rowDispatcher) pop(marker string) func(dest ...any) error {
	q := d.queues[marker]
	if len(q) == 0 {
		return nil
	}
	f := q[0]
	d.queues[marker] = q[1:]
	return f
}

func (d *rowDispatcher) tx(commitErr error) *seamGateTx {
	return &seamGateTx{
		exec: func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			switch {
			case strings.Contains(sql, "totp_secret_enc = pgp_sym_encrypt"):
				// The promotion write: a test drives zero-rows by pushing a
				// zeroTag selection beforehand — default success here.
				return okTag, nil
			}
			return okTag, nil
		},
		row: func(_ context.Context, sql string, _ ...any) pgx.Row {
			switch {
			case strings.Contains(sql, "identity_auth_person_fence"),
				strings.Contains(sql, "identity_auth_local_mint_fence"):
				return armRowFn(func(...any) error { return nil })
			case strings.HasPrefix(sql, "SELECT factor_generation FROM users"):
				if f := d.pop("usersFence"); f != nil {
					return armRowFn(f)
				}
				return armRowFn(func(dest ...any) error { *(dest[0].(*int64)) = 1; return nil })
			case strings.Contains(sql, "session_revocations"):
				if f := d.pop("recheck"); f != nil {
					return armRowFn(f)
				}
				return armRowFn(func(dest ...any) error { *(dest[0].(*bool)) = false; return nil })
			case strings.Contains(sql, "FROM users u WHERE u.id"):
				if f := d.pop("cohort"); f != nil {
					return armRowFn(f)
				}
				return armRowFn(func(dest ...any) error {
					*(dest[0].(*bool)) = true
					*(dest[1].(*bool)) = true
					return nil
				})
			case strings.Contains(sql, "COALESCE(totp_enabled, FALSE) FROM users"):
				if f := d.pop("totpEnabled"); f != nil {
					return armRowFn(f)
				}
				return armRowFn(func(dest ...any) error { *(dest[0].(*bool)) = false; return nil })
			case strings.Contains(sql, "DELETE FROM mfa_reauth_step_ups"):
				if f := d.pop("consume"); f != nil {
					return armRowFn(f)
				}
				return armRowFn(scanGrantRow("totp"))
			case strings.Contains(sql, "UPDATE mfa_reauth_step_ups"):
				if f := d.pop("bindUpdate"); f != nil {
					return armRowFn(f)
				}
				return armRowFn(func(dest ...any) error { *(dest[0].(*string)) = "hash"; return nil })
			case strings.Contains(sql, "SELECT EXISTS"):
				if f := d.pop("bindState"); f != nil {
					return armRowFn(f)
				}
				if f := d.pop("registerResume"); f != nil {
					return armRowFn(f)
				}
				panic("seamGateTx: unscripted EXISTS query: " + sql)
			case strings.Contains(sql, "mfa_reauth_step_ups") && strings.Contains(sql, "SELECT"):
				if f := d.pop("peek"); f != nil {
					return armRowFn(f)
				}
				return armRowFn(scanPeekRow(nil))
			case strings.Contains(sql, "INSERT INTO totp_pending_enrollments"):
				return armRowFn(func(dest ...any) error { *(dest[0].(*string)) = "enrollment-1"; return nil })
			case strings.Contains(sql, "totp_pending_enrollments"):
				if f := d.pop("pending"); f != nil {
					return armRowFn(f)
				}
				return armRowFn(scanPendingRow("MFRGGZDFMZTWQ2LKNNWG23TPM5XGK3DR"))
			case strings.Contains(sql, "mfa_status("):
				if f := d.pop("mfaStatus"); f != nil {
					return armRowFn(f)
				}
				return armRowFn(func(dest ...any) error { *(dest[0].(*string)) = "enrollment_required"; return nil })
			case strings.Contains(sql, "totp_locked_until FROM users"):
				if f := d.pop("lockUnderFence"); f != nil {
					return armRowFn(f)
				}
				return armRowFn(func(dest ...any) error { *(dest[0].(**time.Time)) = nil; return nil })
			case strings.Contains(sql, "totp_failed_attempts = totp_failed_attempts + 1"):
				if f := d.pop("record"); f != nil {
					return armRowFn(f)
				}
				return armRowFn(func(dest ...any) error { *(dest[0].(**time.Time)) = nil; return nil })
			case strings.Contains(sql, "password_hash FROM users"):
				return armRowFn(func(dest ...any) error { *(dest[0].(*string)) = "x"; return nil })
			case strings.Contains(sql, "possession_webauthn_failed_attempts"):
				if f := d.pop("waBudget"); f != nil {
					return armRowFn(f)
				}
				return armRowFn(func(dest ...any) error {
					*(dest[0].(*int)) = 0
					*(dest[1].(**time.Time)) = nil
					return nil
				})
			case strings.Contains(sql, "webauthn_user_handle FROM users"):
				if f := d.pop("waUser"); f != nil {
					return armRowFn(f)
				}
				panic("seamGateTx: unscripted webauthn user load: " + sql)
			case strings.Contains(sql, "passkey_credentials"):
				if f := d.pop("waCredentials"); f != nil {
					return armRowFn(f)
				}
				panic("seamGateTx: unscripted credential query: " + sql)
			case strings.Contains(sql, "DELETE FROM webauthn_ceremonies"):
				if f := d.pop("consumeCeremony"); f != nil {
					return armRowFn(f)
				}
				return armRowFn(func(dest ...any) error {
					*(dest[0].(*string)) = "challenge-hash"
					*(dest[1].(*int64)) = 42
					*(dest[2].(*string)) = "management_assertion"
					*(dest[3].(*string)) = "recovery.regenerate"
					*(dest[4].(**string)) = nil
					*(dest[5].(*string)) = "jti"
					*(dest[6].(*string)) = "session"
					*(dest[7].(**string)) = nil
					*(dest[8].(*time.Time)) = time.Now()
					*(dest[9].(*time.Time)) = time.Now().Add(5 * time.Minute)
					return nil
				})
			}
			panic("seamGateTx: unscripted query: " + sql)
		},
		commitErr: commitErr,
	}
}

// scanGrantRow fills a ConsumeGrant/PeekGrant scan (11 dests) with a grant
// proven by the given method; target nil.
func scanGrantRow(method string) func(dest ...any) error {
	return func(dest ...any) error {
		*(dest[0].(*string)) = "hash"
		*(dest[1].(*int64)) = 42
		*(dest[2].(*string)) = "jti"
		*(dest[3].(*string)) = "totp.enroll"
		*(dest[4].(**string)) = nil
		*(dest[5].(*string)) = method
		*(dest[6].(*[]byte)) = nil
		*(dest[7].(*int64)) = 1
		*(dest[8].(*string)) = "session"
		*(dest[9].(**string)) = nil
		*(dest[10].(*time.Time)) = time.Now().Add(time.Hour)
		return nil
	}
}

// scanPeekRow fills a PeekGrant scan whose TargetRef is settable (the resume
// and bind arms branch on it).
func scanPeekRow(target *string) func(dest ...any) error {
	return func(dest ...any) error {
		*(dest[0].(*string)) = "hash"
		*(dest[1].(*int64)) = 42
		*(dest[2].(*string)) = "jti"
		*(dest[3].(*string)) = "totp.enroll"
		*(dest[4].(**string)) = target
		*(dest[5].(*string)) = "password"
		*(dest[6].(*[]byte)) = nil
		*(dest[7].(*int64)) = 1
		*(dest[8].(*string)) = "session"
		*(dest[9].(**string)) = nil
		*(dest[10].(*time.Time)) = time.Now().Add(time.Hour)
		return nil
	}
}

// scanPendingRow fills ReadPendingTOTPEnrollment's scan (6 dests) with the
// given staged secret.
func scanPendingRow(secret string) func(dest ...any) error {
	return func(dest ...any) error {
		*(dest[0].(*string)) = "enrollment-1"
		*(dest[1].(*int64)) = 42
		*(dest[2].(*string)) = "jti"
		*(dest[3].(*string)) = "totp_setup"
		*(dest[4].(*time.Time)) = time.Now().Add(10 * time.Minute)
		*(dest[5].(*string)) = secret
		return nil
	}
}

// seamCode returns the code valid for the default staged secret right now.
func seamCode(t *testing.T) (secret, code string) {
	t.Helper()
	secret = "MFRGGZDFMZTWQ2LKNNWG23TPM5XGK3DR"
	got, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	return secret, got
}

// --- mfa_possession.go: POST /auth/mfa/possession/totp arms ---

func TestSeamPossessionTOTPTxFailures(t *testing.T) {
	h := NewAuthHandler(AuthHandlerConfig{JWT: newTestJWT(), Logger: discardLogger()})
	_, claims := removalClaimsForSeam(h, 42)
	ctx := context.Background()
	post := func(body map[string]string) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/auth/mfa/possession/totp", strings.NewReader(string(b)))
		req = req.WithContext(ContextWithUser(ctx, claims))
		rr := httptest.NewRecorder()
		h.MFAPossessionTOTP(rr, req)
		return rr
	}

	t.Run("revocation recheck failure → 500, rollback, no grant", func(t *testing.T) {
		d := newRowDispatcher()
		d.push("recheck", func(...any) error { return errInjectedRows })
		tx := d.tx(nil)
		installSeam(h, tx, nil)
		if rr := post(map[string]string{"operation": "recovery.regenerate", "code": "0000000"}); rr.Code != http.StatusInternalServerError {
			t.Fatalf("recheck fault status = %d body %s, want 500", rr.Code, rr.Body.String())
		}
		if tx.commits != 0 || tx.rollbacks < 1 {
			t.Fatalf("recheck fault committed %d / rolled back %d, want rollback only", tx.commits, tx.rollbacks)
		}
	})
	t.Run("cohort classification failure → 500", func(t *testing.T) {
		d := newRowDispatcher()
		d.push("cohort", func(...any) error { return errInjectedRows })
		tx := d.tx(nil)
		installSeam(h, tx, nil)
		if rr := post(map[string]string{"operation": "recovery.regenerate", "code": "0000000"}); rr.Code != http.StatusInternalServerError {
			t.Fatalf("cohort fault status = %d, want 500", rr.Code)
		}
		if tx.commits != 0 {
			t.Fatalf("cohort fault committed %d times, want 0", tx.commits)
		}
	})
	t.Run("begin failure → 500", func(t *testing.T) {
		installSeam(h, nil, errInjectedRows)
		if rr := post(map[string]string{"operation": "recovery.regenerate", "code": "0000000"}); rr.Code != http.StatusInternalServerError {
			t.Fatalf("begin fault status = %d, want 500", rr.Code)
		}
	})
}

// removalClaimsForSeam returns context-claims for a fixture identity.
func removalClaimsForSeam(h *AuthHandler, userID int64) (*token.JWTProvider, *token.Claims) {
	tokH := h.jwt
	return tokH, removalClaims(userID, "seam-jti")
}

// --- mfa_possession.go: webauthn begin/finish arms (DB-backed admission) ---

func TestSeamPossessionBeginTxFailures(t *testing.T) {
	h := newPossessionHarness(t)
	userID, claims := newPossessionUser(t, h, "seambegin", true)
	bearer := armsIssueBearer(t, h, userID, claims.Email)
	d := newRowDispatcher()

	t.Run("revocation recheck failure → 500", func(t *testing.T) {
		d.push("recheck", func(...any) error { return errInjectedRows })
		tx := d.tx(nil)
		installSeam(h, tx, nil)
		rr := postPossession(h, "/auth/mfa/possession/webauthn/begin",
			map[string]any{"operation": "recovery.regenerate"}, map[string]string{"Authorization": "Bearer " + bearer}, nil)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("begin recheck fault status = %d, want 500", rr.Code)
		}
		if tx.rollbacks < 1 {
			t.Fatal("begin recheck fault did not roll back")
		}
	})
	t.Run("cohort classification failure → 500", func(t *testing.T) {
		d2 := newRowDispatcher()
		d2.push("cohort", func(...any) error { return errInjectedRows })
		tx := d2.tx(nil)
		installSeam(h, tx, nil)
		rr := postPossession(h, "/auth/mfa/possession/webauthn/begin",
			map[string]any{"operation": "recovery.regenerate"}, map[string]string{"Authorization": "Bearer " + bearer}, nil)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("begin cohort fault status = %d, want 500", rr.Code)
		}
	})
}

func TestSeamPossessionFinishTxFailures(t *testing.T) {
	h := newPossessionHarness(t)
	userID, claims := newPossessionUser(t, h, "seamfinish", true)
	bearer := armsIssueBearer(t, h, userID, claims.Email)
	bearerClaims, err := h.jwt.Validate(bearer)
	if err != nil {
		t.Fatalf("validate bearer: %v", err)
	}
	seedCeremony := func(t *testing.T, chash, target string) {
		t.Helper()
		_, tErr := h.pool.Exec(context.Background(),
			`INSERT INTO webauthn_ceremonies
			   (challenge_hash, user_id, kind, operation, target_ref, session_jti, token_scope, refresh_family_id, expires_at)
			 VALUES ($1, $2, 'management_assertion', 'recovery.regenerate', NULLIF($3, '')::text, $4, 'session', NULL, now() + interval '5 minutes')`,
			chash, userID, target, bearerClaims.JTI)
		if tErr != nil {
			t.Fatalf("seed ceremony: %v", tErr)
		}
	}

	t.Run("tx begin failure → 500", func(t *testing.T) {
		seedCeremony(t, "seam-finish-begin-chash", "")
		installSeam(h, nil, errInjectedRows)
		rr := postPossession(h, "/auth/mfa/possession/webauthn/finish",
			map[string]any{"operation": "recovery.regenerate"}, map[string]string{"Authorization": "Bearer " + bearer}, nil)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("finish begin fault status = %d body %s, want 500", rr.Code, rr.Body.String())
		}
	})
	t.Run("users fence failure → 500", func(t *testing.T) {
		seedCeremony(t, "seam-finish-fence-chash", "")
		d := newRowDispatcher()
		d.push("usersFence", func(...any) error { return errInjectedRows })
		tx := d.tx(nil)
		installSeam(h, tx, nil)
		rr := postPossession(h, "/auth/mfa/possession/webauthn/finish",
			map[string]any{"operation": "recovery.regenerate"}, map[string]string{"Authorization": "Bearer " + bearer}, nil)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("finish users-fence fault status = %d, want 500", rr.Code)
		}
		if tx.commits != 0 {
			t.Fatalf("finish fence fault committed %d times, want 0", tx.commits)
		}
	})
	t.Run("revocation recheck failure → 500", func(t *testing.T) {
		seedCeremony(t, "seam-finish-recheck-chash", "")
		d := newRowDispatcher()
		d.push("recheck", func(...any) error { return errInjectedRows })
		tx := d.tx(nil)
		installSeam(h, tx, nil)
		rr := postPossession(h, "/auth/mfa/possession/webauthn/finish",
			map[string]any{"operation": "recovery.regenerate"}, map[string]string{"Authorization": "Bearer " + bearer}, nil)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("finish recheck fault status = %d, want 500", rr.Code)
		}
	})
	t.Run("target_ref on an unbound ceremony → 400, ceremony survives", func(t *testing.T) {
		seedCeremony(t, "seam-finish-target-chash", "")
		installSeam(h, nil, errInjectedRows) // must never be reached
		rr := postPossession(h, "/auth/mfa/possession/webauthn/finish",
			map[string]any{"operation": "recovery.regenerate", "target_ref": "AAAA"}, map[string]string{"Authorization": "Bearer " + bearer}, nil)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("finish target mismatch status = %d body %s, want 400", rr.Code, rr.Body.String())
		}
		var live bool
		if err := h.pool.QueryRow(context.Background(),
			`SELECT EXISTS (SELECT 1 FROM webauthn_ceremonies WHERE challenge_hash = 'seam-finish-target-chash')`).Scan(&live); err != nil || !live {
			t.Fatalf("ceremony consumed by the target refusal (%v)", err)
		}
	})
}

// --- totp.go: the gated TOTP arms ---

func TestSeamFencedFactorTxRecheckFailure(t *testing.T) {
	h := NewAuthHandler(AuthHandlerConfig{JWT: newTestJWT(), Logger: discardLogger()})
	_, claims := removalClaimsForSeam(h, 42)
	d := newRowDispatcher()
	d.push("recheck", func(...any) error { return errInjectedRows })
	tx := d.tx(nil)
	installSeam(h, tx, nil)

	req := httptest.NewRequest(http.MethodGet, "/auth/totp/setup", nil)
	req.Header.Set("X-MFA-Reauth", "some-token")
	req = req.WithContext(ContextWithUser(context.Background(), claims))
	rr := httptest.NewRecorder()
	h.TOTPSetup(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("setup recheck fault status = %d, want 500", rr.Code)
	}
	if tx.rollbacks < 1 {
		t.Fatal("setup recheck fault did not roll back")
	}
}

func TestSeamTOTPSetupUserReadFault(t *testing.T) {
	h := NewAuthHandler(AuthHandlerConfig{JWT: newTestJWT(), Logger: discardLogger()})
	_, claims := removalClaimsForSeam(h, 42)
	d := newRowDispatcher()
	d.push("totpEnabled", func(...any) error { return errInjectedRows })
	tx := d.tx(nil)
	installSeam(h, tx, nil)

	req := httptest.NewRequest(http.MethodGet, "/auth/totp/setup", nil)
	req.Header.Set("X-MFA-Reauth", "some-token")
	req = req.WithContext(ContextWithUser(context.Background(), claims))
	rr := httptest.NewRecorder()
	h.TOTPSetup(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("setup user-read fault status = %d, want 500", rr.Code)
	}
}

func TestSeamTOTPSetupResumeCommitFault(t *testing.T) {
	h := NewAuthHandler(AuthHandlerConfig{JWT: newTestJWT(), Logger: discardLogger()})
	_, claims := removalClaimsForSeam(h, 42)
	target := "enrollment-1"
	d := newRowDispatcher()
	d.push("peek", func(dest ...any) error { return scanPeekRow(&target)(dest...) })
	tx := d.tx(errInjectedRows) // the resume COMMIT fails
	installSeam(h, tx, nil)

	req := httptest.NewRequest(http.MethodGet, "/auth/totp/setup", nil)
	req.Header.Set("X-MFA-Reauth", "some-token")
	req = req.WithContext(ContextWithUser(context.Background(), claims))
	rr := httptest.NewRecorder()
	h.TOTPSetup(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("resume commit fault status = %d body %s, want 500", rr.Code, rr.Body.String())
	}
	if tx.commits != 1 {
		t.Fatalf("resume commit attempts = %d, want 1", tx.commits)
	}
}

func TestSeamTOTPSetupBindRaceConflict(t *testing.T) {
	h := NewAuthHandler(AuthHandlerConfig{JWT: newTestJWT(), Logger: discardLogger()})
	_, claims := removalClaimsForSeam(h, 42)
	d := newRowDispatcher()
	d.push("bindUpdate", func(...any) error { return pgx.ErrNoRows })
	d.push("bindState", func(dest ...any) error {
		*(dest[0].(*bool)) = true // live
		*(dest[1].(*bool)) = true // already bound
		return nil
	})
	tx := d.tx(nil)
	installSeam(h, tx, nil)

	req := httptest.NewRequest(http.MethodGet, "/auth/totp/setup", nil)
	req.Header.Set("X-MFA-Reauth", "some-token")
	req = req.WithContext(ContextWithUser(context.Background(), claims))
	rr := httptest.NewRecorder()
	h.TOTPSetup(rr, req)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "proof_already_bound") {
		t.Fatalf("bind-race status = %d body %s, want 409 proof_already_bound", rr.Code, rr.Body.String())
	}
}

func TestSeamTOTPConfirmFaultArms(t *testing.T) {
	h := NewAuthHandler(AuthHandlerConfig{JWT: newTestJWT(), Logger: discardLogger()})
	_, claims := removalClaimsForSeam(h, 42)
	_, code := seamCode(t) // the staged secret arrives through the scripted pending read
	post := func(body map[string]string) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/auth/totp/confirm", strings.NewReader(string(b)))
		req.Header.Set("X-MFA-Reauth", "some-token")
		req = req.WithContext(ContextWithUser(context.Background(), claims))
		rr := httptest.NewRecorder()
		h.TOTPConfirm(rr, req)
		return rr
	}

	t.Run("user read failure → 500", func(t *testing.T) {
		d := newRowDispatcher()
		d.push("totpEnabled", func(...any) error { return errInjectedRows })
		installSeam(h, d.tx(nil), nil)
		if rr := post(map[string]string{"code": code, "enrollment_id": "enrollment-1"}); rr.Code != http.StatusInternalServerError {
			t.Fatalf("confirm user-read fault status = %d, want 500", rr.Code)
		}
	})
	t.Run("consume statement failure → 500 (not the reauth shape)", func(t *testing.T) {
		d := newRowDispatcher()
		d.push("consume", func(...any) error { return errInjectedRows })
		installSeam(h, d.tx(nil), nil)
		rr := post(map[string]string{"code": code, "enrollment_id": "enrollment-1"})
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("consume fault status = %d body %s, want 500", rr.Code, rr.Body.String())
		}
		if strings.Contains(rr.Body.String(), "reauth") {
			t.Fatalf("consume fault answered the reauth shape: %s", rr.Body.String())
		}
	})
	t.Run("proving factor read failure → 500", func(t *testing.T) {
		d := newRowDispatcher()
		d.push("totpEnabled",
			func(dest ...any) error { *(dest[0].(*bool)) = false; return nil }, // confirm's own read
			func(...any) error { return errInjectedRows })                      // the proving-factor read
		installSeam(h, d.tx(nil), nil)
		if rr := post(map[string]string{"code": code, "enrollment_id": "enrollment-1"}); rr.Code != http.StatusInternalServerError {
			t.Fatalf("proving-factor fault status = %d, want 500", rr.Code)
		}
	})
	t.Run("promotion matched zero rows → 409 fresh proof", func(t *testing.T) {
		d := newRowDispatcher()
		d.push("totpEnabled",
			func(dest ...any) error { *(dest[0].(*bool)) = false; return nil }, // confirm's own read
			func(dest ...any) error { *(dest[0].(*bool)) = true; return nil })  // the proving factor is live
		tx := d.tx(nil)
		tx.exec = func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			if strings.Contains(sql, "totp_secret_enc = pgp_sym_encrypt") {
				return zeroTag, nil
			}
			return okTag, nil
		}
		installSeam(h, tx, nil)
		rr := post(map[string]string{"code": code, "enrollment_id": "enrollment-1"})
		if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "totp state changed") {
			t.Fatalf("zero-row promotion status = %d body %s, want 409 state changed", rr.Code, rr.Body.String())
		}
	})
}

func TestSeamTOTPEnrollmentSetupFenceFailures(t *testing.T) {
	h := NewAuthHandler(AuthHandlerConfig{JWT: newTestJWT(), Logger: discardLogger()})
	raw, err := h.jwt.IssueMFAPending(42, "seam-enroll@example.test")
	if err != nil {
		t.Fatalf("issue mfa pending: %v", err)
	}
	post := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/auth/totp/enroll/setup",
			strings.NewReader(`{"mfa_token":"`+raw+`"}`))
		rr := httptest.NewRecorder()
		h.TOTPEnrollmentSetup(rr, req)
		return rr
	}
	for name, marker := range map[string]string{
		"person fence": "personFence",
		"users fence":  "usersFence",
		"recheck":      "recheck",
	} {
		t.Run(name+" failure → 500", func(t *testing.T) {
			d := newRowDispatcher()
			switch marker {
			case "personFence":
				// The fence Exec fails: script via a failing tx exec.
				tx := d.tx(nil)
				tx.exec = func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
					if strings.Contains(sql, "identity_auth_person_fence") {
						return pgconn.CommandTag{}, errInjectedRows
					}
					return okTag, nil
				}
				installSeam(h, tx, nil)
			case "usersFence":
				d.push("usersFence", func(...any) error { return errInjectedRows })
				installSeam(h, d.tx(nil), nil)
			case "recheck":
				d.push("recheck", func(...any) error { return errInjectedRows })
				installSeam(h, d.tx(nil), nil)
			}
			if rr := post(); rr.Code != http.StatusInternalServerError {
				t.Fatalf("%s fault status = %d, want 500", name, rr.Code)
			}
		})
	}
}

func TestSeamBootstrapPromotionArms(t *testing.T) {
	h := NewAuthHandler(AuthHandlerConfig{JWT: newTestJWT(), Logger: discardLogger()})
	userID := int64(42)
	raw, err := h.jwt.IssueMFAPending(userID, "seam-promo@example.test")
	if err != nil {
		t.Fatalf("issue mfa pending: %v", err)
	}
	secret, code := seamCode(t)
	enrollmentID := "enrollment-1"
	post := func(codeValue string) *httptest.ResponseRecorder {
		b, _ := json.Marshal(map[string]string{"mfa_token": raw, "code": codeValue, "enrollment_id": enrollmentID})
		req := httptest.NewRequest(http.MethodPost, "/auth/totp/enroll/confirm", strings.NewReader(string(b)))
		rr := httptest.NewRecorder()
		h.TOTPEnrollmentConfirm(rr, req)
		return rr
	}
	promoBase := func(d *rowDispatcher) {
		d.push("peek", func(dest ...any) error { return scanPeekRow(&enrollmentID)(dest...) })
		d.push("pending", func(dest ...any) error { return scanPendingRow(secret)(dest...) })
	}
	failsUsersFence := func(t *testing.T) *rowDispatcher {
		t.Helper()
		d := newRowDispatcher()
		d.push("usersFence", func(...any) error { return errInjectedRows })
		return d
	}

	t.Run("users fence failure → 500", func(t *testing.T) {
		installSeam(h, failsUsersFence(t).tx(nil), nil)
		if rr := post(code); rr.Code != http.StatusInternalServerError {
			t.Fatalf("promotion users-fence fault status = %d, want 500", rr.Code)
		}
	})
	t.Run("revocation recheck failure → 500", func(t *testing.T) {
		d := newRowDispatcher()
		d.push("recheck", func(...any) error { return errInjectedRows })
		installSeam(h, d.tx(nil), nil)
		if rr := post(code); rr.Code != http.StatusInternalServerError {
			t.Fatalf("promotion recheck fault status = %d, want 500", rr.Code)
		}
	})
	t.Run("peek statement failure → 500", func(t *testing.T) {
		d := newRowDispatcher()
		d.push("peek", func(...any) error { return errInjectedRows })
		installSeam(h, d.tx(nil), nil)
		if rr := post(code); rr.Code != http.StatusInternalServerError {
			t.Fatalf("promotion peek fault status = %d, want 500", rr.Code)
		}
	})
	t.Run("locked budget refuses without evaluating → 429", func(t *testing.T) {
		d := newRowDispatcher()
		promoBase(d)
		future := time.Now().Add(10 * time.Minute)
		d.push("lockUnderFence", func(dest ...any) error { *(dest[0].(**time.Time)) = &future; return nil })
		tx := d.tx(nil)
		installSeam(h, tx, nil)
		if rr := post(code); rr.Code != http.StatusTooManyRequests {
			t.Fatalf("locked promotion status = %d body %s, want 429", rr.Code, rr.Body.String())
		}
		// Production pins the refusal bookkeeping (totp.go:755, mirrored at
		// 836 on the fenced path): a non-accepted outcome is COMMITTED before
		// the 429 is written; the deferred Rollback then observes the closed
		// tx. So the locked fixture ends commits=1, rollbacks=1 — pin exactly
		// that committed-refusal shape.
		if tx.commits != 1 || tx.rollbacks < 1 {
			t.Fatalf("locked promotion tx state: commits=%d rollbacks=%d, want 1 commit + the deferred rollback", tx.commits, tx.rollbacks)
		}
	})
	t.Run("invalid code record refusal → 401", func(t *testing.T) {
		d := newRowDispatcher()
		promoBase(d)
		installSeam(h, d.tx(nil), nil)
		if rr := post("0000000"); rr.Code != http.StatusUnauthorized {
			t.Fatalf("invalid-code promotion status = %d body %s, want 401", rr.Code, rr.Body.String())
		}
	})
	t.Run("proving factor read failure → 500", func(t *testing.T) {
		d := newRowDispatcher()
		promoBase(d)
		d.push("consume", func(dest ...any) error { return scanGrantRow("totp")(dest...) })
		d.push("totpEnabled", func(...any) error { return errInjectedRows })
		installSeam(h, d.tx(nil), nil)
		if rr := post(code); rr.Code != http.StatusInternalServerError {
			t.Fatalf("promotion proving-factor fault status = %d, want 500", rr.Code)
		}
	})
	t.Run("promotion matched zero rows → 409", func(t *testing.T) {
		d := newRowDispatcher()
		promoBase(d)
		d.push("consume", func(dest ...any) error { return scanGrantRow("password")(dest...) })
		tx := d.tx(nil)
		tx.exec = func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
			if strings.Contains(sql, "totp_secret_enc = pgp_sym_encrypt") {
				return zeroTag, nil
			}
			return okTag, nil
		}
		installSeam(h, tx, nil)
		if rr := post(code); rr.Code != http.StatusConflict {
			t.Fatalf("zero-row promotion status = %d body %s, want 409", rr.Code, rr.Body.String())
		}
	})
}

// --- totp.go: the fenced-confirm commit arms (DB-backed user lookup) ---

func TestSeamFencedConfirmCommitArms(t *testing.T) {
	h := newPossessionHarness(t)
	userID := seedLocalUser(t, h.pool, "seam-fenced-confirm@example.test")
	credFence := credentialFenceForPasswordHash("x")
	provider := h.jwt
	raw, err := provider.IssueMFAPendingWithFences(userID, "seam-fenced-confirm@example.test", nil, credFence, token.AMRPassword)
	if err != nil {
		t.Fatalf("issue fenced mfa pending: %v", err)
	}
	secret, code := seamCode(t)
	post := func(codeValue string, commitErr error) *httptest.ResponseRecorder {
		return postFenced(h, raw, secret, codeValue, commitErr, true)
	}
	postUnlocked := func(codeValue string) *httptest.ResponseRecorder {
		return postFenced(h, raw, secret, codeValue, nil, false)
	}

	t.Run("locked outcome commit → 429", func(t *testing.T) {
		if rr := post(code, nil); rr.Code != http.StatusTooManyRequests {
			t.Fatalf("fenced locked status = %d body %s, want 429", rr.Code, rr.Body.String())
		}
	})
	t.Run("commit failure after non-accepted outcome → 503", func(t *testing.T) {
		if rr := post(code, errInjectedRows); rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("fenced commit-fault status = %d body %s, want 503", rr.Code, rr.Body.String())
		}
	})
	t.Run("invalid code outcome → 401", func(t *testing.T) {
		if rr := postUnlocked("0000000"); rr.Code != http.StatusUnauthorized {
			t.Fatalf("fenced invalid status = %d body %s, want 401", rr.Code, rr.Body.String())
		}
	})
}

// postFenced drives the signed-fence confirm against the scripted tx; locked
// seeds the under-fence lock read with a future timestamp when requested.
func postFenced(h *AuthHandler, raw, secret, codeValue string, commitErr error, locked bool) *httptest.ResponseRecorder {
	d := newRowDispatcher()
	enrollment := "enrollment-1"
	d.push("peek", func(dest ...any) error { return scanPeekRow(&enrollment)(dest...) })
	d.push("pending", func(dest ...any) error { return scanPendingRow(secret)(dest...) })
	if locked {
		future := time.Now().Add(10 * time.Minute)
		d.push("lockUnderFence", func(dest ...any) error { *(dest[0].(**time.Time)) = &future; return nil })
	}
	installSeam(h, d.tx(commitErr), nil)
	b, _ := json.Marshal(map[string]string{"mfa_token": raw, "code": codeValue, "enrollment_id": "enrollment-1"})
	req := httptest.NewRequest(http.MethodPost, "/auth/totp/enroll/confirm", strings.NewReader(string(b)))
	rr := httptest.NewRecorder()
	h.TOTPEnrollmentConfirm(rr, req)
	return rr
}

// --- pure wire refusals on the bootstrap endpoints ---

func TestSeamBootstrapWireRefusals(t *testing.T) {
	h := NewAuthHandler(AuthHandlerConfig{JWT: newTestJWT(), Logger: discardLogger()})

	t.Run("enrollment setup malformed body → 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/totp/enroll/setup", strings.NewReader("{not json"))
		rr := httptest.NewRecorder()
		h.TOTPEnrollmentSetup(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("malformed setup status = %d, want 400", rr.Code)
		}
	})
	t.Run("enrollment setup invalid token → 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/totp/enroll/setup", strings.NewReader(`{"mfa_token":"garbage"}`))
		rr := httptest.NewRecorder()
		h.TOTPEnrollmentSetup(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("invalid-token setup status = %d, want 401", rr.Code)
		}
	})
	t.Run("enrollment confirm malformed body → 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/totp/enroll/confirm", strings.NewReader("{not json"))
		rr := httptest.NewRecorder()
		h.TOTPEnrollmentConfirm(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("malformed confirm status = %d, want 400", rr.Code)
		}
	})
	t.Run("enrollment confirm invalid token → 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/totp/enroll/confirm",
			strings.NewReader(`{"mfa_token":"garbage","code":"0000000","enrollment_id":"x"}`))
		rr := httptest.NewRecorder()
		h.TOTPEnrollmentConfirm(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("invalid-token confirm status = %d, want 401", rr.Code)
		}
	})
	t.Run("totp verify invalid token → 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/totp/verify",
			strings.NewReader(`{"mfa_token":"garbage","code":"0000000"}`))
		rr := httptest.NewRecorder()
		h.TOTPVerify(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("invalid-token verify status = %d, want 401", rr.Code)
		}
	})
}

// --- residual cheap arms found by the after-measurement ---

func TestSeamTOTPSetupImpersonatedRefusal(t *testing.T) {
	// The §1.7 last row: an impersonated bearer is refused before any
	// transaction is opened.
	h := NewAuthHandler(AuthHandlerConfig{JWT: newTestJWT(), Logger: discardLogger()})
	_, claims := removalClaimsForSeam(h, 42)
	installSeam(h, nil, errInjectedRows) // must never be reached
	req := httptest.NewRequest(http.MethodGet, "/auth/totp/setup", nil)
	req.Header.Set("X-MFA-Reauth", "some-token")
	req = req.WithContext(ContextWithUser(context.Background(), armsImpersonated(claims)))
	rr := httptest.NewRecorder()
	h.TOTPSetup(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("impersonated setup status = %d, want 403", rr.Code)
	}
}

func TestSeamTOTPEnrollmentSetupResumeCommitFault(t *testing.T) {
	h := NewAuthHandler(AuthHandlerConfig{JWT: newTestJWT(), Logger: discardLogger()})
	raw, err := h.jwt.IssueMFAPending(42, "seam-enroll-resume@example.test")
	if err != nil {
		t.Fatalf("issue mfa pending: %v", err)
	}
	enrollment := "enrollment-1"
	d := newRowDispatcher()
	d.push("peek", func(dest ...any) error { return scanPeekRow(&enrollment)(dest...) })
	tx := d.tx(errInjectedRows) // the resume COMMIT fails
	installSeam(h, tx, nil)

	req := httptest.NewRequest(http.MethodPost, "/auth/totp/enroll/setup",
		strings.NewReader(`{"mfa_token":"`+raw+`"}`))
	rr := httptest.NewRecorder()
	h.TOTPEnrollmentSetup(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("enrollment resume commit fault status = %d body %s, want 500", rr.Code, rr.Body.String())
	}
	if tx.commits != 1 {
		t.Fatalf("enrollment resume commit attempts = %d, want 1", tx.commits)
	}
}

func TestSeamTOTPEnrollmentSetupBindRaceConflict(t *testing.T) {
	h := NewAuthHandler(AuthHandlerConfig{JWT: newTestJWT(), Logger: discardLogger()})
	raw, err := h.jwt.IssueMFAPending(42, "seam-enroll-race@example.test")
	if err != nil {
		t.Fatalf("issue mfa pending: %v", err)
	}
	d := newRowDispatcher()
	d.push("bindUpdate", func(...any) error { return pgx.ErrNoRows })
	d.push("bindState", func(dest ...any) error {
		*(dest[0].(*bool)) = true // live
		*(dest[1].(*bool)) = true // already bound
		return nil
	})
	installSeam(h, d.tx(nil), nil)

	req := httptest.NewRequest(http.MethodPost, "/auth/totp/enroll/setup",
		strings.NewReader(`{"mfa_token":"`+raw+`"}`))
	rr := httptest.NewRecorder()
	h.TOTPEnrollmentSetup(rr, req)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "proof_already_bound") {
		t.Fatalf("enrollment bind-race status = %d body %s, want 409 proof_already_bound", rr.Code, rr.Body.String())
	}
}

func TestSeamBootstrapPromotionAdditionalArms(t *testing.T) {
	h := NewAuthHandler(AuthHandlerConfig{JWT: newTestJWT(), Logger: discardLogger()})
	raw, err := h.jwt.IssueMFAPending(42, "seam-promo2@example.test")
	if err != nil {
		t.Fatalf("issue mfa pending: %v", err)
	}
	secret, code := seamCode(t)
	enrollmentID := "enrollment-1"
	post := func(codeValue string) *httptest.ResponseRecorder {
		b, _ := json.Marshal(map[string]string{"mfa_token": raw, "code": codeValue, "enrollment_id": enrollmentID})
		req := httptest.NewRequest(http.MethodPost, "/auth/totp/enroll/confirm", strings.NewReader(string(b)))
		rr := httptest.NewRecorder()
		h.TOTPEnrollmentConfirm(rr, req)
		return rr
	}

	t.Run("mfa_status read failure → 500", func(t *testing.T) {
		d := newRowDispatcher()
		d.push("mfaStatus", func(...any) error { return errInjectedRows })
		installSeam(h, d.tx(nil), nil)
		if rr := post(code); rr.Code != http.StatusInternalServerError {
			t.Fatalf("mfa_status fault status = %d, want 500", rr.Code)
		}
	})
	t.Run("record failure zero rows → locked 429", func(t *testing.T) {
		d := newRowDispatcher()
		d.push("peek", func(dest ...any) error { return scanPeekRow(&enrollmentID)(dest...) })
		d.push("pending", func(dest ...any) error { return scanPendingRow(secret)(dest...) })
		d.push("record", func(...any) error { return pgx.ErrNoRows })
		installSeam(h, d.tx(nil), nil)
		if rr := post("0000000"); rr.Code != http.StatusTooManyRequests {
			t.Fatalf("record zero-rows status = %d body %s, want 429", rr.Code, rr.Body.String())
		}
	})
}

func TestSeamFencedConfirmBeginFailure(t *testing.T) {
	// The signed-fence confirm opens its transaction AFTER the user lookup:
	// a failed Begin answers the 503 mint-fence-unavailable arm.
	h := newPossessionHarness(t)
	userID := seedLocalUser(t, h.pool, "seam-fenced-begin@example.test")
	credFence := credentialFenceForPasswordHash("x")
	raw, err := h.jwt.IssueMFAPendingWithFences(userID, "seam-fenced-begin@example.test", nil, credFence, token.AMRPassword)
	if err != nil {
		t.Fatalf("issue fenced mfa pending: %v", err)
	}
	installSeam(h, nil, errInjectedRows)
	b, _ := json.Marshal(map[string]string{"mfa_token": raw, "code": "0000000", "enrollment_id": "enrollment-1"})
	req := httptest.NewRequest(http.MethodPost, "/auth/totp/enroll/confirm", strings.NewReader(string(b)))
	rr := httptest.NewRecorder()
	h.TOTPEnrollmentConfirm(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("fenced begin fault status = %d body %s, want 503", rr.Code, rr.Body.String())
	}
}

// --- final residual arms (mustUser admission, verify decode, pending read) ---

func TestSeamTOTPSetupUnauthenticatedRefusal(t *testing.T) {
	// No context claims: mustUser writes the 401 and the setup returns
	// before any transaction.
	h := NewAuthHandler(AuthHandlerConfig{JWT: newTestJWT(), Logger: discardLogger()})
	installSeam(h, nil, errInjectedRows) // must never be reached
	req := httptest.NewRequest(http.MethodGet, "/auth/totp/setup", nil)
	rr := httptest.NewRecorder()
	h.TOTPSetup(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated setup status = %d, want 401", rr.Code)
	}
}

func TestSeamTOTPVerifyMalformedBodyRefusal(t *testing.T) {
	h := NewAuthHandler(AuthHandlerConfig{JWT: newTestJWT(), Logger: discardLogger()})
	req := httptest.NewRequest(http.MethodPost, "/auth/totp/verify", strings.NewReader("{not json"))
	rr := httptest.NewRecorder()
	h.TOTPVerify(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("malformed verify status = %d, want 400", rr.Code)
	}
}

func TestSeamBootstrapPromotionPendingReadFault(t *testing.T) {
	// The staged-row read fails with a plain statement error: bookkeeping,
	// never a grant refusal.
	h := NewAuthHandler(AuthHandlerConfig{JWT: newTestJWT(), Logger: discardLogger()})
	raw, err := h.jwt.IssueMFAPending(42, "seam-promo3@example.test")
	if err != nil {
		t.Fatalf("issue mfa pending: %v", err)
	}
	secret, code := seamCode(t)
	enrollmentID := "enrollment-1"
	d := newRowDispatcher()
	d.push("peek", func(dest ...any) error { return scanPeekRow(&enrollmentID)(dest...) })
	d.push("pending", func(...any) error { return errInjectedRows })
	installSeam(h, d.tx(nil), nil)

	b, _ := json.Marshal(map[string]string{"mfa_token": raw, "code": code, "enrollment_id": enrollmentID})
	req := httptest.NewRequest(http.MethodPost, "/auth/totp/enroll/confirm", strings.NewReader(string(b)))
	rr := httptest.NewRecorder()
	h.TOTPEnrollmentConfirm(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("pending-read fault status = %d, want 500", rr.Code)
	}
	_ = secret
}

// --- FIX-2 residual arms: the seam reaches past the assertion boundary ---

// seamAssertionChallenge is the challenge whose SHA-256 the fixture ceremony
// stores; the crafted assertion presents exactly this string (the protocol
// parser compares the raw JSON value against the stored challenge, no base64
// decode in between).
const seamAssertionChallenge = "seam-assertion-challenge"

// waRowsStub is a pgx.Rows stub yielding one credential row for the
// ceremony loader's allow-list query (Scan dests: ID, PublicKey,
// AttestationType, SignCount).
type waRowsStub struct {
	pgx.Rows // nil embed
	credID   []byte
	pubKey   []byte
	attType  string
	scanErr  error
	yielded  bool
	closed   bool
}

// Next yields the single fixture row exactly once (an always-true Next
// would spin the loader's scan loop forever).
func (r *waRowsStub) Next() bool {
	if r.closed || r.yielded {
		return false
	}
	r.yielded = true
	return true
}

func (r *waRowsStub) Scan(dest ...any) error {
	if r.scanErr != nil {
		return r.scanErr
	}
	*(dest[0].(*[]byte)) = r.credID
	*(dest[1].(*[]byte)) = r.pubKey
	*(dest[2].(*string)) = r.attType
	*(dest[3].(*uint32)) = 0
	return nil
}

func (r *waRowsStub) Close() { r.closed = true }

func (r *waRowsStub) Err() error { return nil }

// coseEC2P256Key hand-encodes the CBOR COSE_Key for an ES256 P-256 public
// key — the exact wire form go-webauthn's ParseKey consumes: map(5) with
// 1:2 (kty EC2), 3:-7 (alg ES256), -1:1 (crv P-256), -2:x, -3:y; negative
// integer keys are major-type-0 with value 0x20+n, 32-byte strings use the
// 0x58 0x20 length form.
func coseEC2P256Key(x, y []byte) []byte {
	buf := []byte{0xa5}
	appendKey := func(key byte, val ...byte) {
		buf = append(buf, key)
		buf = append(buf, val...)
	}
	appendKey(0x01, 0x02) // kty = EC2
	appendKey(0x03, 0x26) // alg = ES256 (-7)
	appendKey(0x20, 0x01) // crv = P-256
	xLen := append([]byte{0x58, 0x20}, x...)
	yLen := append([]byte{0x58, 0x20}, y...)
	appendKey(0x21, xLen...) // x
	appendKey(0x22, yLen...) // y
	return buf
}

func seamSHA256(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// seamValidAssertion mints a cryptographically VALID webauthn_uv assertion:
// a fixture ECDSA P-256 keypair "enrolled" as the user's UV-capable
// credential, authenticator data over the harness RPID with UP|UV set,
// client data naming the harness origin and the fixture challenge, and a
// DER signature over authData || SHA-256(clientDataJSON). Returns the wire
// body, the credential ID, and the credential's COSE public key.
func seamValidAssertion(t *testing.T, userHandle []byte) (body, credID, coseKey []byte) {
	t.Helper()
	const (
		rpID   = "localhost"             // the harness provider's RPID
		origin = "http://localhost:8080" // the harness provider's origin
	)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate assertion key: %v", err)
	}
	coseKey = coseEC2P256Key(
		key.PublicKey.X.FillBytes(make([]byte, 32)),
		key.PublicKey.Y.FillBytes(make([]byte, 32)),
	)
	credID = []byte("seam-assertion-credential-id")

	clientData, err := json.Marshal(map[string]any{
		"type":      "webauthn.get",
		"challenge": seamAssertionChallenge,
		"origin":    origin,
	})
	if err != nil {
		t.Fatalf("marshal client data: %v", err)
	}
	authData := make([]byte, 0, 37)
	authData = append(authData, seamSHA256([]byte(rpID))...) // rpIdHash
	authData = append(authData, 0x05)                        // UP | UV (no BE/BS)
	authData = append(authData, 0, 0, 0, 1)                  // sign counter
	digest := sha256.Sum256(append(authData, seamSHA256(clientData)...))
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	wire, err := json.Marshal(map[string]any{
		"id":    b64(credID),
		"rawId": b64(credID),
		"type":  "public-key",
		// The finish decodes the body ONCE (the possession envelope) and
		// re-reads the same bytes for verification, so the wire body also
		// carries the operation the seeded ceremony declares; go-webauthn's
		// assertion decode ignores the extra member.
		"operation": "recovery.regenerate",
		"response": map[string]any{
			"authenticatorData": b64(authData),
			"clientDataJSON":    b64(clientData),
			"signature":         b64(sig),
			"userHandle":        b64(userHandle),
		},
	})
	if err != nil {
		t.Fatalf("marshal assertion: %v", err)
	}
	return wire, credID, coseKey
}

func TestSeamPossessionFinishConsumeMissReauth(t *testing.T) {
	// The §1.7 consume-miss arm: a crypto-VALID UV assertion (fixture keypair
	// enrolled through the scripted tx, RP/origin/challenge bound to the
	// seeded ceremony) drives the finish PAST verification, and the scripted
	// tx answers the single-use ceremony consume with pgx.ErrNoRows — the
	// ceremony vanished between peek and consume. Production answers the
	// typed 403 reauth_required and rolls back: no grant, no budget reset.
	h := newPossessionHarness(t)
	userID, claims := newPossessionUser(t, h, "seamconsumemiss", true)
	bearer := armsIssueBearer(t, h, userID, claims.Email)
	bearerClaims, err := h.jwt.Validate(bearer)
	if err != nil {
		t.Fatalf("validate bearer: %v", err)
	}

	userHandle := []byte("seam-webauthn-user-handle-000000001")
	assertionBody, credID, coseKey := seamValidAssertion(t, userHandle)
	ceremonyHash := authn.ChallengeHash(seamAssertionChallenge)
	// challenge_hash is the table's PRIMARY KEY and this fixture is
	// deterministic — clear any residue, then remove the row at cleanup.
	if _, err := h.pool.Exec(context.Background(),
		`DELETE FROM webauthn_ceremonies WHERE challenge_hash = $1`, ceremonyHash); err != nil {
		t.Fatalf("clear ceremony residue: %v", err)
	}
	t.Cleanup(func() {
		h.pool.Exec(context.Background(),
			`DELETE FROM webauthn_ceremonies WHERE challenge_hash = $1`, ceremonyHash)
	})
	if _, err := h.pool.Exec(context.Background(),
		`INSERT INTO webauthn_ceremonies
		   (challenge_hash, user_id, kind, operation, target_ref, session_jti, token_scope, refresh_family_id, expires_at)
		 VALUES ($1, $2, 'management_assertion', 'recovery.regenerate', NULL, $3, 'session', NULL, now() + interval '5 minutes')`,
		ceremonyHash, userID, bearerClaims.JTI); err != nil {
		t.Fatalf("seed ceremony: %v", err)
	}

	d := newRowDispatcher()
	handleCopy := append([]byte(nil), userHandle...)
	d.push("waUser", func(dest ...any) error {
		*(dest[0].(*int64)) = userID
		*(dest[1].(*string)) = "seam-finish@example.test"
		*(dest[2].(*string)) = "seam finish user"
		*(dest[3].(*[]byte)) = handleCopy
		return nil
	})
	d.push("consumeCeremony", func(...any) error { return pgx.ErrNoRows })
	tx := d.tx(nil)
	tx.query = func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
		if strings.Contains(sql, "passkey_credentials") {
			return &waRowsStub{credID: credID, pubKey: coseKey, attType: "none"}, nil
		}
		panic("seamGateTx: unscripted query: " + sql)
	}
	installSeam(h, tx, nil)

	// The raw assertion IS the request body (the finish re-reads the same
	// bytes for verification), so post it directly rather than through the
	// JSON-marshalling helper.
	req := httptest.NewRequest(http.MethodPost, "/auth/mfa/possession/webauthn/finish", bytes.NewReader(assertionBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	rr := httptest.NewRecorder()
	h.MFAPossessionWebAuthnFinish(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("consume-miss finish status = %d body %s, want 403", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "reauth_required") {
		t.Fatalf("consume-miss finish body = %s, want the reauth_required problem", rr.Body.String())
	}
	if tx.commits != 0 || tx.rollbacks < 1 {
		t.Fatalf("consume-miss tx state: commits=%d rollbacks=%d, want rollback only", tx.commits, tx.rollbacks)
	}
	// The ceremony row itself was never consumed (the consume ran on the
	// scripted tx that rolled back).
	var live bool
	if err := h.pool.QueryRow(context.Background(),
		`SELECT EXISTS (
		   SELECT 1 FROM webauthn_ceremonies
		    WHERE challenge_hash = $1 AND user_id = $2
		 )`,
		ceremonyHash, userID,
	).Scan(&live); err != nil || !live {
		t.Fatalf("ceremony row after the refusal: live=%v err=%v, want it preserved", live, err)
	}
}

func TestSeamWebAuthnRegisterResumeLookupFault(t *testing.T) {
	// webauthn.go's gated registration begin rides the SAME seamed
	// fencedFactorTx: a grant already bound to a target takes the resume
	// branch, whose live-ceremony recheck is the registration-resume SELECT
	// (webauthn.go ~85) — a statement fault there fails closed with 500.
	h := newPossessionHarness(t)
	_, claims := newPossessionUser(t, h, "seamregresume", true)
	d := newRowDispatcher()
	boundTarget := "challenge-hash-of-prior-ceremony"
	d.push("peek", func(dest ...any) error { return scanPeekRow(&boundTarget)(dest...) })
	d.push("registerResume", func(...any) error { return errInjectedRows })
	tx := d.tx(nil)
	installSeam(h, tx, nil)

	req := httptest.NewRequest(http.MethodPost, "/auth/webauthn/register/begin", nil)
	req.Header.Set("X-MFA-Reauth", "some-token")
	req = req.WithContext(ContextWithUser(context.Background(), claims))
	rr := httptest.NewRecorder()
	h.WebAuthnRegisterBegin(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("register resume lookup fault status = %d body %s, want 500", rr.Code, rr.Body.String())
	}
	if tx.commits != 0 {
		t.Fatalf("register resume fault committed %d times, want 0", tx.commits)
	}
}
