package jmap

// handler_delegate_test.go — the #13 shared-mailbox USE-surface proofs:
//
//   · delegateGrants runs the V090 FORCE-RLS lookup in the RunUserScoped shape
//     (GUC=app.current_user_id) — and the bare-pool shape provably returns
//     ZERO rows under the real constrained role (the "passes unit tests,
//     fails live" trap, pinned here with SET LOCAL ROLE setjoin_app);
//   · parseAccountID's METHOD GATE matrix: delegate permission levels ×
//     method classes (read/mutate/submit/personal), fail-closed defaults;
//   · revocation mid-session 403s the very next call (per-request, uncached);
//   · Dispatch threads each method's registry gate class into ctx;
//   · Session advertises delegate-granted mailboxes as additional accounts
//     (RFC 8620 multi-account shape) with the vendor delegateGrants levels.
//
// All tests here need DB_DSN (skipped otherwise), like the other _db tests.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/pgxutil"
)

// insertTestSharedMailbox creates a SHARED mailbox (user_id IS NULL) in its
// own throwaway domain and registers cleanup. Returns (mailboxID, email).
func insertTestSharedMailbox(t *testing.T, pool *pgxpool.Pool) (int64, string) {
	t.Helper()
	ctx := context.Background()

	suffix := randomSuffixDB(t)
	domainName := "test-jmap-shared-" + suffix + ".example.com"
	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ($1) RETURNING id`, domainName,
	).Scan(&domainID); err != nil {
		t.Fatalf("insert shared domain: %v", err)
	}

	email := "shared-" + suffix + "@" + domainName
	var mbID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO mailboxes (user_id, domain_id, email, type, display_name, is_primary)
		 VALUES (NULL, $1, $2, 'personal', 'Shared', FALSE) RETURNING id`,
		domainID, email,
	).Scan(&mbID); err != nil {
		t.Fatalf("insert shared mailbox: %v", err)
	}

	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM mailbox_delegates WHERE mailbox_id = $1`, mbID) //nolint:errcheck
		pool.Exec(context.Background(), `DELETE FROM mailboxes WHERE id = $1`, mbID)                 //nolint:errcheck
		pool.Exec(context.Background(), `DELETE FROM domains WHERE id = $1`, domainID)               //nolint:errcheck
	})
	return mbID, email
}

// grantDelegate inserts mailbox_delegates rows (superuser pool bypasses RLS).
func grantDelegate(t *testing.T, pool *pgxpool.Pool, mailboxID, userID int64, perms ...string) {
	t.Helper()
	for _, p := range perms {
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by)
			 VALUES ($1, $2, $3, $2)`,
			mailboxID, userID, p); err != nil {
			t.Fatalf("grant %s: %v", p, err)
		}
	}
}

func revokeDelegate(t *testing.T, pool *pgxpool.Pool, mailboxID, userID int64) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`DELETE FROM mailbox_delegates WHERE mailbox_id = $1 AND user_id = $2`,
		mailboxID, userID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
}

// TestDelegateGrants_RunUserScopedShapeUnderRLS is THE trap proof: V090 makes
// mailbox_delegates FORCE-RLS and fail-closed, so under the real constrained
// runtime role (setjoin_app — NOSUPERUSER, NOBYPASSRLS) a bare-pool query
// returns ZERO rows, while the production RunUserScoped shape (GUC =
// app.current_user_id, the exact shape h.delegateGrants uses) sees the grant.
func TestDelegateGrants_RunUserScopedShapeUnderRLS(t *testing.T) {
	pool := testPoolDB(t)
	ctx := context.Background()

	_, userID, _ := insertTestUserWithMailbox(t, pool, false)
	sharedID, _ := insertTestSharedMailbox(t, pool)
	grantDelegate(t, pool, sharedID, userID, "read")

	countAs := func(setGUC bool) int64 {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if setGUC {
			if _, err := tx.Exec(ctx,
				"SELECT set_config('app.current_user_id', $1, true)",
				strconv.FormatInt(userID, 10)); err != nil {
				t.Fatalf("set_config: %v", err)
			}
		}
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE setjoin_app"); err != nil {
			t.Fatalf("SET LOCAL ROLE setjoin_app: %v", err)
		}
		var n int64
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM mailbox_delegates WHERE mailbox_id = $1 AND user_id = $2`,
			sharedID, userID).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}

	// The bare-pool shape (no GUC): fail-closed, ZERO rows — this is what a
	// naive h.pool.Query delegate lookup would see under the live flip.
	if n := countAs(false); n != 0 {
		t.Fatalf("bare-pool shape under setjoin_app saw %d rows, want 0 (V090 fail-closed)", n)
	}
	// The RunUserScoped shape (GUC set): the delegate arm admits the row.
	if n := countAs(true); n != 1 {
		t.Fatalf("RunUserScoped shape under setjoin_app saw %d rows, want 1 (V090 delegate arm)", n)
	}

	// And the production path end-to-end under the same constrained role:
	// RunUserScoped sets the GUC, we drop to setjoin_app inside the same tx,
	// and the h.delegateGrants query shape returns the grant.
	var grants []string
	err := dbscope.RunUserScoped(ctx, pool, userID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE setjoin_app"); err != nil {
			return err
		}
		rows, err := tx.Query(ctx,
			`SELECT permission FROM mailbox_delegates WHERE mailbox_id = $1 AND user_id = $2`,
			sharedID, userID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var g string
			if err := rows.Scan(&g); err != nil {
				return err
			}
			grants = append(grants, g)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatalf("RunUserScoped delegate lookup: %v", err)
	}
	if len(grants) != 1 || grants[0] != "read" {
		t.Fatalf("RunUserScoped delegate lookup = %v, want [read]", grants)
	}

	// Wiring: the real h.delegateGrants (superuser pool — RLS bypassed here,
	// the shape above is the RLS proof) returns the same grant.
	h := NewJMAPHandler(pool, pgxutil.WorkerPool{Pool: pool}, "localhost", nil, "test-bucket", 10_000_000, testLoggerDB(t))
	got, err := h.delegateGrants(ctx, sharedID, userID)
	if err != nil {
		t.Fatalf("h.delegateGrants: %v", err)
	}
	if len(got) != 1 || got[0] != "read" {
		t.Fatalf("h.delegateGrants = %v, want [read]", got)
	}
}

func errType(t *testing.T, errResp json.RawMessage) string {
	t.Helper()
	if errResp == nil {
		return ""
	}
	var e Error
	if err := json.Unmarshal(errResp, &e); err != nil {
		t.Fatalf("unmarshal error resp %s: %v", errResp, err)
	}
	return e.Type
}

// TestParseAccountID_DelegateGateMatrix is the (c) blocker proof: RLS gives
// SCOPE, the method gate gives PERMISSION LEVEL. One subtest per grant-set ×
// method-class cell; driven through the real parseAccountID with the gate
// class injected the way Dispatch injects it.
func TestParseAccountID_DelegateGateMatrix(t *testing.T) {
	pool := testPoolDB(t)
	h := NewJMAPHandler(pool, pgxutil.WorkerPool{Pool: pool}, "localhost", nil, "test-bucket", 10_000_000, testLoggerDB(t))
	ctx := context.Background()

	_, userID, _ := insertTestUserWithMailbox(t, pool, false)
	sharedID, _ := insertTestSharedMailbox(t, pool)
	reqID := strconv.FormatInt(sharedID, 10)

	classes := map[string]gateClass{
		"read": gateRead, "mutate": gateMutate, "submit": gateSubmit, "personal": gatePersonal,
	}
	cases := []struct {
		grants []string
		allow  map[string]bool // class name → allowed
		deny   string          // expected error type on denial
	}{
		{nil, map[string]bool{}, "accountNotFound"},
		{[]string{"manage_calendar"}, map[string]bool{}, "forbidden"}, // calendar delegation is NOT mail delegation
		{[]string{"read"}, map[string]bool{"read": true}, "forbidden"},
		{[]string{"send_on_behalf"}, map[string]bool{"read": true, "submit": true}, "forbidden"},
		{[]string{"send_as"}, map[string]bool{"read": true, "submit": true}, "forbidden"},
		{[]string{"full_access"}, map[string]bool{"read": true, "mutate": true, "submit": true}, "forbidden"},
		{[]string{"read", "send_on_behalf"}, map[string]bool{"read": true, "submit": true}, "forbidden"},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("grants=%v", tc.grants), func(t *testing.T) {
			revokeDelegate(t, pool, sharedID, userID)
			grantDelegate(t, pool, sharedID, userID, tc.grants...)
			for name, class := range classes {
				gctx := invocationContext{Context: ctx, Metadata: invocationMetadata{Gate: class}}
				resolved, errResp := h.parseAccountID(gctx, reqID, userID)
				if tc.allow[name] {
					if errResp != nil {
						t.Errorf("class %s with grants %v: denied (%s), want allowed", name, tc.grants, errResp)
					} else if resolved != sharedID {
						t.Errorf("class %s: resolved %d, want %d", name, resolved, sharedID)
					}
				} else {
					if errResp == nil {
						t.Errorf("class %s with grants %v: ALLOWED, want %s", name, tc.grants, tc.deny)
					} else if got := errType(t, errResp); got != tc.deny {
						t.Errorf("class %s with grants %v: error type %s, want %s", name, tc.grants, got, tc.deny)
					}
				}
			}
		})
	}

	// Fail-closed default: NO gate class in ctx (a path outside Dispatch) must
	// deny a delegated accountId even at the highest grant.
	revokeDelegate(t, pool, sharedID, userID)
	grantDelegate(t, pool, sharedID, userID, "full_access")
	if _, errResp := h.parseAccountID(ctx, reqID, userID); errResp == nil {
		t.Error("no gate class in ctx: delegated accountId allowed, want fail-closed forbidden")
	}

	// Owner hot path is untouched by the gate: the caller's own primary passes
	// under EVERY class, including personal.
	_, ownerID, ownerMbx := insertTestUserWithMailbox(t, pool, false)
	for name, class := range classes {
		gctx := invocationContext{Context: ctx, Metadata: invocationMetadata{Gate: class}}
		if _, errResp := h.parseAccountID(gctx, strconv.FormatInt(ownerMbx, 10), ownerID); errResp != nil {
			t.Errorf("own primary denied under class %s: %s", name, errResp)
		}
	}
}

// TestParseAccountID_DelegateRevokedMidSession pins the uncached per-request
// check: the request AFTER a revocation is denied — no session-lifetime cache.
func TestParseAccountID_DelegateRevokedMidSession(t *testing.T) {
	pool := testPoolDB(t)
	h := NewJMAPHandler(pool, pgxutil.WorkerPool{Pool: pool}, "localhost", nil, "test-bucket", 10_000_000, testLoggerDB(t))

	_, userID, _ := insertTestUserWithMailbox(t, pool, false)
	sharedID, _ := insertTestSharedMailbox(t, pool)
	grantDelegate(t, pool, sharedID, userID, "read")

	gctx := invocationContext{Context: context.Background(), Metadata: invocationMetadata{Gate: gateRead}}
	reqID := strconv.FormatInt(sharedID, 10)

	if _, errResp := h.parseAccountID(gctx, reqID, userID); errResp != nil {
		t.Fatalf("granted read: denied %s, want allowed", errResp)
	}
	revokeDelegate(t, pool, sharedID, userID)
	if _, errResp := h.parseAccountID(gctx, reqID, userID); errResp == nil {
		t.Fatal("REVOKED grant still allowed on the next request — the delegate check must be per-request/uncached")
	} else if got := errType(t, errResp); got != "accountNotFound" {
		t.Fatalf("revoked error type = %s, want accountNotFound", got)
	}
}

// TestDispatch_DelegateMethodGate proves Dispatch threads each method's
// registry gate class into ctx: with a read-only grant, a read method reaches
// its handler while mutating/submission/personal methods 403 at the gate.
func TestDispatch_DelegateMethodGate(t *testing.T) {
	pool := testPoolDB(t)
	h := NewJMAPHandler(pool, pgxutil.WorkerPool{Pool: pool}, "localhost", nil, "test-bucket", 10_000_000, testLoggerDB(t))
	ctx := context.Background()

	_, userID, ownMbx := insertTestUserWithMailbox(t, pool, false)
	sharedID, _ := insertTestSharedMailbox(t, pool)
	grantDelegate(t, pool, sharedID, userID, "read")

	claims := &auth.Claims{UserID: userID, Email: "delegate@test.example"}
	args := func(id int64) json.RawMessage {
		return json.RawMessage(`{"accountId":"` + strconv.FormatInt(id, 10) + `"}`)
	}

	// Read method on the delegated account: passes the gate, reaches the reducer.
	if name, resp := h.Dispatch(ctx, claims, "Mailbox/get", args(sharedID)); name == "error" {
		t.Errorf("Mailbox/get on delegated account with read grant = error %s, want success", resp)
	}
	// Mutating method: forbidden.
	if name, resp := h.Dispatch(ctx, claims, "Email/set", args(sharedID)); name != "error" || errType(t, resp) != "forbidden" {
		t.Errorf("Email/set on read-only delegated account = (%s, %s), want forbidden", name, resp)
	}
	// Submission method: forbidden without a send grant.
	if name, resp := h.Dispatch(ctx, claims, "EmailSubmission/query", args(sharedID)); name != "error" || errType(t, resp) != "forbidden" {
		t.Errorf("EmailSubmission/query on read-only delegated account = (%s, %s), want forbidden", name, resp)
	}
	// Personal-only method: forbidden on a delegated account at any grant.
	if name, resp := h.Dispatch(ctx, claims, "Task/get", args(sharedID)); name != "error" || errType(t, resp) != "forbidden" {
		t.Errorf("Task/get on delegated account = (%s, %s), want forbidden", name, resp)
	}
	// Control: the same mutating method on the caller's OWN primary is not gated.
	if name, resp := h.Dispatch(ctx, claims, "Email/set", args(ownMbx)); name == "error" && errType(t, resp) == "forbidden" {
		t.Errorf("Email/set on own primary = forbidden (%s), want ungated", resp)
	}
}

// TestSession_AdvertisesDelegatedAccounts pins the (b) RFC 8620 multi-account
// session shape: every mail-delegated mailbox appears as an additional account
// (isPersonal=false, name=the shared mailbox's email), isReadOnly reflects the
// absence of full_access, the submission capability appears only with a send
// grant, and the vendor block carries the raw grant levels (the ONE identity
// enumeration the From Select consumes — no second roundtrip).
func TestSession_AdvertisesDelegatedAccounts(t *testing.T) {
	pool := testPoolDB(t)
	h := NewJMAPHandler(pool, pgxutil.WorkerPool{Pool: pool}, "localhost", nil, "test-bucket", 10_000_000, testLoggerDB(t))

	_, userID, ownMbx := insertTestUserWithMailbox(t, pool, false)
	readOnlyID, readOnlyEmail := insertTestSharedMailbox(t, pool)
	grantDelegate(t, pool, readOnlyID, userID, "read")
	fullID, fullEmail := insertTestSharedMailbox(t, pool)
	grantDelegate(t, pool, fullID, userID, "full_access", "send_as")
	fullAlias := strings.Replace(fullEmail, "shared-", "alias-", 1)
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO aliases (mailbox_id, email, domain_id)
		 SELECT id, $2, domain_id FROM mailboxes WHERE id = $1`,
		fullID, fullAlias); err != nil {
		t.Fatalf("insert full-access shared alias: %v", err)
	}
	onBehalfID, onBehalfEmail := insertTestSharedMailbox(t, pool)
	grantDelegate(t, pool, onBehalfID, userID, "send_on_behalf")
	onBehalfAlias := strings.Replace(onBehalfEmail, "shared-", "on-behalf-alias-", 1)
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO aliases (mailbox_id, email, domain_id)
		 SELECT id, $2, domain_id FROM mailboxes WHERE id = $1`,
		onBehalfID, onBehalfAlias); err != nil {
		t.Fatalf("insert send-on-behalf shared alias: %v", err)
	}
	disabledID, _ := insertTestSharedMailbox(t, pool)
	grantDelegate(t, pool, disabledID, userID, "send_as")
	if _, err := pool.Exec(context.Background(),
		`UPDATE mailboxes SET enabled = FALSE WHERE id = $1`, disabledID); err != nil {
		t.Fatalf("disable shared mailbox: %v", err)
	}
	readOnlyAlias := strings.Replace(readOnlyEmail, "shared-", "read-alias-", 1)
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO aliases (mailbox_id, email, domain_id)
		 SELECT id, $2, domain_id FROM mailboxes WHERE id = $1`,
		readOnlyID, readOnlyAlias); err != nil {
		t.Fatalf("insert read-only shared alias: %v", err)
	}
	calOnlyID, _ := insertTestSharedMailbox(t, pool)
	grantDelegate(t, pool, calOnlyID, userID, "manage_calendar")

	claims := &auth.Claims{UserID: userID, Email: "delegate@test.example"}
	req := httptest.NewRequest("GET", "/jmap/session", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	rr := httptest.NewRecorder()
	h.Session(rr, req)
	if rr.Code != 200 {
		t.Fatalf("Session status = %d, body %s", rr.Code, rr.Body.String())
	}

	var sess struct {
		Accounts map[string]struct {
			Name                string         `json:"name"`
			IsPersonal          bool           `json:"isPersonal"`
			IsReadOnly          bool           `json:"isReadOnly"`
			AccountCapabilities map[string]any `json:"accountCapabilities"`
		} `json:"accounts"`
		PrimaryAccounts map[string]string `json:"primaryAccounts"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &sess); err != nil {
		t.Fatalf("unmarshal session: %v", err)
	}

	ownKey := strconv.FormatInt(ownMbx, 10)
	own, ok := sess.Accounts[ownKey]
	if !ok || !own.IsPersonal {
		t.Fatalf("primary account %s missing or not personal: %+v", ownKey, sess.Accounts)
	}
	if sess.PrimaryAccounts["urn:ietf:params:jmap:mail"] != ownKey {
		t.Errorf("primaryAccounts[mail] = %s, want %s (delegated accounts must never become primary)",
			sess.PrimaryAccounts["urn:ietf:params:jmap:mail"], ownKey)
	}

	ro, ok := sess.Accounts[strconv.FormatInt(readOnlyID, 10)]
	if !ok {
		t.Fatalf("read-granted shared mailbox %d absent from session accounts", readOnlyID)
	}
	if ro.IsPersonal || !ro.IsReadOnly || ro.Name != readOnlyEmail {
		t.Errorf("read-only shared account = %+v, want isPersonal=false isReadOnly=true name=%s", ro, readOnlyEmail)
	}
	if _, has := ro.AccountCapabilities["urn:ietf:params:jmap:mail"]; !has {
		t.Error("read-only shared account missing the mail capability")
	}
	if _, has := ro.AccountCapabilities["urn:ietf:params:jmap:submission"]; has {
		t.Error("read-only shared account advertises submission, want absent (no send grant)")
	}
	vendor, _ := ro.AccountCapabilities[VendorCapability].(map[string]any)
	if grants, _ := vendor["delegateGrants"].([]any); len(grants) != 1 || grants[0] != "read" {
		t.Errorf("read-only shared account delegateGrants = %v, want [read]", vendor["delegateGrants"])
	}
	if aliases, _ := vendor["sendAsAliases"].([]any); len(aliases) != 0 {
		t.Errorf("read-only shared account sendAsAliases = %v, want empty", vendor["sendAsAliases"])
	}

	full, ok := sess.Accounts[strconv.FormatInt(fullID, 10)]
	if !ok {
		t.Fatalf("full_access shared mailbox %d absent from session accounts", fullID)
	}
	if full.IsReadOnly {
		t.Error("full_access shared account isReadOnly = true, want false")
	}
	if _, has := full.AccountCapabilities["urn:ietf:params:jmap:submission"]; !has {
		t.Error("send_as shared account missing the submission capability")
	}
	fullVendor, _ := full.AccountCapabilities[VendorCapability].(map[string]any)
	if aliases, _ := fullVendor["sendAsAliases"].([]any); len(aliases) != 1 || aliases[0] != fullAlias {
		t.Errorf("full-access shared account sendAsAliases = %v, want [%s]",
			fullVendor["sendAsAliases"], fullAlias)
	}

	onBehalf, ok := sess.Accounts[strconv.FormatInt(onBehalfID, 10)]
	if !ok {
		t.Fatalf("send_on_behalf shared mailbox %d absent from session accounts", onBehalfID)
	}
	if _, has := onBehalf.AccountCapabilities["urn:ietf:params:jmap:submission"]; !has {
		t.Error("send_on_behalf shared account missing the submission capability")
	}
	onBehalfVendor, _ := onBehalf.AccountCapabilities[VendorCapability].(map[string]any)
	if aliases, _ := onBehalfVendor["sendAsAliases"].([]any); len(aliases) != 0 {
		t.Errorf("send_on_behalf shared account sendAsAliases = %v, want empty", onBehalfVendor["sendAsAliases"])
	}

	if _, has := sess.Accounts[strconv.FormatInt(disabledID, 10)]; has {
		t.Error("disabled send_as mailbox advertised as a session account")
	}
	if _, has := sess.Accounts[strconv.FormatInt(calOnlyID, 10)]; has {
		t.Error("manage_calendar-only mailbox advertised as a mail account — calendar delegation is not mail delegation")
	}
}
