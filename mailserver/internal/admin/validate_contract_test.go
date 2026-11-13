package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/validate"
)

// med-shard2-008 (D-SHARED-VALIDATE-001/002): validation-contract wiring tests
// for the privileged provisioning paths — aliases.email and mailboxes.email
// must persist canonical validated values (no raw display-name/quoted-local/
// comment or control-character forms) and RFC 2142 reserved local-parts must
// be refused. DB-backed; skips without DB_DSN (testsupport.OpenTestPool).

// TestAddAliasPersistsCanonicalValidatedValue pins that the alias add handler
// stores the canonical validated address — the identity fold (trim + ASCII-fold
// lower + RFC 5322 display-name strip) — never the raw request string.
func TestAddAliasPersistsCanonicalValidatedValue(t *testing.T) {
	pool := mailboxTestPool(t)
	h := &UsersHandler{pool: pool, logger: mailboxTestLogger()}
	ctx := context.Background()
	domainID := ensureMailboxTestDomain(t, pool)
	userID := createMailboxTestUser(t, pool, domainID)
	createPersonalMailbox(t, pool, userID, domainID)

	// Raw decorated input: display-name wrapper, mixed case, padding. The
	// local-part carries a random suffix so reruns never collide with the
	// unique alias address left by an earlier run.
	suffix := mailboxRandomSuffix(t)
	raw := fmt.Sprintf(`  "Alias One" <Alias.Case-%s@MbTest.Example>  `, suffix)
	body, _ := json.Marshal(map[string]string{"email": raw})
	req := httptest.NewRequest(http.MethodPost, "/admin/users/0/aliases", bytes.NewReader(body))
	req.SetPathValue("id", fmt.Sprintf("%d", userID))
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.AddAlias(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("AddAlias returned %d, want 201; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode alias response: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM aliases WHERE id = $1`, resp.ID)
	})

	var stored string
	if err := pool.QueryRow(ctx, `SELECT email FROM aliases WHERE id = $1`, resp.ID).Scan(&stored); err != nil {
		t.Fatalf("re-read alias: %v", err)
	}
	// Canonical: decoration stripped, ASCII-folded — and it must resolve
	// identically to the users.email fold it aliases.
	if stored != fmt.Sprintf("alias.case-%s@mbtest.example", suffix) {
		t.Fatalf("aliases.email = %q, want canonical fold of %q", stored, raw)
	}
	if stored != strings.TrimSpace(stored) || strings.ContainsAny(stored, "\"<>") {
		t.Fatalf("aliases.email %q carries raw decoration", stored)
	}
}

// TestAddAliasRejectsReservedLocalPart pins the RFC 2142 gate on the alias
// provisioning path: a reserved local-part is refused with 400 and nothing is
// persisted.
func TestAddAliasRejectsReservedLocalPart(t *testing.T) {
	pool := mailboxTestPool(t)
	h := &UsersHandler{pool: pool, logger: mailboxTestLogger()}
	ctx := context.Background()
	domainID := ensureMailboxTestDomain(t, pool)
	userID := createMailboxTestUser(t, pool, domainID)
	createPersonalMailbox(t, pool, userID, domainID)

	for _, email := range []string{"abuse@mbtest.example", `"postmaster"@mbtest.example`} {
		body, _ := json.Marshal(map[string]string{"email": email})
		req := httptest.NewRequest(http.MethodPost, "/admin/users/0/aliases", bytes.NewReader(body))
		req.SetPathValue("id", fmt.Sprintf("%d", userID))
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()
		h.AddAlias(w, req)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("AddAlias(%s) returned %d, want 400; body=%s", email, w.Code, w.Body.String())
		}
	}
	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM aliases WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = $1)
		 AND lower(email) IN ('abuse@mbtest.example', 'postmaster@mbtest.example')`,
		userID).Scan(&count); err != nil {
		t.Fatalf("count reserved aliases: %v", err)
	}
	if count != 0 {
		t.Fatalf("reserved alias persisted: count=%d", count)
	}
}

// TestMailboxCreatePersistsCanonicalEmail pins that mailboxes.email receives
// the canonical validated value, not the raw request string the old
// error-only ValidateEmail call inspected.
func TestMailboxCreatePersistsCanonicalEmail(t *testing.T) {
	pool := mailboxTestPool(t)
	h := NewMailboxesHandler(pool, pgxutil.WorkerPool{Pool: pool}, mailboxTestLogger())
	ctx := context.Background()
	domainID := ensureMailboxTestDomain(t, pool)
	userID := createMailboxTestUser(t, pool, domainID)
	createPersonalMailbox(t, pool, userID, domainID) // the every-user-has-a-primary trigger demands it

	// Decorated input: display-name + comment wrapper, padding. The canonical
	// value keeps the operator's casing (CanonicalEmail does not apply the
	// identity ASCII-fold) but strips every decoration. Random suffix keeps
	// reruns clear of the mailboxes.email unique constraint.
	suffix := mailboxRandomSuffix(t)
	raw := fmt.Sprintf(`  "Mail Fixture" <Mail.Fixture-%s@mbtest.example> (fixture)  `, suffix)
	// quotaBytes is supplied explicitly: the handler's nil-quota path binds an
	// explicit NULL that bypasses the column default and 500s — a pre-existing
	// defect outside this package's scope, not exercised here.
	payload := fmt.Sprintf(`{"userId":%d,"email":%s,"type":"personal","quotaBytes":1073741824}`,
		userID, mustJSONString(t, raw))
	req := httptest.NewRequest(http.MethodPost, "/admin/mailboxes", strings.NewReader(payload))
	req = req.WithContext(auth.ContextWithUser(ctx, &auth.Claims{UserID: userID}))
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("mailbox Create returned %d, want 201; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode mailbox response: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM mailboxes WHERE id = $1`, resp.ID)
	})

	var stored, displayName string
	if err := pool.QueryRow(ctx,
		`SELECT email, display_name FROM mailboxes WHERE id = $1`, resp.ID,
	).Scan(&stored, &displayName); err != nil {
		t.Fatalf("re-read mailbox: %v", err)
	}
	wantEmail := fmt.Sprintf("Mail.Fixture-%s@mbtest.example", suffix)
	if stored != wantEmail {
		t.Fatalf("mailboxes.email = %q, want canonical %q", stored, wantEmail)
	}
	if displayName != wantEmail {
		t.Fatalf("default display_name = %q, want the canonical address %q", displayName, wantEmail)
	}
}

// TestMailboxCreatePersistsQuotedLocalCanonicalEmail pins the med-shard2-008
// round-2 CanonicalEmail contract at the persist site: an input whose
// quoted-string local-part REQUIRES quoting (`"Quoted Local-x"@…`) must persist
// the re-quoted canonical. The pre-r2 CanonicalEmail returned the de-quoted
// `Quoted Local-x@…`, which fails the same validator and would have stored an
// invalid mailboxes.email.
func TestMailboxCreatePersistsQuotedLocalCanonicalEmail(t *testing.T) {
	pool := mailboxTestPool(t)
	h := NewMailboxesHandler(pool, pgxutil.WorkerPool{Pool: pool}, mailboxTestLogger())
	ctx := context.Background()
	domainID := ensureMailboxTestDomain(t, pool)
	userID := createMailboxTestUser(t, pool, domainID)
	createPersonalMailbox(t, pool, userID, domainID) // the every-user-has-a-primary trigger demands it

	// Quoted local whose bare form is invalid (contains a space). Random suffix
	// keeps reruns clear of the mailboxes.email unique constraint; domain stays
	// lowercase so the expected value is byte-stable.
	suffix := mailboxRandomSuffix(t)
	raw := fmt.Sprintf(`"Quoted Local-%s"@mbtest.example`, suffix)
	payload := fmt.Sprintf(`{"userId":%d,"email":%s,"type":"personal","quotaBytes":1073741824}`,
		userID, mustJSONString(t, raw))
	req := httptest.NewRequest(http.MethodPost, "/admin/mailboxes", strings.NewReader(payload))
	req = req.WithContext(auth.ContextWithUser(ctx, &auth.Claims{UserID: userID}))
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("mailbox Create returned %d, want 201; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode mailbox response: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM mailboxes WHERE id = $1`, resp.ID)
	})

	var stored, displayName string
	if err := pool.QueryRow(ctx,
		`SELECT email, display_name FROM mailboxes WHERE id = $1`, resp.ID,
	).Scan(&stored, &displayName); err != nil {
		t.Fatalf("re-read mailbox: %v", err)
	}
	want := fmt.Sprintf(`"Quoted Local-%s"@mbtest.example`, suffix)
	if stored != want {
		t.Fatalf("mailboxes.email = %q, want the quoted canonical %q (de-quoted form fails ValidateEmail)", stored, want)
	}
	if displayName != want {
		t.Fatalf("default display_name = %q, want the canonical address %q", displayName, want)
	}
	// Returned-value validity at the persist site: what the handler stores must
	// pass the same validator that accepted the request string.
	if ve := validate.ValidateEmail(stored); ve != nil {
		t.Fatalf("stored mailboxes.email %q fails validate.ValidateEmail: %v", stored, ve)
	}
}

// TestMailboxCreateRejectsControlCharacterEmail pins the control-character
// refusal: a header-injection style address must never persist.
func TestMailboxCreateRejectsControlCharacterEmail(t *testing.T) {
	pool := mailboxTestPool(t)
	h := NewMailboxesHandler(pool, pgxutil.WorkerPool{Pool: pool}, mailboxTestLogger())
	ctx := context.Background()
	domainID := ensureMailboxTestDomain(t, pool)
	userID := createMailboxTestUser(t, pool, domainID)

	payload := fmt.Sprintf(`{"userId":%d,"email":"victim@mbtest.example\nBCC: x@y.z","type":"personal"}`, userID)
	req := httptest.NewRequest(http.MethodPost, "/admin/mailboxes", strings.NewReader(payload))
	req = req.WithContext(auth.ContextWithUser(ctx, &auth.Claims{UserID: userID}))
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("mailbox Create with control-char email returned %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

// TestDomainCreatePersistsCanonicalName pins that domains.name is persisted
// trimmed + lowercased (the comparison-canonical form) and validated — the
// create path previously validated a trimmed copy but stored the raw string.
func TestDomainCreatePersistsCanonicalName(t *testing.T) {
	pool := mailboxTestPool(t)
	h := NewDomainsHandler(pool, mailboxTestLogger())
	ctx := context.Background()

	suffix := mailboxRandomSuffix(t)
	raw := fmt.Sprintf("  DbTest-%s.Example.COM  ", suffix)
	payload := fmt.Sprintf(`{"name":%s,"isLocal":true}`, mustJSONString(t, raw))
	req := httptest.NewRequest(http.MethodPost, "/admin/domains", strings.NewReader(payload))
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("domain Create returned %d, want 201; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode domain response: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM domains WHERE id = $1`, resp.ID)
	})

	var stored string
	if err := pool.QueryRow(ctx, `SELECT name FROM domains WHERE id = $1`, resp.ID).Scan(&stored); err != nil {
		t.Fatalf("re-read domain: %v", err)
	}
	want := fmt.Sprintf("dbtest-%s.example.com", suffix)
	if stored != want {
		t.Fatalf("domains.name = %q, want canonical %q", stored, want)
	}
}

// TestDomainUpdateValidatesCanonicalName pins the update path: a rename is
// canonicalized and RFC 1035 validated (the patch path previously accepted
// anything, including invalid names).
func TestDomainUpdateValidatesCanonicalName(t *testing.T) {
	pool := mailboxTestPool(t)
	h := NewDomainsHandler(pool, mailboxTestLogger())
	ctx := context.Background()

	suffix := mailboxRandomSuffix(t)
	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ($1) RETURNING id`,
		fmt.Sprintf("dtest-%s.example", suffix),
	).Scan(&domainID); err != nil {
		t.Fatalf("seed domain: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM domains WHERE id = $1`, domainID)
	})

	// Invalid name is refused outright.
	bad := fmt.Sprintf(`{"name":"bad name!%s"}`, suffix)
	req := httptest.NewRequest(http.MethodPatch, "/admin/domains/0", strings.NewReader(bad))
	req.SetPathValue("id", fmt.Sprintf("%d", domainID))
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.Update(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("domain Update with invalid name returned %d, want 400; body=%s", w.Code, w.Body.String())
	}

	// Valid but decorated name is canonicalized before the write.
	good := fmt.Sprintf(`{"name":%s}`, mustJSONString(t, fmt.Sprintf("  Renamed-%s.EXAMPLE.com  ", suffix)))
	req2 := httptest.NewRequest(http.MethodPatch, "/admin/domains/0", strings.NewReader(good))
	req2.SetPathValue("id", fmt.Sprintf("%d", domainID))
	req2 = req2.WithContext(ctx)
	w2 := httptest.NewRecorder()
	h.Update(w2, req2)
	if w2.Code != http.StatusNoContent {
		t.Fatalf("domain Update returned %d, want 204; body=%s", w2.Code, w2.Body.String())
	}
	var stored string
	if err := pool.QueryRow(ctx, `SELECT name FROM domains WHERE id = $1`, domainID).Scan(&stored); err != nil {
		t.Fatalf("re-read domain: %v", err)
	}
	want := fmt.Sprintf("renamed-%s.example.com", suffix)
	if stored != want {
		t.Fatalf("domains.name = %q, want canonical %q", stored, want)
	}
}

// mustJSONString encodes s as a JSON string literal for inline payloads.
func mustJSONString(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal %q: %v", s, err)
	}
	return string(b)
}
