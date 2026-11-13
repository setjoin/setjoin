package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"setjoin.com/shared/pgxutil"
)

func TestWriteResetPasswordReducerError(t *testing.T) {
	tests := []struct {
		code       string
		wantHandle bool
		wantStatus int
	}{
		{code: "BZ060", wantHandle: true, wantStatus: http.StatusNotFound},
		{code: "BZ061", wantHandle: true, wantStatus: http.StatusNotFound},
		{code: "BZ221", wantHandle: true, wantStatus: http.StatusConflict},
		{code: "23505", wantHandle: false},
	}
	for _, test := range tests {
		t.Run(test.code, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/admin/users/1/reset-password", nil)
			rec := httptest.NewRecorder()
			handled := writeResetPasswordReducerError(
				rec, req, &pgconn.PgError{Code: test.code, Message: "test"},
			)
			if handled != test.wantHandle {
				t.Fatalf("handled=%v, want %v", handled, test.wantHandle)
			}
			if handled && rec.Code != test.wantStatus {
				t.Fatalf("status=%d, want %d", rec.Code, test.wantStatus)
			}
		})
	}
}

func TestResetPasswordRequestParsing(t *testing.T) {
	// Default: mustChange is absent → handler defaults to true
	payload := `{"password":"new-secret-8-chars"}`
	var req struct {
		Password   string `json:"password"`
		MustChange *bool  `json:"mustChange,omitempty"`
	}
	if err := json.Unmarshal([]byte(payload), &req); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if req.Password != "new-secret-8-chars" {
		t.Errorf("password = %q, want new-secret-8-chars", req.Password)
	}
	if req.MustChange != nil {
		t.Error("expected MustChange to be nil when absent")
	}

	// Explicit false
	payload2 := `{"password":"new-secret-8-chars","mustChange":false}`
	var req2 struct {
		Password   string `json:"password"`
		MustChange *bool  `json:"mustChange,omitempty"`
	}
	if err := json.Unmarshal([]byte(payload2), &req2); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if req2.MustChange == nil || *req2.MustChange != false {
		t.Error("expected MustChange to be false")
	}

	// Explicit true
	payload3 := `{"password":"new-secret-8-chars","mustChange":true}`
	var req3 struct {
		Password   string `json:"password"`
		MustChange *bool  `json:"mustChange,omitempty"`
	}
	if err := json.Unmarshal([]byte(payload3), &req3); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if req3.MustChange == nil || *req3.MustChange != true {
		t.Error("expected MustChange to be true")
	}
}

func TestAdminUserResponseParsing(t *testing.T) {
	payload := `{
		"id": 1,
		"email": "alice@example.com",
		"displayName": "Alice",
		"enabled": true,
		"isLocalAdmin": false,
		"departmentId": 2,
		"createdAt": "2024-01-01T00:00:00Z"
	}`
	var u UserResponse
	if err := json.Unmarshal([]byte(payload), &u); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if u.ID != 1 {
		t.Errorf("id = %d, want 1", u.ID)
	}
	if u.Email != "alice@example.com" {
		t.Errorf("email = %q, want alice@example.com", u.Email)
	}
	if !u.Enabled {
		t.Error("expected enabled = true")
	}
	if u.IsLocalAdmin {
		t.Error("expected isLocalAdmin = false")
	}
	if u.DepartmentID == nil || *u.DepartmentID != 2 {
		t.Errorf("departmentId = %v, want 2", u.DepartmentID)
	}
}

// TestUserProvisioningGoesThroughOneSeam guards the "logic where the data is"
// invariant for person+primary-mailbox creation: admin_users.go must NOT
// hand-roll users/mailboxes INSERTs (the path that historically used phantom
// columns like mailboxes(name, role) and omitted NOT NULL domain_id/username).
// Both create paths now route through the provision_account() reducer, which
// owns the schema-correct INSERTs (regression-guarded by provision_account.pg).
func TestUserProvisioningGoesThroughOneSeam(t *testing.T) {
	src, err := os.ReadFile("admin_users.go")
	if err != nil {
		t.Fatalf("read admin_users.go: %v", err)
	}
	s := string(src)
	if regexp.MustCompile(`INSERT INTO mailboxes\s*\(`).MatchString(s) {
		t.Error("admin_users.go must not hand-roll INSERT INTO mailboxes; use provision_account()")
	}
	if regexp.MustCompile(`INSERT INTO users\s*\(`).MatchString(s) {
		t.Error("admin_users.go must not hand-roll INSERT INTO users; use provision_account()")
	}
	if !regexp.MustCompile(`provision_account`).MatchString(s) {
		t.Fatal("expected admin_users.go to provision via provision_account()")
	}
}

// TestMailboxInsertColumnsAreReal is a non-DB guard against the column-mismatch
// regression for the secondary-mailbox path (admin_mailboxes.go still does a
// raw mailbox INSERT for additional mailboxes of an existing user): the source
// must reference only real columns (no phantom name/role).
func TestMailboxInsertColumnsAreReal(t *testing.T) {
	src, err := os.ReadFile("admin_mailboxes.go")
	if err != nil {
		t.Fatalf("read admin_mailboxes.go: %v", err)
	}
	// Match each `INSERT INTO mailboxes ( ... )` column list.
	re := regexp.MustCompile(`INSERT INTO mailboxes\s*\(([^)]*)\)`)
	matches := re.FindAllStringSubmatch(string(src), -1)
	if len(matches) == 0 {
		t.Fatal("expected at least one INSERT INTO mailboxes in admin_mailboxes.go")
	}
	// Columns that exist on the mailboxes table (schema/004_mailboxes.sql).
	valid := map[string]bool{
		"user_id": true, "domain_id": true, "email": true, "type": true,
		"display_name": true, "is_primary": true, "quota_bytes": true,
		"resource_type": true,
	}
	for _, m := range matches {
		for _, col := range splitCSVCols(m[1]) {
			if !valid[col] {
				t.Errorf("INSERT INTO mailboxes uses unknown column %q (column list: %q)", col, m[1])
			}
		}
	}
}

func splitCSVCols(s string) []string {
	var out []string
	for _, part := range bytes.Split([]byte(s), []byte(",")) {
		col := string(bytes.TrimSpace(part))
		if col != "" {
			out = append(out, col)
		}
	}
	return out
}

// TestCreateUserProvisionsPrimaryMailbox drives the real Create handler against
// the test DB and asserts the user's primary mailbox is created with the correct
// schema columns. Skips when DB_DSN is unset.
func TestCreateUserProvisionsPrimaryMailbox(t *testing.T) {
	pool := mailboxTestPool(t)
	ctx := context.Background()

	domainID := ensureMailboxTestDomain(t, pool) // domain "mbtest.example"
	suffix := mailboxRandomSuffix(t)
	email := "newuser-" + suffix + "@mbtest.example"

	h := NewUsersHandler(pool, pgxutil.WorkerPool{Pool: pool}, mailboxTestLogger(), nil, "", "")

	body, _ := json.Marshal(map[string]any{
		"email":       email,
		"displayName": "New User",
		"password":    "Sup3r-Str0ng-Pw!",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/users", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.Create(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("Create status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// Cleanup: the primary-mailbox trigger blocks plain deletes; disable triggers.
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `ALTER TABLE mailboxes DISABLE TRIGGER ALL`)
		pool.Exec(c, `DELETE FROM mailboxes WHERE user_id = $1`, created.ID)
		pool.Exec(c, `ALTER TABLE mailboxes ENABLE TRIGGER ALL`)
		pool.Exec(c, `DELETE FROM users WHERE id = $1`, created.ID)
	})

	// The primary mailbox must exist with the email, domain, display name, and
	// type the handler set — proving the corrected INSERT column list is valid.
	var (
		gotEmail, gotDisplay, gotType string
		gotDomainID                   int64
		gotPrimary                    bool
	)
	err := pool.QueryRow(ctx,
		`SELECT email, domain_id, display_name, type, is_primary
		   FROM mailboxes WHERE user_id = $1`, created.ID,
	).Scan(&gotEmail, &gotDomainID, &gotDisplay, &gotType, &gotPrimary)
	if err != nil {
		t.Fatalf("primary mailbox not found for user %d: %v", created.ID, err)
	}
	if gotEmail != email {
		t.Errorf("mailbox email = %q, want %q", gotEmail, email)
	}
	if gotDomainID != domainID {
		t.Errorf("mailbox domain_id = %d, want %d", gotDomainID, domainID)
	}
	if gotDisplay != "New User" {
		t.Errorf("mailbox display_name = %q, want %q", gotDisplay, "New User")
	}
	if gotType != "personal" {
		t.Errorf("mailbox type = %q, want personal", gotType)
	}
	if !gotPrimary {
		t.Error("mailbox is_primary = false, want true")
	}

	// The admin-create path fires the welcome email async (created=true). It runs
	// in a goroutine, so poll briefly for the system:welcome:<id> sentinel.
	sentinel := "system:welcome:" + strconv.FormatInt(created.ID, 10)
	var welcomes int
	for i := 0; i < 50; i++ {
		_ = pool.QueryRow(ctx,
			`SELECT count(*)::int FROM messages m JOIN mailboxes mb ON mb.id = m.mailbox_id
			  WHERE mb.user_id = $1 AND m.raw_ref = $2`, created.ID, sentinel).Scan(&welcomes)
		if welcomes > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if welcomes != 1 {
		t.Errorf("welcome count for new user = %d, want 1 (admin-create fires on created=true)", welcomes)
	}
}

func TestCreateUserExistingIdentityIsInsertOnly(t *testing.T) {
	pool := mailboxTestPool(t)
	ctx := context.Background()
	domainID := ensureMailboxTestDomain(t, pool)
	suffix := mailboxRandomSuffix(t)
	email := "create-only-" + suffix + "@mbtest.example"
	userID := createScopeTestUser(t, pool, domainID, "mbtest.example")
	if _, err := pool.Exec(ctx,
		`UPDATE users
		    SET email=$2, password_hash='original-hash', enabled=false,
		        display_name='Original Name', sync_source='local'
		  WHERE id=$1`,
		userID, email,
	); err != nil {
		t.Fatalf("seed existing user identity: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE mailboxes
		    SET email=$2, display_name='Original Name'
		  WHERE user_id=$1 AND is_primary`,
		userID, email,
	); err != nil {
		t.Fatalf("seed existing mailbox identity: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO oauth_tokens(user_id,token_hash,token_type,expires_at)
		 VALUES ($1,digest('create-only-anchor','sha256'),'refresh',
		         now()+interval '1 hour')`,
		userID,
	); err != nil {
		t.Fatalf("seed existing refresh anchor: %v", err)
	}

	h := NewUsersHandler(pool, pgxutil.WorkerPool{Pool: pool}, mailboxTestLogger(), nil, "", "")
	body, _ := json.Marshal(map[string]any{
		"email":       email,
		"displayName": "Attacker Replacement",
		"password":    "Sup3r-Str0ng-Pw!",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/users", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.Create(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("Create(existing) status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}

	var passwordHash, displayName, syncSource string
	var enabled bool
	if err := pool.QueryRow(ctx,
		`SELECT password_hash,display_name,enabled,sync_source
		   FROM users WHERE id=$1`,
		userID,
	).Scan(&passwordHash, &displayName, &enabled, &syncSource); err != nil {
		t.Fatalf("read existing identity: %v", err)
	}
	if passwordHash != "original-hash" || displayName != "Original Name" ||
		enabled || syncSource != "local" {
		t.Fatalf("create-only collision mutated user: hash=%q name=%q enabled=%v source=%q",
			passwordHash, displayName, enabled, syncSource)
	}
	var mailboxCount, activeAnchors int
	if err := pool.QueryRow(ctx,
		`SELECT
		   (SELECT count(*) FROM mailboxes WHERE user_id=$1),
		   (SELECT count(*) FROM oauth_tokens
		     WHERE user_id=$1 AND revoked_at IS NULL)`,
		userID,
	).Scan(&mailboxCount, &activeAnchors); err != nil {
		t.Fatalf("read collision side effects: %v", err)
	}
	if mailboxCount != 1 || activeAnchors != 1 {
		t.Fatalf("create-only collision changed related state: mailboxes=%d anchors=%d",
			mailboxCount, activeAnchors)
	}
}

// TestCreateUser_ResponseShapeIsIDKey pins the Create 201 body shape
// (admin_users.go:444): it must be {"id": <int64>}, not the old
// {"user_id":..., "created":true} shape (the reducer's own internal
// unmarshal-only struct, which used to leak straight into the HTTP response).
func TestCreateUser_ResponseShapeIsIDKey(t *testing.T) {
	pool := mailboxTestPool(t)
	ensureMailboxTestDomain(t, pool) // domain "mbtest.example"
	suffix := mailboxRandomSuffix(t)
	email := "shapetest-" + suffix + "@mbtest.example"

	h := NewUsersHandler(pool, pgxutil.WorkerPool{Pool: pool}, mailboxTestLogger(), nil, "", "")

	body, _ := json.Marshal(map[string]any{
		"email":       email,
		"displayName": "Shape Test",
		"password":    "Sup3r-Str0ng-Pw!",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/users", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.Create(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("Create status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode response as object: %v (body=%s)", err, rec.Body.String())
	}
	idRaw, ok := raw["id"]
	if !ok {
		t.Fatalf(`Create response missing "id" key; body=%s`, rec.Body.String())
	}
	var id int64
	if err := json.Unmarshal(idRaw, &id); err != nil {
		t.Fatalf(`"id" is not an int64: %v`, err)
	}
	if id <= 0 {
		t.Errorf("id = %d, want > 0", id)
	}
	if _, ok := raw["user_id"]; ok {
		t.Error(`Create response must not contain "user_id" (old provision-result shape)`)
	}
	if _, ok := raw["created"]; ok {
		t.Error(`Create response must not contain "created" (old provision-result shape)`)
	}

	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `ALTER TABLE mailboxes DISABLE TRIGGER ALL`)
		pool.Exec(c, `DELETE FROM mailboxes WHERE user_id = $1`, id)
		pool.Exec(c, `ALTER TABLE mailboxes ENABLE TRIGGER ALL`)
		pool.Exec(c, `DELETE FROM users WHERE id = $1`, id)
	})
}
