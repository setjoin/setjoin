package admin

// Round-2 admin-scope correction tests (Astra implementation review HOLD):
//
//	H1. The removed `scope == 0` shortcut let a caller whose ONLY assignment is
//	    OU-confined with no domain (the resolver leaves DomainScope unset for it)
//	    reach ANY owner-present mailbox. Authority must be enforced at data
//	    access regardless: admin_can_reach decides owned rows for every caller.
//	H2. The export route previously guarded on the broad Mail-console umbrella;
//	    it now requires the dedicated mail.export grant (V233).
//	H5. Post-authentication revocation: admin_can_reach is re-evaluated per
//	    request, so expiring the assignment denies the very next request.
//
// Fixtures are real rows (domains, departments, users, mailboxes, role groups,
// admin_role_assignments) so admin_can_reach / admin_effective_authority have
// genuine authority to decide. The stub S3 (admin_ediscovery_test.go genre) is
// an httptest.Server driven by a REAL *minio.Client implementing PUT+GET so the
// nonempty import/export round-trip touches actual object-storage code paths.

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

type round2Fixture struct {
	ouActorID     int64 // OU-confined, NO domain: resolver leaves DomainScope unset
	globalActorID int64 // truly global: Help Desk assignment, NULL domain_override
	inDomain      int64
	outDomain     int64
	deptIn        int64
	deptOut       int64
	mbInScope     int64 // owned by user in deptIn
	mbOutScope    int64 // owned by user in deptOut
	distOutScope  int64 // owner-less distribution mailbox in outDomain
}

// round2Fixture seeds the whole round-2 world on the test pool. Every fixture
// name is minted unique per run (random suffix, the shared-DB convention): the
// former fixed round2-in/out domains, /round2-in/out department paths
// (departments_path_key) and 'Round2 OU Probe' role name
// (admin_role_groups_name_key) collided across overlapping runs. Cleanup for
// every created row is registered immediately after its own creation succeeds
// and verifies its error.
func seedRound2Fixture(t *testing.T, pool *pgxpool.Pool) *round2Fixture {
	t.Helper()
	ctx := context.Background()
	suffix := mailboxRandomSuffix(t)

	inDomain := seedScopeFixDomain(t, pool, "round2-in-"+suffix+".example")
	outDomain := seedScopeFixDomain(t, pool, "round2-out-"+suffix+".example")

	seedDept := func(name, path string) int64 {
		t.Helper()
		var id int64
		if err := pool.QueryRow(ctx,
			`INSERT INTO departments (name, path, ldap_ou) VALUES ($1, $2, $3) RETURNING id`,
			name, path, path).Scan(&id); err != nil {
			t.Fatalf("seed department %s: %v", path, err)
		}
		t.Cleanup(func() {
			if _, err := pool.Exec(ctx, `DELETE FROM departments WHERE id = $1`, id); err != nil {
				t.Errorf("cleanup department %s: %v", path, err)
			}
		})
		return id
	}
	deptIn := seedDept("round2-in-"+suffix, "/round2-in-"+suffix)
	deptOut := seedDept("round2-out-"+suffix, "/round2-out-"+suffix)

	userInDept := func(domainID, deptID int64) int64 {
		t.Helper()
		id := createMailboxTestUser(t, pool, domainID)
		if _, err := pool.Exec(ctx,
			`UPDATE users SET department_id = $2 WHERE id = $1`, id, deptID); err != nil {
			t.Fatalf("attach user %d to department %d: %v", id, deptID, err)
		}
		return id
	}

	// OU-only probe role: domain_scope NULL, perms mirroring what the route
	// guards demand (import: users.create; export: mail.export). The name is
	// unique per run — admin_role_groups.name is UNIQUE and the fixed
	// 'Round2 OU Probe' collided across overlapping runs.
	var ouRoleID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO admin_role_groups (name, description, permissions, domain_scope, is_builtin)
		 VALUES ($1, 'round-2 scope-correction fixture', ARRAY['users.create','mail.export'], NULL, false)
		 RETURNING id`, "Round2 OU Probe "+suffix).Scan(&ouRoleID); err != nil {
		t.Fatalf("seed OU probe role: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, `DELETE FROM admin_role_groups WHERE id = $1`, ouRoleID); err != nil {
			t.Errorf("cleanup OU probe role: %v", err)
		}
	})

	var helpDeskID int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM admin_role_groups WHERE name = 'Help Desk' LIMIT 1`,
	).Scan(&helpDeskID); err != nil {
		t.Fatalf("lookup Help Desk role: %v", err)
	}

	assign := func(user, role int64, withOU bool, deptID int64) {
		t.Helper()
		var err error
		if withOU {
			_, err = pool.Exec(ctx,
				`INSERT INTO admin_role_assignments (user_id, role_group_id, scope_type, scope_id, granted_by)
				 VALUES ($1, $2, 'ou', $3, $1)`, user, role, deptID)
		} else {
			_, err = pool.Exec(ctx,
				`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by)
				 VALUES ($1, $2, $1)`, user, role)
		}
		if err != nil {
			t.Fatalf("seed assignment (user=%d role=%d ou=%v): %v", user, role, withOU, err)
		}
		t.Cleanup(func() {
			if _, err := pool.Exec(ctx, `DELETE FROM admin_role_assignments WHERE user_id = $1 AND role_group_id = $2`, user, role); err != nil {
				t.Errorf("cleanup assignment (user=%d role=%d): %v", user, role, err)
			}
		})
	}

	ouActor := userInDept(inDomain, deptIn)
	assign(ouActor, ouRoleID, true, deptIn)

	globalActor := userInDept(inDomain, deptIn)
	assign(globalActor, helpDeskID, false, 0) // NULL domain_override + NULL scope_type = truly global

	ownerIn := userInDept(inDomain, deptIn)
	mbInScope := createPersonalMailbox(t, pool, ownerIn, inDomain)
	ownerOut := userInDept(outDomain, deptOut)
	mbOutScope := createPersonalMailbox(t, pool, ownerOut, outDomain)
	distOutScope := createDistributionMailbox(t, pool, outDomain)

	return &round2Fixture{
		ouActorID: ouActor, globalActorID: globalActor,
		inDomain: inDomain, outDomain: outDomain,
		deptIn: deptIn, deptOut: deptOut,
		mbInScope: mbInScope, mbOutScope: mbOutScope, distOutScope: distOutScope,
	}
}

// round2Claims authenticates as actor holding exactly the route grants (no
// Mail-console umbrella): the handlers must not need it.
func round2Claims(actorID int64) *auth.Claims {
	return &auth.Claims{
		UserID: actorID, IsAdmin: true,
		Permissions: []string{permissions.PermUsersCreate, permissions.PermMailExport},
	}
}

func round2CanReachCtx(t *testing.T, actorID int64) context.Context {
	t.Helper()
	return auth.ContextWithUser(context.Background(), round2Claims(actorID))
}

// round2StubS3 is the ediscovery stub-S3 genre extended with PUT, so a real
// *minio.Client can both upload (import) and fetch (export).
func round2StubS3(t *testing.T) (mc *minio.Client, bucket string) {
	t.Helper()
	return round2StubS3WithHooks(t, round2S3Hooks{})
}

// round2S3Hooks let a test interpose on object traffic — e.g. revoke the
// actor's assignment on the Nth PUT (mid-upload revocation) or Nth GET
// (mid-stream revocation). Hooks run on server goroutines; counters are
// 1-based and serialized.
type round2S3Hooks struct {
	onPut func(n int, key string)
	onGet func(n int, key string)
}

func round2StubS3WithHooks(t *testing.T, hooks round2S3Hooks) (mc *minio.Client, bucket string) {
	t.Helper()
	bucket = "round2-export-bucket"
	var mu sync.Mutex
	putCount, getCount := 0, 0
	objects := map[string][]byte{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/"+bucket+"/")
		switch r.Method {
		case http.MethodPut:
			data, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			mu.Lock()
			objects[key] = data
			mu.Unlock()
			if hooks.onPut != nil {
				mu.Lock()
				n := putCount + 1
				putCount = n
				mu.Unlock()
				hooks.onPut(n, key)
			}
			w.Header().Set("ETag", `"round2-stub-etag"`)
			w.WriteHeader(http.StatusOK)
		default:
			mu.Lock()
			data, ok := objects[key]
			getCount++
			n := getCount
			mu.Unlock()
			if hooks.onGet != nil {
				hooks.onGet(n, key)
			}
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = io.WriteString(w, `<Error><Code>NoSuchKey</Code><Key>`+key+`</Key></Error>`)
				return
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(data)))
			w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(data)
		}
	}))
	t.Cleanup(ts.Close)
	var err error
	mc, err = minio.New(strings.TrimPrefix(ts.URL, "http://"), &minio.Options{
		Creds: credentials.NewStaticV4("test", "test", ""), Secure: false, Region: "us-east-1",
	})
	if err != nil {
		t.Fatalf("minio.New: %v", err)
	}
	return mc, bucket
}

const round2OneMessageMBOX = "From alice@round2-in.example Mon Sep 05 10:00:00 2026\n" +
	"From: alice@round2-in.example\n" +
	"To: bob@round2-in.example\n" +
	"Subject: round2 probe\n" +
	"\n" +
	"round2 probe body\n"

func round2ImportBody(t *testing.T, mbox string) (*bytes.Buffer, string) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("file", "import.mbox")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := fw.Write([]byte(mbox)); err != nil {
		t.Fatalf("write form file: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	return &body, mw.FormDataContentType()
}

// H1: an OU-only/no-domain assignment is NOT global authority — with no
// DomainScope in context (exactly what the removed scope==0 shortcut trusted),
// an out-of-OU owned mailbox must still be denied by admin_can_reach.
func TestRound2OUOnlyAdminNotGlobalAuthority(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedRound2Fixture(t, pool)

	ctx := round2CanReachCtx(t, st.ouActorID) // no DomainScope in context

	t.Run("seam denies out-of-OU owned mailbox with scope==0 context", func(t *testing.T) {
		err := canReachMailbox(ctx, pool, st.mbOutScope)
		if err == nil || !strings.Contains(err.Error(), "not within your administrative scope") {
			t.Fatalf("out-of-OU owned mailbox: want out-of-scope denial, got %v", err)
		}
	})

	t.Run("route-level Export denies out-of-OU owned mailbox → 403", func(t *testing.T) {
		h := NewImportExportHandler(nil, pgxutil.WorkerPool{Pool: pool}, "", testsupport.TestLogger())
		req := httptest.NewRequest(http.MethodGet,
			"/admin/mailboxes/"+strconv.FormatInt(st.mbOutScope, 10)+"/export", nil)
		req.SetPathValue("id", strconv.FormatInt(st.mbOutScope, 10))
		w := httptest.NewRecorder()
		h.Export(w, req.WithContext(ctx))
		if w.Code != http.StatusForbidden {
			t.Fatalf("Export out-of-OU: want 403, got %d (body=%s)", w.Code, w.Body.String())
		}
	})

	t.Run("in-OU owned mailbox still allowed", func(t *testing.T) {
		if err := canReachMailbox(ctx, pool, st.mbInScope); err != nil {
			t.Fatalf("in-OU owned mailbox: want nil, got %v", err)
		}
	})
}

// H1 positive arm: a TRULY global admin (active assignment, NULL domain,
// NULL scope_type) passes admin_can_reach for every owned mailbox with no
// domain scope in context — authority comes from the DB, not the context.
func TestRound2TrulyGlobalAdminAllowed(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedRound2Fixture(t, pool)

	ctx := round2CanReachCtx(t, st.globalActorID)
	if err := canReachMailbox(ctx, pool, st.mbOutScope); err != nil {
		t.Fatalf("global admin out-of-domain owned mailbox: want nil, got %v", err)
	}
	// Owner-less distribution mailbox: DB-resolved global arm (no context scope).
	if err := canReachMailbox(ctx, pool, st.distOutScope); err != nil {
		t.Fatalf("global admin owner-less out-of-domain mailbox: want nil, got %v", err)
	}
}

// H2: the export route guard is the dedicated mail.export permission — the
// broad Mail-console umbrella (domains.read etc.) no longer suffices, while
// mail.export passes through to the handler.
func TestRound2ExportRouteGuardRequiresMailExport(t *testing.T) {
	var hits int
	guard := middleware.RequirePermAudited(permissions.PermMailExport, func(context.Context, middleware.AuditEvent) {})
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits++; w.WriteHeader(http.StatusOK) })

	request := func(perms ...string) int {
		t.Helper()
		hits = 0
		req := httptest.NewRequest(http.MethodGet, "/admin/mailboxes/1/export", nil)
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
			UserID: 1, IsAdmin: true, Permissions: perms,
		}))
		w := httptest.NewRecorder()
		guard(next).ServeHTTP(w, req)
		return w.Code
	}

	if code := request(permissions.PermUsersCreate); code != http.StatusForbidden || hits != 0 {
		t.Fatalf("users.create only: want 403 and handler unreachable, got %d hits=%d", code, hits)
	}
	// Former broad guard: a Mail-console read permission must NOT open export.
	if code := request(permissions.PermDomainsRead, permissions.PermUsersCreate); code != http.StatusForbidden || hits != 0 {
		t.Fatalf("Mail-console read only: want 403 and handler unreachable, got %d hits=%d", code, hits)
	}
	if code := request(permissions.PermUsersCreate, permissions.PermMailExport); code != http.StatusOK || hits != 1 {
		t.Fatalf("mail.export: want 200 and handler reached once, got %d hits=%d", code, hits)
	}
}

// H4: a caller WITH mail.export, in scope, completes a real NONEMPTY import
// (reducer insert + object upload) AND export (streamed ZIP round-trip).
func TestRound2InScopeImportExportWithMailExport(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedRound2Fixture(t, pool)
	mc, bucket := round2StubS3(t)
	h := NewImportExportHandler(mc, pgxutil.WorkerPool{Pool: pool}, bucket, testsupport.TestLogger())

	// Import one real message into the in-OU mailbox as the OU-only actor.
	body, contentType := round2ImportBody(t, round2OneMessageMBOX)
	req := httptest.NewRequest(http.MethodPost,
		"/admin/mailboxes/"+strconv.FormatInt(st.mbInScope, 10)+"/import", bytes.NewReader(body.Bytes()))
	req.SetPathValue("id", strconv.FormatInt(st.mbInScope, 10))
	req.Header.Set("Content-Type", contentType)
	w := httptest.NewRecorder()
	h.Import(w, req.WithContext(round2CanReachCtx(t, st.ouActorID)))
	if w.Code != http.StatusOK {
		t.Fatalf("Import: want 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"imported":1`) || strings.Contains(w.Body.String(), `"failed":1`) {
		t.Fatalf("Import body = %s, want imported:1 with no failures", w.Body.String())
	}

	// Export the same mailbox: a ZIP with exactly the imported message.
	req = httptest.NewRequest(http.MethodGet,
		"/admin/mailboxes/"+strconv.FormatInt(st.mbInScope, 10)+"/export", nil)
	req.SetPathValue("id", strconv.FormatInt(st.mbInScope, 10))
	w = httptest.NewRecorder()
	h.Export(w, req.WithContext(round2CanReachCtx(t, st.ouActorID)))
	if w.Code != http.StatusOK {
		t.Fatalf("Export: want 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/zip" {
		t.Fatalf("Export content type = %q, want application/zip", ct)
	}
	zr, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if err != nil {
		t.Fatalf("Export produced unreadable ZIP: %v", err)
	}
	if len(zr.File) != 1 {
		t.Fatalf("Export ZIP entries = %d, want 1 (nonempty export)", len(zr.File))
	}
	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatalf("open ZIP entry: %v", err)
	}
	defer rc.Close()
	entry, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read ZIP entry: %v", err)
	}
	if !strings.Contains(string(entry), "Subject: round2 probe") {
		t.Errorf("Exported EML missing imported subject; got:\n%s", entry)
	}
}

// H5: post-authentication revocation — expiring the assignment between
// requests denies the next request; authority is re-resolved per request.
func TestRound2PostAuthRevocationDenied(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedRound2Fixture(t, pool)

	if err := canReachMailbox(round2CanReachCtx(t, st.ouActorID), pool, st.mbInScope); err != nil {
		t.Fatalf("pre-revocation in-OU reach: want nil, got %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`UPDATE admin_role_assignments SET expires_at = now() - interval '1 second'
		 WHERE user_id = $1`, st.ouActorID); err != nil {
		t.Fatalf("expire OU assignment: %v", err)
	}
	if err := canReachMailbox(round2CanReachCtx(t, st.ouActorID), pool, st.mbInScope); err == nil {
		t.Fatal("post-revocation in-OU reach: want denial, got nil")
	}

	// Same for the truly global actor: revoking its only assignment removes
	// even global authority on the next request.
	if err := canReachMailbox(round2CanReachCtx(t, st.globalActorID), pool, st.mbOutScope); err != nil {
		t.Fatalf("pre-revocation global reach: want nil, got %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`UPDATE admin_role_assignments SET expires_at = now() - interval '1 second'
		 WHERE user_id = $1`, st.globalActorID); err != nil {
		t.Fatalf("expire global assignment: %v", err)
	}
	if err := canReachMailbox(round2CanReachCtx(t, st.globalActorID), pool, st.mbOutScope); err == nil {
		t.Fatal("post-revocation global reach: want denial, got nil")
	}
}

// ── Round 3: authorization lives INSIDE the data statements ─────────────────
// Astra HOLD: the route seam finished before the upload was read, so a
// revocation during a slow multipart import did not stop subsequent inserts,
// and the export SELECT carried no actor-authority predicate at all. The fix:
// import_message evaluates admin_can_reach_mailbox in its INSERT's WHERE (a
// revoked actor yields zero inserted rows, reported failed), and the export
// query applies the same predicate plus a per-batch stream re-check. The Go
// seam is fast-path UX; the statement is the authority.

// round3Mbox builds an n-message MBOX with distinct subjects.
func round3Mbox(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "From alice@round2-in.example Mon Sep 05 10:00:00 2026\n")
		fmt.Fprintf(&b, "From: alice@round2-in.example\nTo: bob@round2-in.example\nSubject: round3 msg %d\n\nround3 body %d\n", i, i)
	}
	return b.String()
}

// round3Revoke expires every assignment of the actor — the same revocation
// primitive the r2 H5 test uses.
func round3Revoke(t *testing.T, pool *pgxpool.Pool, actorID int64) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`UPDATE admin_role_assignments SET expires_at = now() - interval '1 second'
		 WHERE user_id = $1`, actorID); err != nil {
		t.Fatalf("revoke actor %d: %v", actorID, err)
	}
}

func round3MessageCount(t *testing.T, pool *pgxpool.Pool, mbID int64) int64 {
	t.Helper()
	var n int64
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM messages WHERE mailbox_id = $1`, mbID).Scan(&n); err != nil {
		t.Fatalf("count messages in mailbox %d: %v", mbID, err)
	}
	return n
}

// Round-3 test 1: revocation MID-UPLOAD. The stub S3 revokes the actor's
// assignment on the 3rd PUT (each message uploads before its insert), i.e.
// between inserts. Every subsequent insert must no-op to ZERO new rows via the
// reducer's statement predicate and be reported in the failed list.
func TestRound3ImportRevokedMidUploadInsertsNoRows(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedRound2Fixture(t, pool)
	var revoked atomic.Bool
	mc, bucket := round2StubS3WithHooks(t, round2S3Hooks{
		onPut: func(n int, _ string) {
			if n == 3 { // messages 1-2 inserted; revoke before message 3's insert
				round3Revoke(t, pool, st.ouActorID)
				revoked.Store(true)
			}
		},
	})
	h := NewImportExportHandler(mc, pgxutil.WorkerPool{Pool: pool}, bucket, testsupport.TestLogger())

	body, contentType := round2ImportBody(t, round3Mbox(6))
	req := httptest.NewRequest(http.MethodPost,
		"/admin/mailboxes/"+strconv.FormatInt(st.mbInScope, 10)+"/import", bytes.NewReader(body.Bytes()))
	req.SetPathValue("id", strconv.FormatInt(st.mbInScope, 10))
	req.Header.Set("Content-Type", contentType)
	w := httptest.NewRecorder()
	h.Import(w, req.WithContext(round2CanReachCtx(t, st.ouActorID)))
	if w.Code != http.StatusOK {
		t.Fatalf("Import: want 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	if !revoked.Load() {
		t.Fatal("test wiring: revocation hook never fired")
	}

	var resp struct {
		Imported int              `json:"imported"`
		Failed   []map[string]any `json:"failed"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode import response %q: %v", w.Body.String(), err)
	}
	if resp.Imported != 2 || len(resp.Failed) != 4 {
		t.Fatalf("imported=%d failed=%d, want imported=2 (pre-revocation) failed=4 (post-revocation); body=%s",
			resp.Imported, len(resp.Failed), w.Body.String())
	}
	for _, f := range resp.Failed {
		errText, _ := f["error"].(string)
		if !strings.Contains(errText, "revoked") {
			t.Fatalf("post-revocation failure entry %v must name the revocation, got %q", f, errText)
		}
	}
	if got := round3MessageCount(t, pool, st.mbInScope); got != 2 {
		t.Fatalf("messages in mailbox = %d, want 2 — the revoked authority must insert ZERO new rows", got)
	}
}

// Round-3 test 2a: EXPORT QUERY-level authority. After revocation the exact
// predicate the export SELECT carries (admin_can_reach_mailbox) answers FALSE,
// so a revocation between the route seam and the query empties the row set at
// the query level.
func TestRound3ExportPredicateFlipsAfterRevocation(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedRound2Fixture(t, pool)
	ctx := round2CanReachCtx(t, st.ouActorID)
	scope := middleware.DomainScopeFromContext(ctx)

	var before bool
	if err := pool.QueryRow(context.Background(),
		`SELECT admin_can_reach_mailbox($1, $2, $3)`, st.ouActorID, scope, st.mbInScope).Scan(&before); err != nil {
		t.Fatalf("admin_can_reach_mailbox pre-revocation: %v", err)
	}
	if !before {
		t.Fatal("pre-revocation predicate must be TRUE for the in-OU mailbox")
	}
	round3Revoke(t, pool, st.ouActorID)
	var after bool
	if err := pool.QueryRow(context.Background(),
		`SELECT admin_can_reach_mailbox($1, $2, $3)`, st.ouActorID, scope, st.mbInScope).Scan(&after); err != nil {
		t.Fatalf("admin_can_reach_mailbox post-revocation: %v", err)
	}
	if after {
		t.Fatal("post-revocation export predicate must be FALSE — the query must stop rows")
	}
}

// Round-3 test 2b: EXPORT MID-STREAM revocation. Four messages are exported;
// the stub S3 revokes the actor after serving the first object, and the
// per-batch re-validation (interval forced to 1) must stop the stream instead
// of serving the remaining three messages.
func TestRound3ExportRevokedMidStreamStops(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedRound2Fixture(t, pool)
	mc, bucket := round2StubS3WithHooks(t, round2S3Hooks{
		onGet: func(n int, _ string) {
			if n == 1 { // first message served; revoke before the next re-check
				round3Revoke(t, pool, st.ouActorID)
			}
		},
	})
	h := NewImportExportHandler(mc, pgxutil.WorkerPool{Pool: pool}, bucket, testsupport.TestLogger())

	// Authorized: import four real messages.
	body, contentType := round2ImportBody(t, round3Mbox(4))
	req := httptest.NewRequest(http.MethodPost,
		"/admin/mailboxes/"+strconv.FormatInt(st.mbInScope, 10)+"/import", bytes.NewReader(body.Bytes()))
	req.SetPathValue("id", strconv.FormatInt(st.mbInScope, 10))
	req.Header.Set("Content-Type", contentType)
	w := httptest.NewRecorder()
	h.Import(w, req.WithContext(round2CanReachCtx(t, st.ouActorID)))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"imported":4`) {
		t.Fatalf("pre-revocation import: want 200/imported:4, got %d (body=%s)", w.Code, w.Body.String())
	}

	oldEvery := mailboxExportRecheckEvery
	mailboxExportRecheckEvery = 1 // re-validate reach before every streamed message
	t.Cleanup(func() { mailboxExportRecheckEvery = oldEvery })

	req = httptest.NewRequest(http.MethodGet,
		"/admin/mailboxes/"+strconv.FormatInt(st.mbInScope, 10)+"/export", nil)
	req.SetPathValue("id", strconv.FormatInt(st.mbInScope, 10))
	w = httptest.NewRecorder()
	h.Export(w, req.WithContext(round2CanReachCtx(t, st.ouActorID)))
	if w.Code != http.StatusOK {
		t.Fatalf("Export: want 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	zr, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if err != nil {
		t.Fatalf("Export produced unreadable ZIP: %v", err)
	}
	if len(zr.File) != 1 {
		t.Fatalf("mid-stream revocation: ZIP entries = %d, want 1 (stream must stop after the first message)", len(zr.File))
	}
	if got := round3MessageCount(t, pool, st.mbInScope); got != 4 {
		t.Fatalf("export must not mutate data: messages = %d, want 4", got)
	}
}
