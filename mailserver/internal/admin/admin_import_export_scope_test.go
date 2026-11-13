package admin

// DB-backed TDD for the admin domain-scope seam on mailbox import/export
// (D-MAILSERVER-INTERNAL-ADMIN-F-001): before this fix neither handler checked
// admin_can_reach or DomainScopeFromContext, so any Mail-console admin could
// import into / export any mailbox id on the BYPASSRLS worker pool.
//
// Style mirrors the sibling seam test (admin_spam_scope_test.go) and reuses the
// mailbox fixtures (admin_mailboxes_test.go):
//
//	actor (actorID):    admin user in the IN domain; DB-resolved assignment
//	                    carries domain_override=IN, so admin_can_reach has real
//	                    authority to decide (active row; rbac.jit defaults OFF).
//	mbInScope:          mailbox owned by a user in the IN domain.
//	mbOutScope:         mailbox owned by a user in the OUT domain.
//
// The per-request domain scope is injected into the request context exactly the
// way middleware/console_guard.go does in production. minio stays nil: denied
// requests must not reach data access, and passing requests use 0-message
// bodies so no object storage is ever touched (a nil-pointer panic would fail
// the test loudly if the seam were skipped).

import (
	"bytes"
	"context"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

const (
	scopeFixInDomainName  = "scope-fix-in.example"
	scopeFixOutDomainName = "scope-fix-out.example"
)

type mailboxScopeFixture struct {
	actorID       int64
	globalActorID int64 // truly global: Help Desk assignment with NULL domain_override
	inDomain      int64
	outDomain     int64
	mbInScope     int64
	mbOutScope    int64
}

func seedScopeFixDomain(t *testing.T, pool *pgxpool.Pool, name string) int64 {
	t.Helper()
	var id int64
	err := pool.QueryRow(context.Background(),
		`INSERT INTO domains (name) VALUES ($1)
		 ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
		 RETURNING id`, name).Scan(&id)
	if err != nil {
		t.Fatalf("seed domain %s: %v", name, err)
	}
	// Registered first → runs last (LIFO), after the users/mailboxes seeded
	// inside these domains have been cleaned up.
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM domains WHERE id = $1`, id); err != nil {
			t.Errorf("cleanup scope-fixture domain %s: %v", name, err)
		}
	})
	return id
}

func seedMailboxScopeFixture(t *testing.T, pool *pgxpool.Pool) *mailboxScopeFixture {
	t.Helper()
	inDomain := seedScopeFixDomain(t, pool, scopeFixInDomainName)
	outDomain := seedScopeFixDomain(t, pool, scopeFixOutDomainName)

	actor := createMailboxTestUser(t, pool, inDomain)
	var helpDeskID int64
	if err := pool.QueryRow(context.Background(),
		`SELECT id FROM admin_role_groups WHERE name = 'Help Desk' LIMIT 1`,
	).Scan(&helpDeskID); err != nil {
		t.Fatalf("lookup Help Desk role: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO admin_role_assignments (user_id, role_group_id, domain_override, granted_by)
		 VALUES ($1, $2, $3, $1)
		 ON CONFLICT (user_id, role_group_id) DO UPDATE SET domain_override = EXCLUDED.domain_override`,
		actor, helpDeskID, inDomain); err != nil {
		t.Fatalf("seed actor assignment: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM admin_role_assignments WHERE user_id = $1`, actor) // nolint:errcheck
	})

	// Truly global actor: Help Desk (domain_scope NULL) with NULL
	// domain_override and NULL scope_type — admin_can_reach covers every
	// owned target for this caller. Round 2: context scope 0 alone is NOT
	// global authority, so the global-path subtests use THIS actor.
	globalActor := createMailboxTestUser(t, pool, inDomain)
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by)
		 VALUES ($1, $2, $1)
		 ON CONFLICT (user_id, role_group_id) DO NOTHING`,
		globalActor, helpDeskID); err != nil {
		t.Fatalf("seed global actor assignment: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM admin_role_assignments WHERE user_id = $1`, globalActor) // nolint:errcheck
	})

	ownerIn := createMailboxTestUser(t, pool, inDomain)
	mbInScope := createPersonalMailbox(t, pool, ownerIn, inDomain)
	ownerOut := createMailboxTestUser(t, pool, outDomain)
	mbOutScope := createPersonalMailbox(t, pool, ownerOut, outDomain)

	return &mailboxScopeFixture{
		actorID: actor, globalActorID: globalActor,
		inDomain: inDomain, outDomain: outDomain,
		mbInScope: mbInScope, mbOutScope: mbOutScope,
	}
}

// scopeFixRequest builds a request authenticated as actor with an optional
// domain scope (0 = global-scope admin, no scope in context).
func scopeFixRequest(t *testing.T, method, path string, body *bytes.Buffer, mbID, actor int64, scope int64) *http.Request {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		rdr = bytes.NewReader(body.Bytes())
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.SetPathValue("id", strconv.FormatInt(mbID, 10))
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID: actor, IsAdmin: true, Permissions: permissions.AllPermissions,
	})
	if scope != 0 {
		ctx = middleware.ContextWithDomainScope(ctx, scope)
	}
	return req.WithContext(ctx)
}

func scopeFixImportBody(t *testing.T, mbox string) (*bytes.Buffer, string) {
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

// One-message MBOX: if a denied import ever reached data access, importRawMessage
// would call PutObject on the nil minio client and panic the test.
const scopeFixOneMessageMBOX = "From alice@scope-fix-in.example Mon Sep 05 10:00:00 2026\n" +
	"From: alice@scope-fix-in.example\n" +
	"To: bob@scope-fix-in.example\n" +
	"Subject: scope probe\n" +
	"\n" +
	"probe body\n"

const scopeFixEmptyMBOX = "   \n  \n"

func TestImportExportMailboxScope(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedMailboxScopeFixture(t, pool)
	h := NewImportExportHandler(nil, pgxutil.WorkerPool{Pool: pool}, "", testsupport.TestLogger())

	t.Run("Export/out-of-scope mailbox → 403, zero rows streamed", func(t *testing.T) {
		req := scopeFixRequest(t, http.MethodGet,
			"/admin/mailboxes/"+strconv.FormatInt(st.mbOutScope, 10)+"/export", nil,
			st.mbOutScope, st.actorID, st.inDomain)
		w := httptest.NewRecorder()
		h.Export(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("Export out-of-scope: want 403, got %d (body=%s)", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "target mailbox not within your administrative scope") {
			t.Errorf("Export out-of-scope: want sibling seam wording, got body=%s", w.Body.String())
		}
		if strings.Contains(w.Body.String(), "From ") || strings.Contains(w.Header().Get("Content-Type"), "zip") {
			t.Errorf("Export out-of-scope streamed rows: body=%q content-type=%q", w.Body.String(), w.Header().Get("Content-Type"))
		}
	})

	t.Run("Export/in-scope mailbox → 200 (unchanged)", func(t *testing.T) {
		req := scopeFixRequest(t, http.MethodGet,
			"/admin/mailboxes/"+strconv.FormatInt(st.mbInScope, 10)+"/export", nil,
			st.mbInScope, st.actorID, st.inDomain)
		w := httptest.NewRecorder()
		h.Export(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("Export in-scope: want 200, got %d (body=%s)", w.Code, w.Body.String())
		}
		if ct := w.Header().Get("Content-Type"); ct != "application/zip" {
			t.Errorf("Export in-scope content type = %q, want application/zip (stream reached)", ct)
		}
	})

	t.Run("Import/out-of-scope mailbox → 403 before any insert", func(t *testing.T) {
		var before int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM messages WHERE mailbox_id = $1`, st.mbOutScope).Scan(&before); err != nil {
			t.Fatalf("count before: %v", err)
		}
		body, contentType := scopeFixImportBody(t, scopeFixOneMessageMBOX)
		req := scopeFixRequest(t, http.MethodPost,
			"/admin/mailboxes/"+strconv.FormatInt(st.mbOutScope, 10)+"/import", body,
			st.mbOutScope, st.actorID, st.inDomain)
		req.Header.Set("Content-Type", contentType)
		w := httptest.NewRecorder()
		h.Import(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("Import out-of-scope: want 403, got %d (body=%s)", w.Code, w.Body.String())
		}
		var after int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM messages WHERE mailbox_id = $1`, st.mbOutScope).Scan(&after); err != nil {
			t.Fatalf("count after: %v", err)
		}
		if after != before {
			t.Errorf("Import out-of-scope inserted rows: before=%d after=%d", before, after)
		}
	})

	t.Run("Truly global admin passes on both", func(t *testing.T) {
		// Round 2: global authority is DB-resolved (the domain_override=IN
		// actor is NOT global just because no DomainScope is in context), so
		// this path uses the fixture's genuinely global actor.
		// Import: empty mbox → 0 messages, never touches the nil minio client;
		// a seam regression would 403 here.
		body, contentType := scopeFixImportBody(t, scopeFixEmptyMBOX)
		req := scopeFixRequest(t, http.MethodPost,
			"/admin/mailboxes/"+strconv.FormatInt(st.mbOutScope, 10)+"/import", body,
			st.mbOutScope, st.globalActorID, 0)
		req.Header.Set("Content-Type", contentType)
		w := httptest.NewRecorder()
		h.Import(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("Import global admin: want 200, got %d (body=%s)", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), `"imported":0`) {
			t.Errorf("Import global admin body = %s, want imported:0", w.Body.String())
		}

		req = scopeFixRequest(t, http.MethodGet,
			"/admin/mailboxes/"+strconv.FormatInt(st.mbOutScope, 10)+"/export", nil,
			st.mbOutScope, st.globalActorID, 0)
		w = httptest.NewRecorder()
		h.Export(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("Export global admin: want 200, got %d (body=%s)", w.Code, w.Body.String())
		}
	})
}

func TestCanReachMailboxDecision(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedMailboxScopeFixture(t, pool)

	scopedCtx := func() context.Context {
		ctx := auth.ContextWithUser(context.Background(), &auth.Claims{
			UserID: st.actorID, IsAdmin: true, Permissions: permissions.AllPermissions,
		})
		return middleware.ContextWithDomainScope(ctx, st.inDomain)
	}()

	t.Run("truly global actor passes owned out-of-scope mailbox via admin_can_reach", func(t *testing.T) {
		// Round 2: there is no scope==0 shortcut — a genuinely global caller
		// (NULL domain_override, NULL scope_type) is allowed BECAUSE
		// admin_can_reach says so, for every owned mailbox.
		ctx := auth.ContextWithUser(context.Background(), &auth.Claims{UserID: st.globalActorID, IsAdmin: true})
		if err := canReachMailbox(ctx, pool, st.mbOutScope); err != nil {
			t.Fatalf("global admin on out-of-scope mailbox: want nil, got %v", err)
		}
	})

	t.Run("domain-scoped actor without context scope is NOT global (round-2 HOLD)", func(t *testing.T) {
		// The domain_override=IN actor with no DomainScope in context must now
		// be denied on the out-of-domain owned mailbox — the removed
		// scope==0 shortcut would have let them through.
		ctx := auth.ContextWithUser(context.Background(), &auth.Claims{UserID: st.actorID, IsAdmin: true})
		if err := canReachMailbox(ctx, pool, st.mbOutScope); !errors.Is(err, errMailboxOutOfScope) {
			t.Fatalf("domain-scoped actor sans context scope: want errMailboxOutOfScope, got %v", err)
		}
	})

	t.Run("user-owned mailbox within admin_can_reach → allow", func(t *testing.T) {
		if err := canReachMailbox(scopedCtx, pool, st.mbInScope); err != nil {
			t.Fatalf("in-domain mailbox: want nil, got %v", err)
		}
	})

	t.Run("owner-less mailbox matched by domain scope → allow", func(t *testing.T) {
		mbDist := createDistributionMailbox(t, pool, st.inDomain)
		if err := canReachMailbox(scopedCtx, pool, mbDist); err != nil {
			t.Fatalf("distribution mailbox in domain scope: want nil, got %v", err)
		}
	})

	t.Run("out-of-domain mailbox → deny", func(t *testing.T) {
		if err := canReachMailbox(scopedCtx, pool, st.mbOutScope); !errors.Is(err, errMailboxOutOfScope) {
			t.Fatalf("out-of-domain mailbox: want errMailboxOutOfScope, got %v", err)
		}
	})

	t.Run("unknown mailbox → fail closed without existence oracle wording", func(t *testing.T) {
		err := canReachMailbox(scopedCtx, pool, 987654321)
		if !errors.Is(err, errMailboxNotFound) {
			t.Fatalf("unknown mailbox: want errMailboxNotFound, got %v", err)
		}
	})

	t.Run("no auth claims → fail closed", func(t *testing.T) {
		if err := canReachMailbox(context.Background(), pool, st.mbInScope); !errors.Is(err, errMailboxOutOfScope) {
			t.Fatalf("claims-less context: want errMailboxOutOfScope, got %v", err)
		}
	})
}
