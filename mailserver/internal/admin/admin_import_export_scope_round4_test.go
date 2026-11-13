package admin

// Round-4 admin-scope correction tests (Astra r13 HOLD):
//
//	H1. The owner-less arm of the statement-level predicate
//	    (admin_can_reach_mailbox) accepted the request-carried p_domain_scope
//	    without checking the actor STILL held authority, so revoking the
//	    assignment mid-session did not stop owner-less imports/exports. The arm
//	    now re-resolves LIVE authority: the actor's current effective authority
//	    (admin_effective_authority) must still return the mailbox domain as its
//	    broadest scope.
//	H1b. The DB-resolved genuinely-global fallback is canReachMailbox-exact:
//	    it applies ONLY when no domain scope is in context; a non-matching
//	    context scope denies even a genuinely-global actor (the old fallback
//	    was unconditional).
//
// Round 6 (Astra r5 HOLD): the owner-less arm must anchor LIVE authority to
// the MAILBOX'S OWN domain (a.scope = mb.domain_id), never to the claimed
// context scope — a domain-A actor must not pass for an owner-less domain-B
// mailbox, and the export mid-stream re-check must consult the same live
// authority instead of the cached-domain allow arm.
//
// Fixtures reuse the round-2 world (real rows so admin_effective_authority has
// genuine authority to decide) plus a domain-scoped actor over the out domain.

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// seedRound4DomainActor creates an actor whose ONLY authority is a Help Desk
// assignment with domain_override = outDomain (effective scope exactly
// outDomain) and returns (actorID, context with that DomainScope).
func seedRound4DomainActor(t *testing.T, pool *pgxpool.Pool, outDomain int64) (int64, context.Context) {
	t.Helper()
	ctx := context.Background()
	actor := createMailboxTestUser(t, pool, outDomain)
	var helpDeskID int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM admin_role_groups WHERE name = 'Help Desk' LIMIT 1`,
	).Scan(&helpDeskID); err != nil {
		t.Fatalf("lookup Help Desk role: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO admin_role_assignments (user_id, role_group_id, domain_override, granted_by)
		 VALUES ($1, $2, $3, $1)`, actor, helpDeskID, outDomain); err != nil {
		t.Fatalf("seed round-4 domain actor: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM admin_role_assignments WHERE user_id = $1`, actor) // nolint:errcheck
	})
	reqCtx := auth.ContextWithUser(context.Background(), &auth.Claims{
		UserID: actor, IsAdmin: true,
	})
	return actor, middleware.ContextWithDomainScope(reqCtx, outDomain)
}

// round4Reach queries the exact statement-level predicate the import INSERT's
// WHERE and the export SELECT carry.
func round4Reach(t *testing.T, pool *pgxpool.Pool, actor, scope, mbID int64) bool {
	t.Helper()
	var ok bool
	if err := pool.QueryRow(context.Background(),
		`SELECT admin_can_reach_mailbox($1, $2, $3)`, actor, scope, mbID).Scan(&ok); err != nil {
		t.Fatalf("admin_can_reach_mailbox: %v", err)
	}
	return ok
}

// H1 (required assertion): owner-less distribution mailbox, domain-scoped
// actor — the domain arm admits while the assignment is live, and the SAME
// call denies after a mid-session revocation. Before round 4 the arm trusted
// the cached p_domain_scope and kept admitting through exactly this window.
func TestRound4OwnerlessDomainArmRevokedMidSession(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedRound2Fixture(t, pool)
	actor, ctx := seedRound4DomainActor(t, pool, st.outDomain)

	if err := canReachMailbox(ctx, pool, st.distOutScope); err != nil {
		t.Fatalf("pre-revocation seam: want nil, got %v", err)
	}
	if !round4Reach(t, pool, actor, st.outDomain, st.distOutScope) {
		t.Fatal("pre-revocation statement predicate must be TRUE for the in-domain owner-less mailbox")
	}

	round3Revoke(t, pool, actor)

	// The statement predicate is the authority: after the mid-session
	// revocation the exact owner-less domain-arm call that passed above denies.
	// (The Go seam's owner-less arm consults the same LIVE mailbox-own-domain
	// authority since round 6, so the fast path flips here too — the seam and
	// the statement predicate now agree in both directions.)
	if round4Reach(t, pool, actor, st.outDomain, st.distOutScope) {
		t.Fatal("post-revocation statement predicate must be FALSE — live authority is gone")
	}
	if err := canReachMailbox(ctx, pool, st.distOutScope); err == nil {
		t.Fatal("post-revocation Go seam must deny — live mailbox-domain authority is gone")
	}
}

// H1 end-to-end: an import into the owner-less mailbox whose authority is
// revoked while the upload runs inserts ZERO rows and reports every message
// failed with the revocation wording (the seam passed pre-revocation; the
// statement predicate is the authority).
func TestRound4OwnerlessImportRevokedMidUpload(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedRound2Fixture(t, pool)
	actor, ctx := seedRound4DomainActor(t, pool, st.outDomain)

	var revoked atomic.Bool
	mc, bucket := round2StubS3WithHooks(t, round2S3Hooks{
		onPut: func(n int, _ string) {
			if n == 1 { // revoke before the first message's statement predicate runs
				round3Revoke(t, pool, actor)
				revoked.Store(true)
			}
		},
	})
	h := NewImportExportHandler(mc, pgxutil.WorkerPool{Pool: pool}, bucket, testsupport.TestLogger())

	body, contentType := round2ImportBody(t, round3Mbox(3))
	req := httptest.NewRequest(http.MethodPost,
		"/admin/mailboxes/"+strconv.FormatInt(st.distOutScope, 10)+"/import", bytes.NewReader(body.Bytes()))
	req.SetPathValue("id", strconv.FormatInt(st.distOutScope, 10))
	req.Header.Set("Content-Type", contentType)
	w := httptest.NewRecorder()
	h.Import(w, req.WithContext(ctx))
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
	if resp.Imported != 0 || len(resp.Failed) != 3 {
		t.Fatalf("imported=%d failed=%d, want imported=0 failed=3 (owner-less arm must re-check LIVE authority); body=%s",
			resp.Imported, len(resp.Failed), w.Body.String())
	}
	for _, f := range resp.Failed {
		errText, _ := f["error"].(string)
		if !strings.Contains(errText, "revoked") {
			t.Fatalf("failure entry %v must name the revocation, got %q", f, errText)
		}
	}
	if got := round3MessageCount(t, pool, st.distOutScope); got != 0 {
		t.Fatalf("messages in owner-less mailbox = %d, want 0 — revoked authority must insert no rows", got)
	}
}

// H1b: the genuinely-global fallback is canReachMailbox-exact — with a
// non-matching context scope even a truly global actor is denied; with no
// context scope the LIVE DB-resolved global authority admits. Round-6 (Astra
// r5) correction: the non-matching scope must be genuinely different from the
// mailbox's OWN domain — the pre-fix call passed st.outDomain, which IS
// distOutScope's own domain, so it asserted the denial for the wrong reason.
func TestRound4OwnerlessGlobalFallbackExact(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedRound2Fixture(t, pool)

	if round4Reach(t, pool, st.globalActorID, st.inDomain, st.distOutScope) {
		t.Fatal("non-matching context scope must deny the owner-less mailbox even for a global actor")
	}
	if !round4Reach(t, pool, st.globalActorID, 0, st.distOutScope) {
		t.Fatal("no context scope: live genuinely-global authority must admit the owner-less mailbox")
	}
	globalCtx := round2CanReachCtx(t, st.globalActorID)
	if err := canReachMailbox(globalCtx, pool, st.distOutScope); err != nil {
		t.Fatalf("global actor, no context scope: want nil, got %v", err)
	}
}

// ── Round 6 (Astra r5 HOLD) ─────────────────────────────────────────────────
// The owner-less arm anchored LIVE authority to the CLAIMED context scope
// (a.scope = p_domain_scope) instead of the MAILBOX'S OWN domain, so an actor
// scoped to domain A was admitted for an owner-less mailbox in domain B, and
// the export per-batch re-check reused canReachMailbox's cached-domain allow
// arm to keep owner-less exports streaming after revocation.

// Wrong-domain owner-less denial: an actor whose ONLY live authority is the IN
// domain, claiming exactly that scope in context, must not reach the
// owner-less distribution mailbox in the OUT domain — statement predicate and
// Go seam both deny. Before round 6 the statement predicate admitted exactly
// this caller (its live authority matched its own claim; the mailbox's domain
// was never consulted).
func TestRound6OwnerlessWrongDomainDenied(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedRound2Fixture(t, pool)
	actor, ctx := seedRound4DomainActor(t, pool, st.inDomain)

	if round4Reach(t, pool, actor, st.inDomain, st.distOutScope) {
		t.Fatal("domain-A live authority must not reach an owner-less mailbox in domain B (predicate)")
	}
	if err := canReachMailbox(ctx, pool, st.distOutScope); err == nil {
		t.Fatal("domain-A live authority must not reach an owner-less mailbox in domain B (seam)")
	}
}

// Owner-less mid-stream revocation denial: an export of the owner-less
// mailbox whose per-batch re-check used the cached-domain allow arm kept
// streaming after revocation; the re-check must consult LIVE mailbox-domain
// authority and stop the stream.
func TestRound6OwnerlessExportRevokedMidStreamStops(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedRound2Fixture(t, pool)
	actor, ctx := seedRound4DomainActor(t, pool, st.outDomain)
	mc, bucket := round2StubS3WithHooks(t, round2S3Hooks{
		onGet: func(n int, _ string) {
			if n == 1 { // first message served; revoke before the next re-check
				round3Revoke(t, pool, actor)
			}
		},
	})
	h := NewImportExportHandler(mc, pgxutil.WorkerPool{Pool: pool}, bucket, testsupport.TestLogger())

	// Authorized: import four real messages into the owner-less mailbox.
	body, contentType := round2ImportBody(t, round3Mbox(4))
	req := httptest.NewRequest(http.MethodPost,
		"/admin/mailboxes/"+strconv.FormatInt(st.distOutScope, 10)+"/import", bytes.NewReader(body.Bytes()))
	req.SetPathValue("id", strconv.FormatInt(st.distOutScope, 10))
	req.Header.Set("Content-Type", contentType)
	w := httptest.NewRecorder()
	h.Import(w, req.WithContext(ctx))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"imported":4`) {
		t.Fatalf("pre-revocation import: want 200/imported:4, got %d (body=%s)", w.Code, w.Body.String())
	}

	oldEvery := mailboxExportRecheckEvery
	mailboxExportRecheckEvery = 1 // re-validate reach before every streamed message
	t.Cleanup(func() { mailboxExportRecheckEvery = oldEvery })

	req = httptest.NewRequest(http.MethodGet,
		"/admin/mailboxes/"+strconv.FormatInt(st.distOutScope, 10)+"/export", nil)
	req.SetPathValue("id", strconv.FormatInt(st.distOutScope, 10))
	w = httptest.NewRecorder()
	h.Export(w, req.WithContext(ctx))
	if w.Code != http.StatusOK {
		t.Fatalf("Export: want 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	zr, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if err != nil {
		t.Fatalf("Export produced unreadable ZIP: %v", err)
	}
	if len(zr.File) != 1 {
		t.Fatalf("owner-less mid-stream revocation: ZIP entries = %d, want 1 (cached-domain recheck must not keep streaming)", len(zr.File))
	}
	if got := round3MessageCount(t, pool, st.distOutScope); got != 4 {
		t.Fatalf("export must not mutate data: messages = %d, want 4", got)
	}
}
