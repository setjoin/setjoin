package caldav

// Free/busy canonical-identity acceptance tests (med-shard2-011 / CALDAV-004):
// the free-busy-query REPORT must resolve principals by canonical mailbox
// identity (ARCH-003), never by raw users.id. The fixture manufactures the
// exact numeric collision the defect exploits:
//
//   - caller users.id = 501; caller's PRIMARY mailbox id = 101
//   - victim users.id = 101; victim's second mailbox id = 501  ← collision
//   - calendar 303 is the caller's own calendar (mailbox 101)
//
// The pre-fix caller passed the calendar id as p_account_id and the owner's
// raw users.id (501) into calendar_free_busy's MAILBOX-id parameter — which
// numerically collides with the victim's mailbox 501 — and then resolved the
// mailto href from `WHERE m.id = 501`, i.e. the VICTIM's email and busy data.
// The fixed handler passes the caller's primary mailbox as p_account_id (the
// sharing.defaults viewer principal), the calendar's owning mailbox_id as the
// target, and fail-closes on any reducer echo that is not exactly the expected
// mailbox id.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/reducercall"
)

// fbStubCaller records the reducer invocation and replays a canned result —
// the seam that lets the test poison the echo the production PoolCaller would
// faithfully relay from the real reducer.
type fbStubCaller struct {
	gotFn   string
	gotArgs []any
	raw     json.RawMessage
	err     error
}

func (c *fbStubCaller) Call(_ context.Context, fn string, args ...any) (json.RawMessage, error) {
	c.gotFn, c.gotArgs = fn, args
	return c.raw, c.err
}

func (c *fbStubCaller) CallScoped(context.Context, int64, string, ...any) (json.RawMessage, error) {
	return nil, errors.New("fbStubCaller: CallScoped not implemented")
}

func (c *fbStubCaller) CallScopedBatch(context.Context, int64, ...reducercall.ScopedCall) ([]json.RawMessage, error) {
	return nil, errors.New("fbStubCaller: CallScopedBatch not implemented")
}

// fbIdentityScratch builds the minimal users/mailboxes/calendars shape the
// free-busy-query handler reads, with the colliding ids from the header. DDL
// is schema-qualified (the helper runs it on the base pool, outside the
// scratch search_path).
func fbIdentityScratch(t *testing.T) *pgxpool.Pool {
	t.Helper()
	const schema = "caldav_fbident"
	pool := itipGapScratchSchema(t, schema, []string{
		`CREATE TABLE ` + schema + `.users (id bigint PRIMARY KEY, email text NOT NULL)`,
		`CREATE TABLE ` + schema + `.mailboxes (id bigint PRIMARY KEY, user_id bigint, is_primary boolean NOT NULL DEFAULT false)`,
		`CREATE TABLE ` + schema + `.calendars (id bigint PRIMARY KEY, mailbox_id bigint NOT NULL,` +
			` name text NOT NULL DEFAULT '', color text, description text, timezone text NOT NULL DEFAULT 'UTC',` +
			` is_default boolean NOT NULL DEFAULT false, is_shared boolean NOT NULL DEFAULT false)`,
		`INSERT INTO ` + schema + `.users VALUES (501, 'caller@fb.test'), (101, 'victim@fb.test')`,
		`INSERT INTO ` + schema + `.mailboxes VALUES (101, 501, true), (202, 101, true), (501, 101, false)`,
		`INSERT INTO ` + schema + `.calendars VALUES (303, 101)`,
	})
	return pool
}

func fbIdentityRequest(t *testing.T, h *Handler, callerUserID int64) *httptest.ResponseRecorder {
	t.Helper()
	const body = `<C:free-busy-query xmlns:C="urn:ietf:params:xml:ns:caldav">` +
		`<C:time-range start="20260101T000000Z" end="20260301T000000Z"/>` +
		`</C:free-busy-query>`
	req := httptest.NewRequest(http.MethodPost, "/303/", strings.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: callerUserID}))
	rec := httptest.NewRecorder()
	h.handleFreeBusyQuery(rec, req, []byte(body))
	return rec
}

// TestFreeBusyQuery_CanonicalOwnerMailboxIdentity: the reducer receives the
// caller's primary mailbox as p_account_id (the sharing.defaults viewer
// principal — never the calendar id) and the calendar's canonical owning
// mailbox_id (never the owner's raw users.id, which collides with the victim's
// mailbox here); the rendered href carries the CALLER's own email, never
// another user's.
func TestFreeBusyQuery_CanonicalOwnerMailboxIdentity(t *testing.T) {
	pool := fbIdentityScratch(t)
	stub := &fbStubCaller{
		raw: json.RawMessage(`[{"userId":"101","intervals":[{"start":"2026-01-05T09:00:00Z","end":"2026-01-05T10:00:00Z","status":"busy"}]}]`),
	}
	h := &Handler{pool: pool, caller: stub, logger: noopLogger()}

	rec := fbIdentityRequest(t, h, 501)

	if stub.gotFn != "calendar_free_busy" {
		t.Fatalf("reducer fn = %q, want calendar_free_busy", stub.gotFn)
	}
	if len(stub.gotArgs) != 4 {
		t.Fatalf("reducer args = %#v, want 4", stub.gotArgs)
	}
	if id, ok := stub.gotArgs[0].(int64); !ok || id != 101 {
		t.Errorf("p_account_id = %#v, want the caller's primary mailbox 101 (sharing.defaults viewer principal)", stub.gotArgs[0])
	}
	targets, ok := stub.gotArgs[1].([]int64)
	if !ok || len(targets) != 1 || targets[0] != 101 {
		t.Errorf("p_user_ids = %#v, want [101] (the calendar's canonical owning mailbox_id, not the colliding users.id 501)", stub.gotArgs[1])
	}

	body := rec.Body.String()
	if !strings.Contains(body, "mailto:caller@fb.test") {
		t.Errorf("free/busy href must carry the caller's own email; got:\n%s", body)
	}
	if !strings.Contains(body, "FREEBUSY;FBTYPE=BUSY") {
		t.Errorf("free/busy intervals must be rendered; got:\n%s", body)
	}
	if strings.Contains(body, "victim@fb.test") {
		t.Errorf("free/busy response leaked the colliding victim's email:\n%s", body)
	}
}

// TestFreeBusyQuery_CollisionEchoFailsClosed: a reducer result whose echoed
// userId is not exactly the requested canonical mailbox id is dropped —
// fail-closed/empty, never another principal's busy data or email.
func TestFreeBusyQuery_CollisionEchoFailsClosed(t *testing.T) {
	pool := fbIdentityScratch(t)
	stub := &fbStubCaller{
		// Poisoned echo: the pre-fix identity confusion would render mailbox
		// 501 (the victim's) busy data and email here.
		raw: json.RawMessage(`[{"userId":"501","intervals":[{"start":"2026-01-05T09:00:00Z","end":"2026-01-05T10:00:00Z","status":"busy"}]}]`),
	}
	h := &Handler{pool: pool, caller: stub, logger: noopLogger()}

	rec := fbIdentityRequest(t, h, 501)

	body := rec.Body.String()
	if strings.Contains(body, "FREEBUSY") || strings.Contains(body, "mailto:") {
		t.Errorf("mismatched principal echo must fail closed/empty; got:\n%s", body)
	}
}
