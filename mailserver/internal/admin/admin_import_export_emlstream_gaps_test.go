package admin

// Handler-level coverage for mailbox import/export error and re-check paths:
//
//   - canReachMailbox: a nonexistent mailbox id fails closed with the
//     errMailboxNotFound sentinel (no existence oracle leak), and an
//     unavailable pool wraps the lookup failure as a generic database error
//     (neither sentinel — the handler maps it to 500).
//   - importEML: an unreadable source returns zero imported plus the
//     "Failed to read import file" entry; an insert-stage failure (pool gone
//     after the object upload) returns zero imported plus the generic
//     "Import failed for this message" entry.
//   - Export format=mbox: the per-batch authority re-check runs INSIDE the
//     MBOX streaming loop exactly as in the ZIP loop — when reach still holds
//     every message streams (exportStreamRevoked returns false), and when
//     authority is revoked mid-stream the loop breaks instead of serving the
//     remaining messages.
//
// Reuses the round-2/round-3 fixtures and stub S3
// (admin_import_export_scope_round2_test.go).

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// failingReader is an io.Reader whose Read always fails — a corrupted or
// vanished upload source.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("source exploded") }

// TestCanReachMailboxMissingMailboxAndClosedPool pins the canReachMailbox
// sentinel contract: missing mailbox → errMailboxNotFound; broken pool → a
// wrapped generic lookup failure that is NOT one of the scope sentinels.
func TestCanReachMailboxMissingMailboxAndClosedPool(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedRound2Fixture(t, pool)
	ctx := round2CanReachCtx(t, st.globalActorID)

	t.Run("nonexistent mailbox id fails closed with the not-found sentinel", func(t *testing.T) {
		err := canReachMailbox(ctx, pool, 987654321)
		if !errors.Is(err, errMailboxNotFound) {
			t.Fatalf("nonexistent mailbox: want errMailboxNotFound, got %v", err)
		}
	})

	t.Run("unavailable pool wraps the lookup failure generically", func(t *testing.T) {
		closed := testsupport.OpenTestPool(t)
		closed.Close() // OpenTestPool's cleanup Close is idempotent
		err := canReachMailbox(ctx, closed, st.mbInScope)
		if err == nil {
			t.Fatal("closed pool: want error, got nil")
		}
		if errors.Is(err, errMailboxNotFound) || errors.Is(err, errMailboxOutOfScope) {
			t.Fatalf("closed pool: want generic wrapped lookup failure, got sentinel %v", err)
		}
		if !strings.Contains(err.Error(), "mailbox scope lookup failed") {
			t.Fatalf("closed pool: error %q does not name the lookup failure", err)
		}
	})
}

// TestImportEMLReaderAndInsertFailures pins both single-message importEML
// failure arms: an unreadable source is reported before any storage work, and
// an insert-stage failure after the object upload still reports the message
// (never a silent drop) with zero imported.
func TestImportEMLReaderAndInsertFailures(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedRound2Fixture(t, pool)
	mc, bucket := round2StubS3(t)
	ctx := round2CanReachCtx(t, st.globalActorID)

	t.Run("unreadable source returns zero imported and a read-failure entry", func(t *testing.T) {
		h := NewImportExportHandler(mc, pgxutil.WorkerPool{Pool: pool}, bucket, testsupport.TestLogger())
		imported, failed := h.importEML(ctx, st.mbInScope, nil, failingReader{})
		if imported != 0 || len(failed) != 1 {
			t.Fatalf("imported=%d failed=%d, want 0 and exactly one failure entry", imported, len(failed))
		}
		txt, _ := failed[0]["error"].(string)
		if !strings.Contains(txt, "Failed to read import file") {
			t.Fatalf("failure entry %q does not name the read failure", txt)
		}
	})

	t.Run("insert-stage failure returns zero imported and a failure entry", func(t *testing.T) {
		closed := testsupport.OpenTestPool(t)
		closed.Close()
		h := NewImportExportHandler(mc, pgxutil.WorkerPool{Pool: closed}, bucket, testsupport.TestLogger())
		imported, failed := h.importEML(ctx, st.mbInScope, nil, strings.NewReader(round2OneMessageMBOX))
		if imported != 0 || len(failed) != 1 {
			t.Fatalf("imported=%d failed=%d, want 0 and exactly one failure entry", imported, len(failed))
		}
		txt, _ := failed[0]["error"].(string)
		if !strings.Contains(txt, "Import failed for this message") {
			t.Fatalf("failure entry %q does not name the insert failure", txt)
		}
	})

	t.Run("readable message imports successfully", func(t *testing.T) {
		h := NewImportExportHandler(mc, pgxutil.WorkerPool{Pool: pool}, bucket, testsupport.TestLogger())
		imported, failed := h.importEML(ctx, st.mbInScope, nil, strings.NewReader(round2OneMessageMBOX))
		if imported != 1 || len(failed) != 0 {
			t.Fatalf("imported=%d failed=%d, want 1 with no failure entries", imported, len(failed))
		}
	})
}

// importRound3Mbox seeds n real messages into the in-scope mailbox as the
// OU-scoped actor, the same pattern the round-3 tests use.
func importRound3Mbox(t *testing.T, h *ImportExportHandler, mbID, actorID int64, n int) {
	t.Helper()
	body, contentType := round2ImportBody(t, round3Mbox(n))
	req := httptest.NewRequest(http.MethodPost,
		"/admin/mailboxes/"+strconv.FormatInt(mbID, 10)+"/import", bytes.NewReader(body.Bytes()))
	req.SetPathValue("id", strconv.FormatInt(mbID, 10))
	req.Header.Set("Content-Type", contentType)
	w := httptest.NewRecorder()
	h.Import(w, req.WithContext(round2CanReachCtx(t, actorID)))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"imported":`+strconv.Itoa(n)) {
		t.Fatalf("seed import of %d messages: want 200/imported:%d, got %d (body=%s)",
			n, n, w.Code, w.Body.String())
	}
}

func exportMBOX(t *testing.T, h *ImportExportHandler, mbID, actorID int64) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet,
		"/admin/mailboxes/"+strconv.FormatInt(mbID, 10)+"/export?format=mbox", nil)
	req.SetPathValue("id", strconv.FormatInt(mbID, 10))
	w := httptest.NewRecorder()
	h.Export(w, req.WithContext(round2CanReachCtx(t, actorID)))
	if w.Code != http.StatusOK {
		t.Fatalf("Export mbox: want 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/mbox" {
		t.Fatalf("Export mbox content type = %q, want application/mbox", ct)
	}
	return w
}

// TestExportMBOXRecheckPassesStreamsAll pins the healthy arm of the MBOX
// streaming loop's per-batch re-validation: with the interval forced to 1, the
// re-check before the SECOND message must find authority intact and stream
// every message (exportStreamRevoked returns false inside the mbox loop, not
// just the ZIP loop).
func TestExportMBOXRecheckPassesStreamsAll(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	st := seedRound2Fixture(t, pool)
	mc, bucket := round2StubS3(t)
	h := NewImportExportHandler(mc, pgxutil.WorkerPool{Pool: pool}, bucket, testsupport.TestLogger())

	importRound3Mbox(t, h, st.mbInScope, st.ouActorID, 2)

	oldEvery := mailboxExportRecheckEvery
	mailboxExportRecheckEvery = 1 // re-validate reach before every streamed message
	t.Cleanup(func() { mailboxExportRecheckEvery = oldEvery })

	out := exportMBOX(t, h, st.mbInScope, st.ouActorID).Body.String()
	if !strings.Contains(out, "Subject: round3 msg 0") || !strings.Contains(out, "Subject: round3 msg 1") {
		t.Fatalf("mbox export must stream BOTH messages (the i=1 re-check must pass), got:\n%s", out)
	}
}

// TestExportMBOXRevokedMidStreamStops pins the revocation arm of the MBOX
// streaming loop: the stub S3 revokes the actor after serving the first
// object, and the re-check before the next message must stop the stream.
func TestExportMBOXRevokedMidStreamStops(t *testing.T) {
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

	importRound3Mbox(t, h, st.mbInScope, st.ouActorID, 3)

	oldEvery := mailboxExportRecheckEvery
	mailboxExportRecheckEvery = 1
	t.Cleanup(func() { mailboxExportRecheckEvery = oldEvery })

	out := exportMBOX(t, h, st.mbInScope, st.ouActorID).Body.String()
	// The export orders by received_at DESC, which does not discriminate
	// same-second imports — assert on the COUNT of streamed messages, not on
	// which message came first.
	if served := strings.Count(out, "Subject: round3 msg "); served != 1 {
		t.Fatalf("mid-stream revocation: mbox must stream exactly ONE message, got %d:\n%s", served, out)
	}
	if separators := strings.Count(out, "From <imported-"); separators != 1 {
		t.Fatalf("mid-stream revocation: mbox must carry exactly one MBOX separator, got %d", separators)
	}
}
