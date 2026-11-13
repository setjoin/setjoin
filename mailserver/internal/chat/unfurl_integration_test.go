// unfurl_integration_test.go — Pillar A3 QoL Task 13: the full send-
// triggered pipeline over the REAL /chat routes (chatDo/chatTestPool/
// chatTestUser from tracer_integration_test.go, a2FakeStore from
// attachments_integration_test.go — same package, same fixtures). DB-gated
// on DB_DSN (skip-if-absent, the package convention).
//
// triggerUnfurl runs in a detached goroutine (unfurl.go), so every assertion
// here that depends on it having run polls with a short timeout instead of
// asserting immediately after the send response.
package chat_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"

	"setjoin.com/mailserver/internal/chat"
	"setjoin.com/shared/toggle"
)

// localhostURL: see unfurl_test.go's identical helper (package chat, not
// reachable from this external chat_test package) — same reasoning:
// ssrf.ValidateURL's literal-IP fast path only matches text net.ParseIP
// accepts, so rewriting httptest's "127.0.0.1" to "localhost" lets a plain
// test client actually reach the origin without weakening the real guard.
func localhostURL(raw string) string {
	return strings.Replace(raw, "127.0.0.1", "localhost", 1)
}

func TestUnfurlHappyPath_ImageRoundTripsThroughSendAndServingRoute(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	userA := chatTestUser(t, pool, "unfurlhappyA")

	// imagePNGBytes is set (below, right after the server starts) from the
	// server's own address — httptest assigns a fresh random port per run,
	// so this keeps the content, and hence its sha256, unique run-to-run
	// against the persistent test DB (blobs is content-addressed and never
	// reset between separate `go test` invocations the way pgTAP's ROLLBACK
	// resets each ../*.pg file).
	var imagePNGBytes string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/article":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, `<html><head>
				<meta property="og:title" content="A Great Article">
				<meta property="og:description" content="Всё об этом">
				<meta property="og:image" content="/cover.png">
			</head></html>`)
		case "/cover.png":
			w.Header().Set("Content-Type", "image/png")
			w.Write([]byte(imagePNGBytes))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	imagePNGBytes = "\x89PNG\r\n\x1a\nfake-but-fine-for-a-test-" + srv.URL
	articleURL := localhostURL(srv.URL) + "/article"

	store := newA2FakeStore()
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true, "chat.unfurl": true}), slog.Default())
	h.SetUnfurl(store, "unfurltestbucket", &http.Client{})

	channelID := unfurlCreateChannel(t, h, userA, "unfurl-happy")
	rr := chatDo(t, h, userA, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID),
		fmt.Sprintf(`{"body":"check this out %s"}`, articleURL))
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST messages: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var sent struct {
		MessageID int64 `json:"messageId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &sent); err != nil {
		t.Fatalf("decode send response: %v", err)
	}

	preview := unfurlWaitForPreview(t, h, userA, channelID, sent.MessageID)
	if preview["title"] != "A Great Article" {
		t.Errorf("preview title = %v, want %q", preview["title"], "A Great Article")
	}
	if preview["description"] != "Всё об этом" {
		t.Errorf("preview description = %v, want the fetched non-ASCII description", preview["description"])
	}
	imageSha, _ := preview["imageSha256"].(string)
	if imageSha == "" {
		t.Fatal("preview imageSha256 is empty, want the content-addressed sha of the fetched image")
	}

	// The image bytes actually landed in the (fake) object store, content-
	// addressed under the bare sha256 key — the blob/handler.go Put shape.
	if got := string(store.objects[imageSha]); got != imagePNGBytes {
		t.Errorf("store object %q = %q, want the fetched image bytes", imageSha, got)
	}

	// blobs.ref_count was incremented exactly once by chat_link_preview_cache_write.
	var refCount int
	if err := pool.QueryRow(context.Background(), `SELECT ref_count FROM blobs WHERE sha256 = $1`, imageSha).Scan(&refCount); err != nil {
		t.Fatalf("query blobs.ref_count: %v", err)
	}
	if refCount != 1 {
		t.Errorf("blobs.ref_count = %d, want 1", refCount)
	}

	// The image-serving route streams it back, content-type pinned from the
	// cache row, and refuses an arbitrary unrelated sha256 (the ownership
	// gate, chat_link_preview_image_owner — anti-oracle over the GLOBAL
	// blobs table).
	imgRR := chatDo(t, h, userA, "GET", "/chat/unfurl/image/"+imageSha, "")
	if imgRR.Code != http.StatusOK {
		t.Fatalf("GET unfurl image: want 200, got %d: %s", imgRR.Code, imgRR.Body.String())
	}
	if ct := imgRR.Header().Get("Content-Type"); ct != "image/png" {
		t.Errorf("unfurl image Content-Type = %q, want image/png", ct)
	}
	if imgRR.Body.String() != imagePNGBytes {
		t.Errorf("unfurl image body = %q, want the original fetched bytes", imgRR.Body.String())
	}

	unrelatedSha := "0000000000000000000000000000000000000000000000000000000000ff"
	oracleRR := chatDo(t, h, userA, "GET", "/chat/unfurl/image/"+unrelatedSha, "")
	if oracleRR.Code != http.StatusNotFound {
		t.Errorf("GET unfurl image for an unrelated sha256: want 404 (anti-oracle), got %d", oracleRR.Code)
	}

	// The load-bearing case: a sha256 that IS a real row in the GLOBAL blobs
	// table (e.g. a mail attachment or Drive file) and IS present in the
	// object store, but was NEVER cached as an unfurl image
	// (chat_link_previews.image_blob_sha256 never references it). Unlike
	// unrelatedSha above — which has no blobs row and so 404s at the
	// `SELECT content_type FROM blobs` lookup regardless of whether the
	// chat_link_preview_image_owner gate runs at all — this sha clears every
	// downstream lookup, so only the ownership gate itself can produce the
	// 404. Deleting/bypassing that gate must turn this red.
	foreignSha := fmt.Sprintf("%x", sha256.Sum256([]byte("mail-attachment-not-an-unfurl-image-"+srv.URL)))
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO blobs (sha256, minio_ref, size_bytes, content_type) VALUES ($1, $1, 4, 'image/png')`,
		foreignSha); err != nil {
		t.Fatalf("insert foreign blobs row: %v", err)
	}
	if _, err := store.PutObject(context.Background(), "unfurltestbucket", foreignSha, strings.NewReader("evil"), 4, minio.PutObjectOptions{}); err != nil {
		t.Fatalf("put foreign object: %v", err)
	}
	foreignRR := chatDo(t, h, userA, "GET", "/chat/unfurl/image/"+foreignSha, "")
	if foreignRR.Code != http.StatusNotFound {
		t.Errorf("GET unfurl image for a real, unreferenced global blob: want 404 (ownership gate), got %d", foreignRR.Code)
	}
}

func TestUnfurlToggleOff_NeverFetchesOrStores(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	userA := chatTestUser(t, pool, "unfurloffA")

	fetched := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetched = true
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head><title>Should never be fetched</title></head></html>`))
	}))
	defer srv.Close()

	store := newA2FakeStore()
	// chat.unfurl EXPLICITLY false (not merely absent) — toggle.FeatureFlags.
	// IsEnabled falls through overrides -> flags -> registryDefaults -> a
	// bare `true` default for a key present in none of those; chat.unfurl is
	// a literal-string toggle (translate.go's "feature.assist" precedent) not
	// in the shared/toggle registry, so an OMITTED key here would read as
	// enabled in this static test harness even though production always has
	// the V122-seeded false DB row loaded. Same explicit-false shape as
	// translate_test.go's "feature.assist": false off-path.
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true, "chat.unfurl": false}), slog.Default())
	h.SetUnfurl(store, "unfurltestbucket", &http.Client{})

	channelID := unfurlCreateChannel(t, h, userA, "unfurl-off")
	body := fmt.Sprintf("see %s", localhostURL(srv.URL))
	rr := chatDo(t, h, userA, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID),
		fmt.Sprintf(`{"body":%q}`, body))
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST messages: want 201, got %d: %s", rr.Code, rr.Body.String())
	}

	// Give any wrongly-spawned goroutine a beat to misbehave, then assert
	// nothing happened — no fetch, no store write, no cache row for THIS
	// url (scoped by url, not a bare count — the DB is shared across this
	// file's other tests).
	time.Sleep(150 * time.Millisecond)
	if fetched {
		t.Error("chat.unfurl is OFF: the origin server was fetched anyway")
	}
	if len(store.objects) != 0 {
		t.Error("chat.unfurl is OFF: an object was stored anyway")
	}
	var cacheRows int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM chat_link_previews WHERE url = $1`, localhostURL(srv.URL)).Scan(&cacheRows); err != nil {
		t.Fatalf("count chat_link_previews: %v", err)
	}
	if cacheRows != 0 {
		t.Errorf("chat.unfurl is OFF: %d chat_link_previews rows exist for this url, want 0", cacheRows)
	}
}

// TestUnfurlSSRFDenied_NeverAppliesAPreview proves the send-triggered
// PIPELINE end to end degrades to "no preview, ever" when the fetch is
// SSRF-denied — using a redirect-to-metadata-address scenario (the same
// shape unfurl_test.go's TestFollowRedirects_DeniesRedirectToPrivateTarget
// proves at the unit level), now driven through a real send + the real
// claim/fetch/cache_write/apply reducer protocol.
func TestUnfurlSSRFDenied_NeverAppliesAPreview(t *testing.T) {
	dsn := chatDSN(t)
	pool := chatTestPool(t, dsn)
	userA := chatTestUser(t, pool, "unfurlssrfA")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()
	maliciousURL := localhostURL(srv.URL) + "/redirect-to-metadata"

	store := newA2FakeStore()
	h := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true, "chat.unfurl": true}), slog.Default())
	h.SetUnfurl(store, "unfurltestbucket", &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	})

	channelID := unfurlCreateChannel(t, h, userA, "unfurl-ssrf")
	rr := chatDo(t, h, userA, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID),
		fmt.Sprintf(`{"body":"see %s"}`, maliciousURL))
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST messages: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var sent struct {
		MessageID int64 `json:"messageId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &sent); err != nil {
		t.Fatalf("decode send response: %v", err)
	}

	// Poll for the cache row to land at status='error' (proves the claim/
	// fetch/cache_write leg actually ran and concluded denied), then assert
	// the message NEVER gained a preview — not now, not ever.
	deadline := time.Now().Add(2 * time.Second)
	var status string
	for time.Now().Before(deadline) {
		err := pool.QueryRow(context.Background(),
			`SELECT status FROM chat_link_previews WHERE url = $1`, maliciousURL).Scan(&status)
		if err == nil && status != "pending" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if status != "error" {
		t.Fatalf("chat_link_previews.status = %q, want error (SSRF-denied redirect target)", status)
	}
	if len(store.objects) != 0 {
		t.Error("an SSRF-denied fetch must never store an image object")
	}

	rr = chatDo(t, h, userA, "GET", fmt.Sprintf("/chat/channels/%d/messages", channelID), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET messages: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var listed []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode messages: %v", err)
	}
	for _, m := range listed {
		if int64(m["messageId"].(float64)) == sent.MessageID {
			if m["payload"] != nil {
				t.Errorf("message payload = %v, want nil (no preview ever merged for an SSRF-denied URL)", m["payload"])
			}
		}
	}
}

// ── shared helpers ──────────────────────────────────────────────────────────

func unfurlCreateChannel(t *testing.T, h *chat.Handler, ownerID int64, name string) int64 {
	t.Helper()
	rr := chatDo(t, h, ownerID, "POST", "/chat/channels", fmt.Sprintf(`{"name":%q}`, name))
	if rr.Code != http.StatusCreated {
		t.Fatalf("create channel %q: want 201, got %d: %s", name, rr.Code, rr.Body.String())
	}
	var out struct {
		ChannelID int64 `json:"channelId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode channel: %v", err)
	}
	return out.ChannelID
}

// unfurlWaitForPreview polls GET .../messages until messageId carries a
// payload.preview object (triggerUnfurl's goroutine is detached/async), or
// fails the test after a short deadline.
func unfurlWaitForPreview(t *testing.T, h *chat.Handler, userID, channelID, messageID int64) map[string]any {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rr := chatDo(t, h, userID, "GET", fmt.Sprintf("/chat/channels/%d/messages", channelID), "")
		if rr.Code != http.StatusOK {
			t.Fatalf("GET messages: want 200, got %d: %s", rr.Code, rr.Body.String())
		}
		var listed []map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &listed); err != nil {
			t.Fatalf("decode messages: %v", err)
		}
		for _, m := range listed {
			if int64(m["messageId"].(float64)) != messageID {
				continue
			}
			payload, _ := m["payload"].(map[string]any)
			if payload == nil {
				break
			}
			if preview, ok := payload["preview"].(map[string]any); ok {
				return preview
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("message %d never gained a payload.preview within the deadline", messageID)
	return nil
}
