// unfurl.go — link-preview unfurl, full (with images), SSRF-hardened
// (Pillar A3 QoL Task 13). Behind its OWN toggle (chat.unfurl, DEFAULT OFF,
// V122 §H) — independent of feature.chat.
//
// Trigger: sendMessage (messages.go) calls triggerUnfurl after a successful
// send, which extracts the first URL from the just-sent body and kicks a
// detached goroutine — never on the request's own context (the HTTP
// response has already been written by the time the fetch would even start
// dialing; ctx.WithoutCancel mirrors internal/webhook/dispatcher.go's
// detached-delivery precedent). This is a deliberate widening of Task 13's
// literal Files list (unfurl.go + chat_unfurl.sql + the worker + the image
// route): the plan's own prose describes a send-triggered flow ("on send
// with a URL... -> async fetch"), and there is no queue/marker column
// anywhere in V122 a periodic sweep could use to find "messages not yet
// unfurl-checked" without either a new migration or re-scanning the whole
// table forever — the one-line hook here is the smaller, lower-risk
// deviation. See the task's final report for the full rationale.
//
// Fetcher: shared/ssrf.SafeHTTPClient (connect-time private/loopback/
// link-local/metadata denial, defeats DNS rebinding) — NOT
// internal/linkprotect, which is click-time URL reputation and never
// fetches. SafeHTTPClient's CheckRedirect returns http.ErrUseLastResponse
// (redirects are never auto-followed), so followRedirects below re-validates
// and re-dials EVERY hop through the exact same safe client — a redirect to
// an internal address is denied exactly like a direct request to one would
// be, and each hop still defeats rebinding independently.
//
// W4 native-RLS scope-wrap exemption (scripts/check-rls-scope-wrap.sh
// allowlists processUnfurl/applyUnfurl/fetchAndStoreImage/unfurlImage by
// name): every h.pool call in this file targets chat_link_previews (deny-all
// to the app role, V122 §E) or blobs (global content-addressed, no owner
// column) through reducers that are ALREADY SECURITY DEFINER and
// self-scoped by url_hash/sha256 — never by caller identity — so there is no
// p_user_id to bind a GUC to, and triggerUnfurl's detached goroutine
// (ctx.WithoutCancel) never threads one through in the first place. The
// Worker below runs on workerPool (BYPASSRLS) like every other maintenance
// worker in this repo, so it needs no wrap either.
package chat

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"golang.org/x/net/html"

	"setjoin.com/shared/httputil"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/ssrf"
	"setjoin.com/shared/toggle"
)

// unfurlStore is the minimal object-storage seam this file needs — the same
// two methods as internal/drive's unexported objectStore (PutObject to save
// a fetched image, GetObject to serve it back). Structural typing means
// drive.MinioStore (production) and the chat package's own test fakes both
// satisfy this without any shared exported interface.
type unfurlStore interface {
	PutObject(ctx context.Context, bucket, object string, reader io.Reader, size int64, opts minio.PutObjectOptions) (minio.UploadInfo, error)
	GetObject(ctx context.Context, bucket, object string, opts minio.GetObjectOptions) (io.ReadCloser, error)
}

// Caps (plan Task 13): "connect-time... size cap (~2 MiB page / ~5 MiB
// image), content-type allowlist... total-time cap".
const (
	maxHTMLBytes       int64 = 2 << 20 // 2 MiB
	maxImageBytes      int64 = 5 << 20 // 5 MiB
	maxRedirectHops          = 3
	unfurlTotalTimeout       = 15 * time.Second // wraps the whole fetchPreview call (page + optional image)
)

// Unfurl metadata bounds (occ_980dba9c476e43f3e6d8ef7e —
// unfurl-unbounded-title-description): og:title/og:description are parsed from
// attacker-controlled page bytes, so they are bounded before persistence. The
// SQL side is the authority — chat_unfurl_bound_text in chat_unfurl.sql
// truncates-with-marker at chat_link_preview_cache_write AND at the
// chat_message_unfurl_apply payload merge — and these Go caps mirror it at the
// fetch path so over-bound strings never even ship to the cache write. Units
// are CHARACTERS (runes), matching SQL char_length, not bytes.
const (
	maxUnfurlTitleChars       = 512
	maxUnfurlDescriptionChars = 1024
)

// boundUnfurlText truncates s to maxChars characters, marking the truncation
// with a trailing ellipsis that occupies the bound's final character — so the
// result never exceeds the cap and is visibly marked. Byte-identical semantics
// to chat_unfurl_bound_text in chat_unfurl.sql (which this mirrors defensively;
// the reducer stays the authority for any other caller).
func boundUnfurlText(s string, maxChars int) string {
	runes := []rune(s)
	if len(runes) <= maxChars {
		return s
	}
	return string(runes[:maxChars-1]) + "…"
}

// SetUnfurl wires the Task 13 unfurl dependencies post-construction — the
// drive.NewWorker/driveH.SetJWTProvider idiom: a nil-safe optional seam so
// every existing NewHandler call site (main.go + every test file already
// calling chat.NewHandler(pool, flags, logger)) is untouched. client is
// injectable so tests can pass a plain *http.Client (httptest servers always
// bind loopback, which the real ssrf.SafeHTTPClient would correctly refuse
// to dial — the SAME reason internal/webhook's tests swap in a plain client,
// see webhook_deliveries_test.go); production wires ssrf.SafeHTTPClient.
func (h *Handler) SetUnfurl(store unfurlStore, bucket string, client *http.Client) {
	h.unfurlStore = store
	h.unfurlBucket = bucket
	h.unfurlClient = client
}

func (h *Handler) registerUnfurlRoutes(mux router) {
	mux.HandleFunc("GET /chat/unfurl/image/{sha256}", h.unfurlImage)
}

// urlRe grabs the first http(s) URL token in a message body, trimming
// common trailing punctuation a sentence would wrap it in.
var urlRe = regexp.MustCompile(`https?://[^\s<>"']+`)

// extractFirstURL returns the first URL in body that both looks like a URL
// and passes the fast-fail ssrf.ValidateURL pre-check (bad scheme, literal
// private/loopback/metadata IP) plus a userinfo ("user:pass@host") refusal
// the plan calls out explicitly — ValidateURL itself doesn't check
// userinfo. This is the cheap reject-early leg; the real, authoritative
// guard is still the dial-time Control hook inside ssrf.SafeHTTPClient, run
// again on every hop in followRedirects.
func extractFirstURL(body string) (string, bool) {
	m := urlRe.FindString(body)
	if m == "" {
		return "", false
	}
	m = strings.TrimRight(m, ".,;:!?)]}'\"")
	if err := validateFetchURL(m); err != nil {
		return "", false
	}
	return m, true
}

func validateFetchURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.User != nil {
		return ssrf.ErrUnsafeURL // refuse userinfo-bearing URLs outright (plan Task 13)
	}
	return ssrf.ValidateURL(raw)
}

// followRedirects issues client.Do against startURL and manually follows up
// to maxHops 3xx redirects, re-validating (ssrf.ValidateURL + userinfo
// refusal) and re-dialing EVERY hop through the SAME safe client — the
// plan's "redirect cap: each hop re-passes the safe dialer". client's
// CheckRedirect must return http.ErrUseLastResponse (ssrf.SafeHTTPClient
// already sets this) so Go's own transport never silently follows a
// redirect for us.
func followRedirects(ctx context.Context, client *http.Client, startURL string, maxHops int) (*http.Response, error) {
	current := startURL
	for hop := 0; ; hop++ {
		if err := validateFetchURL(current); err != nil {
			return nil, fmt.Errorf("unfurl: %s: %w", current, err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			return resp, nil
		}
		loc := resp.Header.Get("Location")
		resp.Body.Close()
		if loc == "" {
			return nil, fmt.Errorf("unfurl: redirect with no Location")
		}
		if hop >= maxHops {
			return nil, fmt.Errorf("unfurl: too many redirects (cap %d)", maxHops)
		}
		base, err := url.Parse(current)
		if err != nil {
			return nil, err
		}
		next, err := url.Parse(loc)
		if err != nil {
			return nil, err
		}
		current = base.ResolveReference(next).String()
	}
}

// parsePreviewHTML scans an HTML document for og:title/og:description/
// og:image (falling back to <title> for the title, and a bare
// name="description" meta for the description), resolving a relative
// og:image against baseURL. Pure — no I/O — so it's unit-testable on a
// plain string reader.
func parsePreviewHTML(r io.Reader, baseURL string) (title, description, image string) {
	base, _ := url.Parse(baseURL) // nil-safe: ResolveReference on a nil *url.URL panics, so guard below
	z := html.NewTokenizer(r)
	inTitle := false
	for {
		switch z.Next() {
		case html.ErrorToken:
			return
		case html.StartTagToken, html.SelfClosingTagToken:
			tok := z.Token()
			switch tok.Data {
			case "title":
				inTitle = true
			case "meta":
				var property, name, content string
				for _, a := range tok.Attr {
					switch a.Key {
					case "property":
						property = a.Val
					case "name":
						name = a.Val
					case "content":
						content = a.Val
					}
				}
				key := property
				if key == "" {
					key = name
				}
				switch key {
				case "og:title":
					title = content
				case "og:description", "description":
					if description == "" {
						description = content
					}
				case "og:image", "og:image:url":
					if base != nil {
						if rel, err := url.Parse(content); err == nil {
							image = base.ResolveReference(rel).String()
						}
					} else {
						image = content
					}
				}
			}
		case html.TextToken:
			if inTitle && title == "" {
				if t := strings.TrimSpace(string(z.Text())); t != "" {
					title = t
				}
			}
		case html.EndTagToken:
			tok := z.Token()
			if tok.Data == "title" {
				inTitle = false
			}
		}
	}
}

// triggerUnfurl is called by sendMessage (messages.go) right after a
// successful send. Best-effort and fully async: it never affects the send
// response, and any failure (toggle off, no URL, no store wired, DB error)
// is a silent no-op — unfurl is enrichment, never load-bearing.
func (h *Handler) triggerUnfurl(parent context.Context, sent json.RawMessage, body string) {
	if h.unfurlStore == nil || !h.flags.IsEnabled(toggle.ChatUnfurl) {
		return
	}
	rawURL, ok := extractFirstURL(body)
	if !ok {
		return
	}
	var msg struct {
		MessageID int64 `json:"messageId"`
	}
	if err := json.Unmarshal(sent, &msg); err != nil || msg.MessageID == 0 {
		return
	}
	ctx := context.WithoutCancel(parent)
	go h.processUnfurl(ctx, msg.MessageID, rawURL)
}

func unfurlURLHash(rawURL string) string {
	sum := sha256.Sum256([]byte(rawURL))
	return hex.EncodeToString(sum[:])
}

// processUnfurl runs the claim/fetch/apply protocol documented in
// chat_unfurl.sql's header for ONE (messageId, url) pair.
func (h *Handler) processUnfurl(ctx context.Context, messageID int64, rawURL string) {
	urlHash := unfurlURLHash(rawURL)

	var cached json.RawMessage
	if err := h.pool.QueryRow(ctx, `SELECT chat_link_preview_lookup($1)`, urlHash).Scan(&cached); err != nil {
		h.logger.Warn("chat: unfurl lookup failed", "error", err)
		return
	}
	if len(cached) > 0 && string(cached) != "null" {
		var c struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(cached, &c); err == nil && c.Status == "ok" {
			h.applyUnfurl(ctx, messageID, urlHash)
		}
		// pending or error: no-op (ponytail — see chat_unfurl.sql's header;
		// no retry queue in v1, the TTL worker reaps a stuck pending row).
		return
	}

	var won bool
	if err := h.pool.QueryRow(ctx, `SELECT chat_link_preview_claim($1, $2)`, urlHash, rawURL).Scan(&won); err != nil {
		h.logger.Warn("chat: unfurl claim failed", "error", err)
		return
	}
	if !won {
		return // lost the race to another concurrent post of the same URL
	}

	title, description, imageSha, status := h.fetchPreview(ctx, rawURL)
	if _, err := h.pool.Exec(ctx, `SELECT chat_link_preview_cache_write($1,$2,$3,$4,$5)`,
		urlHash, nullIfEmpty(title), nullIfEmpty(description), nullIfEmpty(imageSha), status); err != nil {
		h.logger.Warn("chat: unfurl cache write failed", "error", err)
		return
	}
	if status == "ok" {
		h.applyUnfurl(ctx, messageID, urlHash)
	}
}

func (h *Handler) applyUnfurl(ctx context.Context, messageID int64, urlHash string) {
	if _, err := h.pool.Exec(ctx, `SELECT chat_message_unfurl_apply($1, $2)`, messageID, urlHash); err != nil {
		h.logger.Warn("chat: unfurl apply failed", "error", err)
	}
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// fetchPreview does the actual network work for one URL: fetch the page
// (redirect-capped, size-capped, content-type-checked), parse title/
// description/og:image, then — if an image URL was found — fetch and store
// it too (best-effort: an image-fetch failure still returns the text
// preview with an empty imageSha, "ok" status; only a failure to fetch the
// PAGE itself is a hard "error"). A single unfurlTotalTimeout wall-clock cap
// wraps both legs (the plan's "total-time cap").
func (h *Handler) fetchPreview(parent context.Context, rawURL string) (title, description, imageSha, status string) {
	ctx, cancel := context.WithTimeout(parent, unfurlTotalTimeout)
	defer cancel()

	resp, err := followRedirects(ctx, h.unfurlClient, rawURL, maxRedirectHops)
	if err != nil {
		return "", "", "", "error"
	}
	defer resp.Body.Close()

	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		return "", "", "", "error"
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxHTMLBytes+1))
	if err != nil || int64(len(data)) > maxHTMLBytes {
		return "", "", "", "error"
	}

	title, description, imageURL := parsePreviewHTML(bytes.NewReader(data), rawURL)
	// Metadata bound mirror (occ_980dba9c476e43f3e6d8ef7e): bound before the
	// values leave this file; the reducer caps stay the authority.
	title = boundUnfurlText(title, maxUnfurlTitleChars)
	description = boundUnfurlText(description, maxUnfurlDescriptionChars)
	if title == "" && description == "" && imageURL == "" {
		return "", "", "", "error" // nothing usable — the v1 unfurl floor
	}
	if imageURL == "" {
		return title, description, "", "ok"
	}
	sha, err := h.fetchAndStoreImage(ctx, imageURL)
	if err != nil {
		if h.logger != nil {
			h.logger.Info("chat: unfurl image fetch failed", "url", imageURL, "error", err)
		}
		return title, description, "", "ok" // partial success: text preview, no image
	}
	return title, description, sha, "ok"
}

// fetchAndStoreImage fetches imageURL (redirect-capped, size-capped,
// image/* content-type only), content-addresses the bytes into the SAME
// blobs table message attachments use (blob/handler.go's Put shape: PUT the
// bytes under the computed sha256 key, then INSERT INTO blobs at
// ref_count=0 — chat_link_preview_cache_write does the +1, the ONLY
// increment path per V122 §E), and returns the sha256 hex.
func (h *Handler) fetchAndStoreImage(ctx context.Context, imageURL string) (string, error) {
	resp, err := followRedirects(ctx, h.unfurlClient, imageURL, maxRedirectHops)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "image/") {
		return "", fmt.Errorf("unfurl image: unexpected content-type %q", contentType)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxImageBytes+1))
	if err != nil {
		return "", err
	}
	if int64(len(data)) > maxImageBytes {
		return "", fmt.Errorf("unfurl image exceeds %d bytes", maxImageBytes)
	}

	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])
	if _, err := h.unfurlStore.PutObject(ctx, h.unfurlBucket, sha, bytes.NewReader(data), int64(len(data)),
		minio.PutObjectOptions{ContentType: contentType}); err != nil {
		return "", err
	}
	if _, err := h.pool.Exec(ctx,
		`INSERT INTO blobs (sha256, minio_ref, size_bytes, content_type, ref_count)
		 VALUES ($1, $2, $3, $4, 0) ON CONFLICT (sha256) DO NOTHING`,
		sha, h.unfurlBucket+"/"+sha, len(data), contentType,
	); err != nil {
		return "", err
	}
	return sha, nil
}

// shaHexRe validates the {sha256} path param before it ever reaches SQL or
// the object store.
var shaHexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// unfurlImage serves GET /chat/unfurl/image/{sha256}. Gated only by the
// package-wide ServeHTTP gate (feature.chat + auth) — same "chat-capability-
// gated" posture the plan calls for, not re-gated on chat.unfurl (an image
// fetched while the toggle was on stays viewable if it's later flipped
// off). The chat_link_preview_image_owner check is the load-bearing
// authorization boundary: blobs is a GLOBAL content-addressed table shared
// with mail attachments/Drive/HR receipts, so without it this route would be
// an oracle for ANY blob's bytes+content-type given its bare sha256, not
// just a legitimately-cached unfurl image.
func (h *Handler) unfurlImage(w http.ResponseWriter, r *http.Request) {
	sha := r.PathValue("sha256")
	if !shaHexRe.MatchString(sha) || h.unfurlStore == nil {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	var owned bool
	if err := h.pool.QueryRow(r.Context(), `SELECT chat_link_preview_image_owner($1)`, sha).Scan(&owned); err != nil || !owned {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	var contentType string
	if err := h.pool.QueryRow(r.Context(), `SELECT content_type FROM blobs WHERE sha256 = $1`, sha).Scan(&contentType); err != nil {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	obj, err := h.unfurlStore.GetObject(r.Context(), h.unfurlBucket, sha, minio.GetObjectOptions{})
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	defer obj.Close()
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	// G705 precedent (blob/handler.go): the bytes + content-type behind this
	// route are attacker-supplied (fetched from the open web) — nosniff + a
	// sandbox CSP stop a browser from rendering them as active content (sniffed
	// or correctly-typed as a top-level document) in the app origin.
	httputil.SetUntrustedBlobHeaders(w)
	_, _ = io.Copy(w, obj)
}

// Worker runs the Task 13 TTL eviction leg — the plan's own "Modify the
// chat worker" wording assumed a pre-existing chat maintenance worker; none
// exists yet in this package (drive.NewWorker/pushjobs.NewWorker are the
// only precedents), so this task creates it, mirroring their shape exactly:
// a plain pgxutil.WorkerPool (BYPASSRLS — chat_link_previews is deny-all to
// the app role, V122 §E) + a ticker loop that exits on ctx cancel. Deleting
// an expired chat_link_previews row triggers the V122
// chat_link_preview_blob_refcount AFTER DELETE trigger, decrementing the
// image blob's ref_count (reaped by the existing trg_blob_refcount_zero
// path, unchanged) — no bespoke GC logic needed here, just the DELETE.
type Worker struct {
	pool   pgxutil.WorkerPool
	logger *slog.Logger
}

// unfurlWorkerInterval: a 14-day TTL doesn't need drive's 5-minute chunk-GC
// cadence — an hourly tick is plenty.
const unfurlWorkerInterval = 1 * time.Hour

// NewWorker builds the Task 13 maintenance worker.
func NewWorker(pool pgxutil.WorkerPool, logger *slog.Logger) *Worker {
	return &Worker{pool: pool, logger: logger}
}

// Run starts the ticker loop; exits cleanly when ctx is cancelled.
func (w *Worker) Run(ctx context.Context) {
	w.logger.Info("chat unfurl worker started", "interval", unfurlWorkerInterval)
	ticker := time.NewTicker(unfurlWorkerInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			w.logger.Info("chat unfurl worker stopped")
			return
		case <-ticker.C:
			w.evictExpired(ctx)
		}
	}
}

// evictExpired deletes every chat_link_previews row past the ~14-day TTL —
// including a stuck 'pending' row (a crashed fetch never wrote a result),
// so a later post of that URL gets to re-claim and retry (chat_unfurl.sql's
// header comment).
func (w *Worker) evictExpired(ctx context.Context) {
	// Single statement: the SELECT-then-DELETE-per-row version both cost 1+N
	// round trips and could race a concurrent eviction between the two steps
	// (RETURNING makes the delete claim the rows atomically).
	ct, err := w.pool.Exec(ctx,
		`DELETE FROM chat_link_previews WHERE fetched_at < now() - interval '14 days' RETURNING url_hash`)
	if err != nil {
		w.logger.Warn("chat unfurl worker: TTL eviction failed", "error", err)
		return
	}
	if ct.RowsAffected() > 0 {
		w.logger.Debug("chat unfurl worker: evicted expired previews", "count", ct.RowsAffected())
	}
}
