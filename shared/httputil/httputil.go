// Package httputil provides shared HTTP response helpers consumed by both servers.
package httputil

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"setjoin.com/shared/clientip"
)

// ReadBody reads a request body through an enforced byte ceiling. It writes a
// stable RFC 7807 response and returns ok=false when the body is too large or
// cannot be read. Callers must return immediately when ok is false.
func ReadBody(w http.ResponseWriter, r *http.Request, maxBytes int64) ([]byte, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	body, err := io.ReadAll(r.Body)
	if err == nil {
		return body, true
	}
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		WriteProblem(w, r, &Problem{
			Type:   TypeTooLarge,
			Status: http.StatusRequestEntityTooLarge,
			Detail: "request body exceeds the allowed size",
		})
		return nil, false
	}
	WriteProblem(w, r, &Problem{Status: http.StatusBadRequest, Detail: "could not read request body"})
	return nil, false
}

// TrustFunc reports whether a remote address is a trusted proxy.
// When trusted, X-Forwarded-For is used to determine the real client IP.
type TrustFunc func(remoteAddr string) bool

// ClientIPWithTrust extracts the client IP from an HTTP request using a
// caller-provided trust function. Thin wrapper over clientip.ExtractWithTrust
// (the shared leaf implementation); see that package for the trust semantics.
func ClientIPWithTrust(r *http.Request, trustFunc TrustFunc) string {
	return clientip.ExtractWithTrust(r, trustFunc)
}

// WriteJSON writes a JSON response with the given status code. Sensitive
// JSON API responses default to Cache-Control: no-store when the caller has
// not set a deliberate cache policy (blob/Drive callers pin their own
// private/max-age headers), so no shared JSON writer can silently omit
// cache policy on authenticated, per-tenant payloads.
func WriteJSON(w http.ResponseWriter, code int, data any) {
	setNoStoreIfUnset(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(data)
}

// setNoStoreIfUnset applies Cache-Control: no-store unless the caller already
// set a Cache-Control policy. Set-if-absent keeps deliberate per-caller
// policies (private, max-age on blob/Drive content) authoritative.
func setNoStoreIfUnset(w http.ResponseWriter) {
	if w.Header().Get("Cache-Control") == "" {
		w.Header().Set("Cache-Control", "no-store")
	}
}

// maxOffset caps the "offset" query parameter ParseLimitOffset returns. The
// value reaches SQL strictly as a bound parameter, but PostgreSQL still scans
// and discards up to the offset — an unbounded offset lets an authenticated
// client amplify per-request work at real table depth. One million keeps
// every realistic deep-page admin flow reachable while bounding the
// scan-and-discard friction.
const maxOffset = 1_000_000

// ParseLimitOffset parses the "limit" and "offset" query parameters.
// limit is reset to defLimit when absent, non-numeric, <= 0, or > maxLimit —
// the `if limit <= 0 || limit > maxLimit { limit = defLimit }` clamp repeated
// across the admin/user list endpoints. offset defaults to 0 (absent or
// non-numeric), is floored at 0 when negative, and is capped at maxOffset so
// a request cannot demand an unbounded scan-and-discard. Callers whose
// endpoint has no offset query param may discard the second return value.
func ParseLimitOffset(r *http.Request, defLimit, maxLimit int) (limit, offset int) {
	limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > maxLimit {
		limit = defLimit
	}
	offset, _ = strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	if offset > maxOffset {
		offset = maxOffset
	}
	return limit, offset
}

// WriteDBErr logs a database-operation failure at Error level (fields
// "error", err) and writes the standard 500 Problem{Detail: "database
// error"} response — the repeated
// `h.logger.Error(logMsg, "error", err); WriteProblem(w, r, &Problem{Status: 500, Detail: "database error"})`
// pattern used across the admin/user handlers.
func WriteDBErr(w http.ResponseWriter, r *http.Request, logger *slog.Logger, logMsg string, err error) {
	logger.Error(logMsg, "error", err)
	WriteProblem(w, r, &Problem{Status: http.StatusInternalServerError, Detail: "database error"})
}

// WriteError now emits an RFC 7807 application/problem+json response
// (via WriteProblemStatus): type about:blank, title StatusText(code),
// detail msg, status code.
//
// Deprecated: Use WriteProblem with an RFC 7807 Problem instead.
// WriteError produces only a minimal problem (no Instance/Content-Language,
// no typed Type URI); handlers holding r should prefer WriteProblem.
func WriteError(w http.ResponseWriter, code int, msg string) {
	WriteProblemStatus(w, code, msg)
}

// errTrailingJSON reports that more than one JSON document arrived in a
// request body DecodeJSON was asked to read.
var errTrailingJSON = errors.New("json: trailing data after top-level value")

// DecodeJSON reads the request body (capped at 1 MiB) and unmarshals JSON
// into v. Hardening at the shared chokepoint:
//
//   - the body cap is enforced with http.MaxBytesReader and surfaces as
//     *http.MaxBytesError — WriteDecodeError maps it to 413;
//   - a second JSON document after the first is rejected (errTrailingJSON)
//     instead of silently ignored.
//
// Unknown-field TOLERANCE is a deliberate forward-compatibility tradeoff
// (accepted by both triage passes): every caller decodes into a dedicated
// request DTO and takes identity from auth context, never from the body, so
// there is no mass-assignment sink. Flipping strict for all callers changes
// the wire contract of every endpoint and needs its own sign-off.
func DecodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errTrailingJSON
	}
	return nil
}

// WriteDecodeError maps a DecodeJSON error to its proper Problem response:
// a body-cap violation becomes 413 (too large), everything else 400 (invalid
// JSON). Callers previously misclassified cap errors as 400 by handling every
// DecodeJSON error identically.
func WriteDecodeError(w http.ResponseWriter, r *http.Request, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		WriteProblem(w, r, &Problem{
			Type:   TypeTooLarge,
			Status: http.StatusRequestEntityTooLarge,
			Detail: "request body exceeds the allowed size",
		})
		return
	}
	WriteProblem(w, r, &Problem{Type: TypeInvalidJSON, Status: http.StatusBadRequest, Detail: "invalid JSON body"})
}

// FieldError describes a single field-level validation error.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ClientIP extracts the client IP address from an HTTP request using the
// env-configured trusted proxy (TRUSTED_PROXY_IP). Thin wrapper over
// clientip.Extract (the shared leaf implementation).
func ClientIP(r *http.Request) string {
	return clientip.Extract(r)
}

// SetUntrustedBlobHeaders hardens a response that streams attacker-supplied
// bytes with an attacker-supplied Content-Type (mail attachment / chat unfurl /
// Drive file content) served from the app origin.
//
// nosniff alone is NOT enough: it only blocks MIME *sniffing* of a mistyped
// body into active content — a blob a user uploaded/mailed with a *correct*
// text/html or image/svg+xml Content-Type still renders as a live document
// when the victim opens the URL as a top-level navigation, executing any
// inline <script> in the app origin under the SPA's script-permissive CSP.
// These download endpoints authenticate via the HttpOnly access_token cookie
// (auth/chain.go), so a top-level navigation DOES carry the victim's session —
// making this a stored-XSS vector across mailboxes and shared Drive/chat spaces.
//
// The `sandbox` CSP puts any such top-level/iframe document in an opaque origin
// with scripts, forms and plugins disabled. A CSP response header applies only
// to documents, never to subresource loads, so an <img>/<video> that points at
// this same URL is unaffected — inline image/media previews keep working while
// only the dangerous open-as-a-document path is neutralized. default-src 'none'
// additionally blocks any subresource an SVG/HTML document might try to fetch.
func SetUntrustedBlobHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
}
