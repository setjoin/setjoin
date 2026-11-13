// Package httputil provides shared HTTP response helpers consumed by both servers.
package httputil

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"setjoin.com/shared/middleware"
)

// Problem is an RFC 7807 Problem Details object.
type Problem struct {
	Type     string `json:"type"`     // URI to error docs
	Title    string `json:"title"`    // English fallback summary
	Status   int    `json:"status"`   // HTTP status code
	Detail   string `json:"detail"`   // Human-readable explanation
	Instance string `json:"instance"` // Request path

	// InvalidParams is an RFC 7807 section 3 extension for validation errors.
	InvalidParams []FieldError `json:"invalid-params,omitempty"`

	// Remediation gives a bounded next action. CA-3b uses the stable values
	// "terms" and "risk"; reducer-backed APIs may return a safe operator-facing
	// sentence from their structured HINT or the shared class fallback.
	// RemediationTouID is the terms_of_use.id to accept when Remediation=="terms".
	Remediation      string `json:"remediation,omitempty"`
	RemediationTouID int64  `json:"remediation_tou_id,omitempty"`

	// Code is a machine-readable BZ error code for client-actionable reducer
	// failures. It is omitted for unknown/internal failures.
	Code string `json:"code,omitempty"`

	// Retryable states whether repeating the same request without changing its
	// inputs or prerequisites is expected to succeed.
	Retryable *bool `json:"retryable,omitempty"`

	// HolderID is set only on the drive BZ149 (file hard-locked) 423 response
	// — the client's "save as a branch instead" offer needs to name whose
	// checkout is blocking the save. Empty/omitted everywhere else.
	HolderID int64 `json:"holderId,omitempty"`
}

// Standard problem types (RFC 7807 section 4.1).
const (
	TypeValidationFailed   = "https://setjoin.com/errors/validation-failed"
	TypeInvalidEmail       = "https://setjoin.com/errors/invalid-email"
	TypeUnauthorized       = "https://setjoin.com/errors/unauthorized"
	TypeForbidden          = "https://setjoin.com/errors/forbidden"
	TypeTokenExpired       = "https://setjoin.com/errors/token-expired"
	TypeNotFound           = "https://setjoin.com/errors/not-found"
	TypeConflict           = "https://setjoin.com/errors/conflict"
	TypeInternalError      = "https://setjoin.com/errors/internal-error"
	TypeServiceUnavailable = "https://setjoin.com/errors/service-unavailable"
	TypeRateLimited        = "https://setjoin.com/errors/rate-limited"
	TypeCSRFFailed         = "https://setjoin.com/errors/csrf-failed"
	TypeMDMRequired        = "https://setjoin.com/errors/mdm-required"
	TypeMFARequired        = "https://setjoin.com/errors/mfa-required"
	TypeInvalidJSON        = "https://setjoin.com/errors/invalid-json"
	TypeTooLarge           = "https://setjoin.com/errors/too-large"
)

// Identifier for the default problem type per RFC 7807 section 4.2.
const TypeAboutBlank = "about:blank"

// LocaleFromContext is an optional hook for extracting a locale preference
// from an auth context (e.g., claims.LanguagePreference). Set by the
// application server at startup. If nil or returns "", falls back to
// Accept-Language header resolution.
var LocaleFromContext func(context.Context) string

// sanitizeStatus pins a status code into the range http.ResponseWriter can
// actually write. WriteHeader panics per-connection on values outside
// [100, 999]; every in-scope path uses literals today, so an out-of-range
// value can only come from a future hand-built Problem left at zero or fed a
// dynamic number — clamping to 500 keeps that failure a well-formed problem
// response instead of a dropped connection.
func sanitizeStatus(code int) int {
	if code < 100 || code > 599 {
		return http.StatusInternalServerError
	}
	return code
}

// languageTagPattern bounds the Content-Language reflection to a single
// RFC 5646-shaped language tag (language subtags and variants). net/http
// already neutralizes CR/LF, but reflecting an arbitrary Accept-Language
// blob into a response header is unnecessary surface: a value that does not
// match the tag shape falls back to "en".
var languageTagPattern = regexp.MustCompile(`^[A-Za-z]{1,8}(-[A-Za-z0-9]{1,8})*$`)

// sanitizeLanguageTag returns tag unchanged when it is a well-formed single
// language tag, "" otherwise.
func sanitizeLanguageTag(tag string) string {
	tag = strings.TrimSpace(tag)
	if !languageTagPattern.MatchString(tag) {
		return ""
	}
	return tag
}

// WriteProblem writes an RFC 7807 Problem Details JSON response.
// It sets Content-Type: application/problem+json and sets problem.Instance
// to the request path. The status is clamped into the writable range and the
// response defaults to Cache-Control: no-store when the caller set no cache
// policy (see WriteJSON).
func WriteProblem(w http.ResponseWriter, r *http.Request, problem *Problem) {
	problem.Status = sanitizeStatus(problem.Status)
	if problem.Type == "" {
		problem.Type = TypeAboutBlank
	}
	if problem.Title == "" {
		problem.Title = http.StatusText(problem.Status)
	}
	problem.Instance = r.URL.Path

	setNoStoreIfUnset(w)
	w.Header().Set("Content-Type", "application/problem+json")
	if lang := sanitizeLanguageTag(resolveLocale(r)); lang != "" {
		w.Header().Set("Content-Language", lang)
	}
	w.WriteHeader(problem.Status)
	json.NewEncoder(w).Encode(problem)
}

// WriteProblemStatus writes a minimal RFC 7807 application/problem+json response
// WITHOUT a *http.Request (no Instance/Content-Language). For middleware and deep
// call sites that lack r. Handlers holding r should prefer WriteProblem.
func WriteProblemStatus(w http.ResponseWriter, code int, detail string) {
	code = sanitizeStatus(code)
	setNoStoreIfUnset(w)
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(&Problem{Type: TypeAboutBlank, Title: http.StatusText(code), Status: code, Detail: detail})
}

// ParseIDPath parses the r.PathValue(name) path parameter as an int64. On
// parse failure it writes a 400 Problem{Status: 400, Detail: detail} via
// WriteProblem and returns ok=false — callers must return immediately when
// ok is false. This is the exact shape of the repeated
// `id, err := strconv.ParseInt(r.PathValue("id"), 10, 64); if err != nil { ... }`
// call sites that wrote a bare Status+Detail Problem; sites with additional
// validation (e.g. an id<=0 check) or a different response shape (WriteError/
// WriteProblemStatus, extra Problem fields) are left untouched.
func ParseIDPath(w http.ResponseWriter, r *http.Request, name, detail string) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	if err != nil {
		WriteProblem(w, r, &Problem{Status: http.StatusBadRequest, Detail: detail})
		return 0, false
	}
	return id, true
}

// ProblemRequestID returns the request_id from context for inclusion in
// log lines associated with a problem response.
func ProblemRequestID(ctx context.Context) string {
	return middleware.GetRequestID(ctx)
}

// resolveLocale picks the best language:
// LocaleFromContext hook > Accept-Language header > "en". The reflected value
// is sanitized to a single well-formed language tag; anything else falls back
// to "en" so an arbitrary Accept-Language blob is never mirrored into the
// Content-Language response header.
func resolveLocale(r *http.Request) string {
	if LocaleFromContext != nil {
		if lang := LocaleFromContext(r.Context()); lang != "" {
			return lang
		}
	}
	if al := r.Header.Get("Accept-Language"); al != "" {
		if lang := sanitizeLanguageTag(parsePrimaryLanguage(al)); lang != "" {
			return lang
		}
	}
	return "en"
}

// parsePrimaryLanguage extracts the first language tag from an
// Accept-Language header value (before any comma, semicolon, or q=).
func parsePrimaryLanguage(header string) string {
	if i := strings.IndexAny(header, ",;"); i != -1 {
		return strings.TrimSpace(header[:i])
	}
	return strings.TrimSpace(header)
}

// NewValidationProblem creates a 422 problem with field-level extensions.
func NewValidationProblem(detail string, fields []FieldError) *Problem {
	return &Problem{
		Type:          TypeValidationFailed,
		Title:         "Validation Failed",
		Status:        http.StatusUnprocessableEntity,
		Detail:        detail,
		InvalidParams: fields,
	}
}

// NewUnauthorizedProblem creates a 401 problem.
func NewUnauthorizedProblem(detail string) *Problem {
	return &Problem{
		Type:   TypeUnauthorized,
		Title:  "Unauthorized",
		Status: http.StatusUnauthorized,
		Detail: detail,
	}
}

// NewForbiddenProblem creates a 403 problem.
func NewForbiddenProblem(detail string) *Problem {
	return &Problem{
		Type:   TypeForbidden,
		Title:  "Forbidden",
		Status: http.StatusForbidden,
		Detail: detail,
	}
}

// NewNotFoundProblem creates a 404 problem.
func NewNotFoundProblem(detail string) *Problem {
	return &Problem{
		Type:   TypeNotFound,
		Title:  "Not Found",
		Status: http.StatusNotFound,
		Detail: detail,
	}
}

// NewInternalProblem creates a 500 problem with a safe detail.
// Never passes raw err.Error() -- the actual error is logged separately.
func NewInternalProblem() *Problem {
	return &Problem{
		Type:   TypeInternalError,
		Title:  "Internal Server Error",
		Status: http.StatusInternalServerError,
		Detail: "An unexpected error occurred. Please try again.",
	}
}

// NewServiceUnavailableProblem creates a 503 problem.
func NewServiceUnavailableProblem(detail string) *Problem {
	return &Problem{
		Type:   TypeServiceUnavailable,
		Title:  "Service Unavailable",
		Status: http.StatusServiceUnavailable,
		Detail: detail,
	}
}

// NewConflictProblem creates a 409 problem.
func NewConflictProblem(detail string) *Problem {
	return &Problem{
		Type:   TypeConflict,
		Title:  "Conflict",
		Status: http.StatusConflict,
		Detail: detail,
	}
}

// NewRateLimitedProblem creates a 429 problem.
func NewRateLimitedProblem(detail string) *Problem {
	return &Problem{
		Type:   TypeRateLimited,
		Title:  "Too Many Requests",
		Status: http.StatusTooManyRequests,
		Detail: detail,
	}
}

// NewTokenExpiredProblem creates a 401 problem for expired tokens.
func NewTokenExpiredProblem(detail string) *Problem {
	return &Problem{
		Type:   TypeTokenExpired,
		Title:  "Token Expired",
		Status: http.StatusUnauthorized,
		Detail: detail,
	}
}
