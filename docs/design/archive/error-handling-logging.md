# Error Handling & Logging Standard — Design Spec

Date: 2026-06-05
Status: Design

## Goal

Standardize all error responses on RFC 7807 (Problem Details for HTTP APIs), enforce request ID propagation, eliminate raw `err.Error()` leakage to clients, and standardize structured logging with context. Fix 50+ error/logging findings from the full-codebase quality audit.

## Architecture

Single error response type used by every handler. Single request ID propagated through every request. Single logging pattern used everywhere.

```
Client → Request ID middleware → Handler → WriteProblem(w, r, problem)
                │                     │
                └── X-Request-ID      └── slog.ErrorContext(ctx, ...)
                    in response           includes request_id + user_id
```

## RFC 7807 Problem Details

### Type

```go
// shared/httputil/problem.go

type Problem struct {
    Type     string `json:"type"`     // URI to error docs
    Title    string `json:"title"`    // English fallback summary
    Status   int    `json:"status"`   // HTTP status code
    Detail   string `json:"detail"`   // Localized human-readable explanation
    Instance string `json:"instance"` // Request path
}
```

### Usage

```go
func WriteProblem(w http.ResponseWriter, r *http.Request, problem *Problem) {
    problem.Instance = r.URL.Path
    claims, _ := auth.UserFromContext(r.Context())
    problem.Detail = localizeDetail(problem.Type, problem.Detail, resolverLocale(r, claims))
    w.Header().Set("Content-Type", "application/problem+json")
    w.Header().Set("Content-Language", resolverLocale(r, claims))
    w.WriteHeader(problem.Status)
    json.NewEncoder(w).Encode(problem)
}
```

### Standard error types

```go
// Validation
TypeValidationFailed = "https://setjoin.com/errors/validation-failed"
TypeInvalidEmail     = "https://setjoin.com/errors/invalid-email"

// Auth
TypeUnauthorized     = "https://setjoin.com/errors/unauthorized"
TypeForbidden        = "https://setjoin.com/errors/forbidden"
TypeTokenExpired     = "https://setjoin.com/errors/token-expired"

// Resource
TypeNotFound         = "https://setjoin.com/errors/not-found"
TypeConflict         = "https://setjoin.com/errors/conflict"

// Server
TypeInternalError    = "https://setjoin.com/errors/internal-error"
TypeServiceUnavailable = "https://setjoin.com/errors/service-unavailable"
```

### Localization

Language resolution priority:
1. User's account language preference (`users.language_preference`)
2. `Accept-Language` header from browser/app
3. Server default (`en`)

i18n keys are server-side translations of the error detail. Keys exist in `en.ts`, `zh.ts`, `de.ts`. Same translation files, shared between client and server via Go embed.

### Migration from current patterns

```go
// Pattern 1: http.Error (no-no — leaks raw errors)
// Before:  http.Error(w, "webauthn error: " + err.Error(), 500)
// After:   WriteProblem(w, r, &Problem{
//              Type: TypeInternalError, Title: "Internal Server Error",
//              Status: 500, Detail: "An unexpected error occurred",
//          })

// Pattern 2: httputil.WriteError (generic)
// Before:  httputil.WriteError(w, 400, "invalid email")
// After:   WriteProblem(w, r, &Problem{
//              Type: TypeInvalidEmail, Title: "Invalid Email",
//              Status: 400, Detail: "Email address '" + sanitize(email) + "' is invalid",
//          })

// Pattern 3: Raw error logging (no context)
// Before:  logger.Error("deliver failed", "rcpt", rcpt, "error", err)
// After:   slog.ErrorContext(ctx, "deliver failed",
//              "request_id", RequestIDFromContext(ctx),
//              "user_id", claims.UserID,
//              "error", err,
//          )
```

## Request ID Propagation

Every inbound request gets a UUID. Passed through context. Included in every log line and every error response.

```go
// shared/middleware/requestid.go

func RequestID(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        id := uuid.New().String()
        w.Header().Set("X-Request-ID", id)
        ctx := context.WithValue(r.Context(), ctxKeyRequestID, id)
        logger := slog.Default().With("request_id", id)
        ctx = context.WithValue(ctx, ctxKeyLogger, logger)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

Applied at the top of the middleware stack in `main.go`, before auth.

## Logging Standard

### Required fields

Every log line produced during an authenticated request MUST include:
- `request_id` — from context
- `user_id` — from Claims, "anon" if unauthenticated

### Pattern

```go
// Before (current — 14+ variants):
logger.Error("mdm: list devices failed", "error", err)
c.srv.logger.Warn("external sender check failed", "from", headers.fromAddr)

// After (standardized):
slog.ErrorContext(ctx, "list devices failed",
    "request_id", middleware.RequestIDFromContext(ctx),
    "user_id", claims.UserID,
    "error", err,
)
```

### What gets redacted

- Email addresses in log values: truncated to `u***@domain`
- Passwords, tokens, secrets: never logged (caught by `LogValue()` methods returning `"***REDACTED***"`)
- IP addresses: logged as-is (required for audit/security, already hashed in some contexts)

### Error payload policy

- `err.Error()` is NEVER sent directly to clients
- Internal errors log the full error with context, return generic `"An unexpected error occurred"`
- Validation errors return specific, user-friendly, localized messages
- Debug details only in `SETJOIN_DEV=true` mode

## Client Handling

All four clients parse the same JSON format:

```
Webmail (JS):
  const problem = await res.json();
  toast.error(problem.detail);  // Already localized by server

iOS (Swift):
  let problem = try JSONDecoder().decode(Problem.self, from: data)
  // Switch on problem.type for specific behaviors:
  //   token-expired → redirect to login
  //   rate-limited  → show retry timer
  //   default       → show problem.detail

Android (Kotlin):
  val problem = json.decodeFromString<Problem>(errorBody)
  showError(problem.detail)
```

## Audit Trail

Validation failures and auth errors are logged to `admin_audit_log`:
```json
{
  "event_type": "error_response",
  "problem_type": "https://setjoin.com/errors/validation-failed",
  "status": 400,
  "detail": "Email address '...' is invalid",
  "request_id": "req_a1b2c3d4",
  "user_id": 42
}
```

## New Files

```
shared/httputil/problem.go         — WriteProblem, problem types, localization
shared/httputil/problem_test.go
shared/middleware/requestid.go     — Request ID middleware
```

## Modified Files

~50 handler files: replace `http.Error` and `httputil.WriteError` with `WriteProblem`. Replace bare `slog.Error` with `slog.ErrorContext`.

## References

- RFC 7807 — Problem Details for HTTP APIs (saved at docs/ref/rfcs/rfc7807-problem-details.txt)
- `mailserver/webmail/src/lib/i18n/` — existing i18n keys (en.ts, zh.ts, de.ts)
- `shared/httputil/httputil.go:25` — existing WriteError (deprecated by this spec)
- Audit findings: 50+ error/logging gaps from quality audit
