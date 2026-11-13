package scim

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/pwhash"
)

// contextKey is a private type for context keys to avoid collisions.
type contextKey string

const (
	ctxTokenID          contextKey = "scim_token_id"   //nolint:gosec // G101: context-key constant, not a credential
	ctxTokenName        contextKey = "scim_token_name" //nolint:gosec // G101: context-key constant, not a credential
	ctxDeletionPolicy   contextKey = "scim_deletion_policy"
	ctxAttributeMapping contextKey = "scim_attribute_mapping"
	ctxSourceID         contextKey = "scim_source_id"
	ctxSourceGeneration contextKey = "scim_source_generation"
)

// maxBodyBytes caps every SCIM request body at the repo-standard 1 MiB JSON
// budget (D-MAILSERVER-INTERNAL-SCIM-002, CWE-770). The largest legitimate SCIM
// payloads (User/Group resources with members arrays) sit far below it; SCIM_RATE_LIMIT-style
// env overrides do not apply — raise it only with a matching IdP-side review.
const maxBodyBytes = 1 << 20

// Server holds the SCIM service dependencies.
type Server struct {
	pool           *pgxpool.Pool
	workerPool     *pgxpool.Pool
	logger         *slog.Logger
	authServerURL  string
	internalAPIKey string
	limiter        middleware.Limiter // nil = allow (unit-test / unconfigured), mirrors jmap's decryptLimiter
}

// SetRateLimiter installs the per-IP rate limiter applied OUTSIDE token
// verification: authenticateToken is the unauthenticated CPU cost (bearer
// verification), so the limiter must run before it, exactly like every other
// authenticating surface wires middleware.RateLimit in cmd/mailserverd/main.go.
// Production passes a DB-backed HybridRateLimiter (SCIM_RATE_LIMIT /min per IP).
func (s *Server) SetRateLimiter(l middleware.Limiter) {
	s.limiter = l
}

// NewServer creates a new SCIM server. workerPool is the BYPASSRLS pool used for
// cross-tenant carve-outs (e.g. the welcome-email deliver() into a freshly
// created mailbox); it aliases pool until DB_WORKER_DSN is set, so it is INERT
// until the native-RLS flip.
func NewServer(pool *pgxpool.Pool, workerPool pgxutil.WorkerPool, logger *slog.Logger, authServerURL, internalAPIKey string) *Server {
	return &Server{
		pool:           pool,
		workerPool:     workerPool.Pool,
		logger:         logger,
		authServerURL:  authServerURL,
		internalAPIKey: internalAPIKey,
	}
}

// scimToken is a row from scim_tokens after bcrypt verification.
type scimToken struct {
	ID               int64
	Name             string
	DeletionPolicy   string
	AttributeMapping map[string]interface{}
	SourceID         int64
	SourceGeneration int64
}

// authenticateToken verifies the SCIM Bearer token in two layers (V238):
//
//  1. Indexed fast path — the lowercase hex SHA-256 of the raw token resolves
//     at most ONE candidate row via scim_token_lookup() (partial unique index
//     on token_lookup_hash), then a single bcrypt compare verifies it. O(1)
//     regardless of how many modern tokens exist.
//  2. Legacy fallback — only when the indexed lookup misses, the pre-V238
//     rows (token_lookup_hash IS NULL, surfaced exclusively by
//     scim_list_active_tokens) go through the historical bcrypt scan. That set
//     is fixed at migration time and shrinks to zero as tokens rotate; modern
//     tokens are never scanned.
func (s *Server) authenticateToken(ctx context.Context, rawToken string) (*scimToken, error) {
	sum := sha256.Sum256([]byte(rawToken))
	st, hash, err := s.lookupTokenByHash(ctx, hex.EncodeToString(sum[:]))
	if err != nil {
		return nil, err
	}
	if st != nil {
		// The index only narrowed the candidate; the credential seam remains
		// the verifier.
		if err := bcryptCompare(hash, rawToken); err != nil {
			return nil, nil
		}
		s.recordTokenUsage(st.ID)
		return st, nil
	}

	// Legacy fallback: bcrypt scan over lookup-hash-less (pre-V238) tokens only.
	rows, err := s.pool.Query(ctx,
		`SELECT token_id, name, token_hash, deletion_policy, attribute_mapping,
		        source_id, source_generation
		 FROM scim_list_active_tokens()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var id, sourceID, sourceGeneration int64
		var name, hash, dp string
		var mapping map[string]interface{}

		if err := rows.Scan(&id, &name, &hash, &dp, &mapping, &sourceID, &sourceGeneration); err != nil {
			continue
		}

		// bcrypt compare the raw token against the stored hash
		if err := bcryptCompare(hash, rawToken); err == nil {
			s.recordTokenUsage(id)

			return &scimToken{
				ID:               id,
				Name:             name,
				DeletionPolicy:   dp,
				AttributeMapping: mapping,
				SourceID:         sourceID,
				SourceGeneration: sourceGeneration,
			}, nil
		}
	}

	if rows.Err() != nil {
		return nil, rows.Err()
	}

	return nil, nil // no matching token found
}

// lookupTokenByHash resolves the single indexed candidate row for a token
// lookup hash. It returns (nil, "", nil) when no active token carries the hash.
func (s *Server) lookupTokenByHash(ctx context.Context, lookupHash string) (*scimToken, string, error) {
	var id, sourceID, sourceGeneration int64
	var name, hash, dp string
	var mapping map[string]interface{}

	err := s.pool.QueryRow(ctx,
		`SELECT token_id, name, token_hash, deletion_policy, attribute_mapping,
		        source_id, source_generation
		 FROM scim_token_lookup($1)`, lookupHash,
	).Scan(&id, &name, &hash, &dp, &mapping, &sourceID, &sourceGeneration)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}

	return &scimToken{
		ID:               id,
		Name:             name,
		DeletionPolicy:   dp,
		AttributeMapping: mapping,
		SourceID:         sourceID,
		SourceGeneration: sourceGeneration,
	}, hash, nil
}

// recordTokenUsage asynchronously bumps last_used_at — non-critical.
func (s *Server) recordTokenUsage(tokenID int64) {
	//nolint:gosec // G118: background task outliving request (request ctx would cancel the write)
	go func(tokenID int64) {
		_, _ = s.pool.Exec(context.Background(),
			`SELECT scim_record_token_usage($1)`, tokenID)
	}(tokenID)
}

// Authenticate middleware validates the SCIM Bearer token against the scim_tokens table.
func (s *Server) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			WriteSCIMError(w, http.StatusUnauthorized, "Missing or invalid Authorization header", "invalidToken")
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == "" {
			WriteSCIMError(w, http.StatusUnauthorized, "Empty SCIM token", "invalidToken")
			return
		}

		st, err := s.authenticateToken(r.Context(), token)
		if err != nil {
			s.logger.Error("scim token lookup failed", "error", err)
			WriteSCIMError(w, http.StatusInternalServerError, "Authentication service unavailable", "")
			return
		}
		if st == nil {
			WriteSCIMError(w, http.StatusUnauthorized, "Invalid or expired SCIM token", "invalidToken")
			return
		}

		// Store token metadata in request context
		ctx := context.WithValue(r.Context(), ctxTokenID, st.ID)
		ctx = context.WithValue(ctx, ctxTokenName, st.Name)
		ctx = context.WithValue(ctx, ctxDeletionPolicy, st.DeletionPolicy)
		ctx = context.WithValue(ctx, ctxAttributeMapping, st.AttributeMapping)
		ctx = context.WithValue(ctx, ctxSourceID, st.SourceID)
		ctx = context.WithValue(ctx, ctxSourceGeneration, st.SourceGeneration)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireContentType middleware rejects requests without the SCIM content type.
func (s *Server) RequireContentType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct := r.Header.Get("Content-Type")
		// GET and DELETE don't require a content type
		if r.Method == http.MethodGet || r.Method == http.MethodDelete {
			next.ServeHTTP(w, r)
			return
		}
		if ct != "" && (strings.HasPrefix(ct, ContentTypeSCIM) || strings.HasPrefix(ct, "application/json")) {
			next.ServeHTTP(w, r)
			return
		}
		WriteSCIMError(w, http.StatusBadRequest, "Content-Type must be application/scim+json", "invalidValue")
	})
}

type router interface {
	Handle(pattern string, handler http.Handler)
	HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request))
}

// RegisterRoutes mounts all SCIM endpoints on the provided mux.
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	s.registerRoutes(mux)
}

func (s *Server) registerRoutes(mux router) {
	auth := s.Authenticate
	ct := s.RequireContentType
	// Rate limit OUTSIDE auth (D-MAILSERVER-INTERNAL-SCIM-001): token
	// verification is the unauthenticated CPU cost, so the per-IP limiter must
	// gate it. nil limiter = allow (unit tests / unconfigured), mirroring jmap.
	limit := func(next http.Handler) http.Handler {
		if s.limiter == nil {
			return next
		}
		return middleware.RateLimit(s.limiter)(next)
	}

	// Users endpoints
	mux.Handle("GET /scim/v2/Users", limit(auth(ct(http.HandlerFunc(s.GetUsers)))))
	mux.Handle("POST /scim/v2/Users", limit(auth(ct(http.HandlerFunc(s.CreateUser)))))
	mux.Handle("GET /scim/v2/Users/{id}", limit(auth(ct(http.HandlerFunc(s.GetUser)))))
	mux.Handle("PUT /scim/v2/Users/{id}", limit(auth(ct(http.HandlerFunc(s.ReplaceUser)))))
	mux.Handle("PATCH /scim/v2/Users/{id}", limit(auth(ct(http.HandlerFunc(s.PatchUser)))))
	mux.Handle("DELETE /scim/v2/Users/{id}", limit(auth(ct(http.HandlerFunc(s.DeleteUser)))))

	// Groups endpoints
	mux.Handle("GET /scim/v2/Groups", limit(auth(ct(http.HandlerFunc(s.GetGroups)))))
	mux.Handle("POST /scim/v2/Groups", limit(auth(ct(http.HandlerFunc(s.CreateGroup)))))
	mux.Handle("GET /scim/v2/Groups/{id}", limit(auth(ct(http.HandlerFunc(s.GetGroup)))))
	mux.Handle("PATCH /scim/v2/Groups/{id}", limit(auth(ct(http.HandlerFunc(s.PatchGroup)))))
	mux.Handle("DELETE /scim/v2/Groups/{id}", limit(auth(ct(http.HandlerFunc(s.DeleteGroup)))))

	// ServiceProviderConfig (required by Okta for initial connection validation)
	mux.Handle("GET /scim/v2/ServiceProviderConfig", limit(auth(ct(http.HandlerFunc(s.ServiceProviderConfig)))))
}

// bcryptCompare is a testable wrapper around the shared pwhash credential
// seam. VerifyCredentialHash is the bcrypt-only arm (SCIM tokens are always
// minted bcrypt and must never silently widen to the password seam's SM3
// dispatch); the name keeps the historical test-override seam recognizable.
var bcryptCompare = pwhash.VerifyCredentialHash

// decodeSCIMBody decodes the JSON request body under the 1 MiB MaxBytesReader
// cap shared by every SCIM decode path (D-MAILSERVER-INTERNAL-SCIM-002). It
// writes the SCIM error response and returns false when the body must be
// rejected: 413 at the cap (http.MaxBytesError), 400 for malformed JSON.
func decodeSCIMBody(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(v)
	if err == nil {
		return true
	}
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		WriteSCIMError(w, http.StatusRequestEntityTooLarge,
			"Request body exceeds the 1 MiB SCIM limit", "")
		return false
	}
	WriteSCIMError(w, http.StatusBadRequest, "Invalid JSON body", "invalidSyntax")
	return false
}

// deletionPolicy returns the deletion_policy from the token context, defaulting to "soft".
func deletionPolicy(ctx context.Context) string {
	if v, ok := ctx.Value(ctxDeletionPolicy).(string); ok && v != "" {
		return v
	}
	return "soft"
}
