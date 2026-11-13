package drive

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/storage"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/toggle"
)

// sentinel errors used to distinguish an application-level 400/404 signal
// from a genuine reducer/DB error inside a RunUserScoped closure.
var (
	errInvalidField      = errors.New("drive: invalid patch field value")
	errNoRecognizedField = errors.New("drive: no recognized patch field")
	errSpaceNotFound     = errors.New("drive: space not found or caller not a member")
)

const maxBodyBytes = 16 << 10 // 16 KiB — every drive spaces/members/nodes body is small; put_version (Task 20) uses its own larger cap.

// Handler serves /api/drive/* — spaces, membership, tree, nodes, the change
// feed (Task 17), chunk transport (Task 19), and versions/content (Task 20)
// on the same mux. Every reducer call runs under
// dbscope.RunUserScoped(claims.UserID) — the RLS-latent posture (R1-R4 of
// DATABASE_SECURITY.md stays the primary check; V114's FORCE-RLS policies are
// the backstop once the setjoin_app DSN flips).
type Handler struct {
	pool             *pgxpool.Pool // app pool — every route below
	workerPool       *pgxpool.Pool // BYPASSRLS — the ?admin=1 cross-tenant metadata read, AND (P5) the WORM-applied mark-bookkeeping Exec (drive_chunks has no user UPDATE policy, G7); nil-safe
	store            objectStore   // chunk/content object storage seam (Task 19/20); nil-safe for the spaces/members/nodes-only routes
	bucket           string
	jwt              *auth.JWTProvider // native-token minting (Task 17b); nil-safe — wired post-construction via SetJWTProvider
	retention        storage.Retention // P5 G1: gxp Object-Lock apply (worm.go); nil-safe — wired post-construction via SetRetention (SPEC §12-22 fallback: nil means every gxp chunk stays worm-pending, surfaced not silent)
	flags            *toggle.FeatureFlags
	logger           *slog.Logger
	mux              *http.ServeMux
	historyCursorKey [32]byte // process-local HMAC key; cursors are intentionally short-lived across restarts
}

type router interface {
	Handle(pattern string, handler http.Handler)
	HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request))
}

// NewHandler builds the Handler and registers every P1 route on its own
// internal mux, PREFIX-LESS ("GET /drive/spaces", never "/api/drive/spaces")
// — main.go mounts this behind http.StripPrefix("/api", apiMux), so by the
// time ServeHTTP sees a request its path has already had "/api" stripped
// (mirrors the booking registration, cmd/mailserverd/main.go:~2713). store is
// the drive package's own object-storage seam (see chunks.go) — production
// callers pass MinioStore{minioClient}; nil is fine for tests that never hit
// the chunk/content routes.
func NewHandler(pool, workerPool *pgxpool.Pool, store objectStore, bucket string, flags *toggle.FeatureFlags, logger *slog.Logger) *Handler {
	h := &Handler{pool: pool, workerPool: workerPool, store: store, bucket: bucket, flags: flags, logger: logger, mux: http.NewServeMux()}
	if _, err := rand.Read(h.historyCursorKey[:]); err != nil {
		panic("drive: initialize history cursor key: " + err.Error())
	}
	h.registerRoutes(h.mux)
	return h
}

func (h *Handler) registerRoutes(mux router) {
	mux.HandleFunc("GET /drive/spaces", h.listSpaces)
	mux.HandleFunc("POST /drive/spaces", h.createSpace)
	mux.HandleFunc("PATCH /drive/spaces/{id}", h.patchSpace)
	mux.HandleFunc("GET /drive/spaces/{id}/members", h.listMembers)
	mux.HandleFunc("POST /drive/spaces/{id}/members", h.grantMember)
	mux.HandleFunc("DELETE /drive/spaces/{id}/members/{userId}", h.revokeMember)
	mux.HandleFunc("GET /drive/spaces/{id}/tree", h.tree)
	mux.HandleFunc("GET /drive/changes", h.changes)
	mux.HandleFunc("GET /drive/access-invalidations", h.accessInvalidations)
	mux.HandleFunc("GET /drive/visibility-snapshot", h.visibilitySnapshot)
	h.registerACLGovernanceRoutes(mux)
	mux.HandleFunc("GET /drive/nodes", h.nodesMeta) // P2 Task 2: batch node-meta read
	mux.HandleFunc("POST /drive/nodes", h.createNode)
	mux.HandleFunc("PATCH /drive/nodes/{id}", h.patchNode)
	mux.HandleFunc("POST /drive/nodes/{id}/trash", h.trashNode)
	mux.HandleFunc("POST /drive/nodes/{id}/restore", h.restoreNode)
	mux.HandleFunc("DELETE /drive/nodes/{id}", h.destroyNode)
	mux.HandleFunc("HEAD /drive/chunks/{sha256}", h.headChunk)
	mux.HandleFunc("PUT /drive/chunks/{sha256}", h.putChunk)
	h.registerContentRoutes(mux)                                     // Task 20: versions POST/GET, content GET
	mux.HandleFunc("GET /drive/versions/{id}/preview", h.getPreview) // P3 Task 14: office->PDF rendition
	h.registerNativeTokenRoute(mux)                                  // Task 17b: native-token POST
	h.registerBranchRoutes(mux)                                      // P4 Task 9: branches + version labels
	h.registerLockRoutes(mux)                                        // P4 Task 10: locks + watches
	h.registerFolderAdminRoutes(mux)                                 // P4 Task 11: delegated folder admins
	h.registerActivityRoutes(mux)                                    // P4 Task 11: activity feed
	h.registerExportRoutes(mux)                                      // P5 Task 8: export request + single-use consume
	h.registerWormRoutes(mux)                                        // P5 Task 9: audit-chain verify
	h.registerTrashRoutes(mux)                                       // P6 Task 9: admin tier-2 trash
	h.registerSearchRoutes(mux)                                      // P6 Task 10: name search
	h.registerAuditRoutes(mux)                                       // P6 Task 11: audit query/CSV export + alarm CRUD
	h.registerAsOfRoutes(mux)                                        // P6 Task 12: space-as-of-T view + watch list
	h.registerHistoryRoutes(mux)                                     // H0: Drive-owned file History
	h.registerOfficeRoutes(mux)                                      // O1: provider-neutral Office launch control plane
}

// ServeHTTP is the ONE gate every drive route passes through: G5 (per-request
// toggle check — never cached in a constructor) then authentication. Route
// dispatch is delegated to the internal mux.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.flags.IsEnabled(toggle.FeatureDrive) {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	if auth.UserFromContext(r.Context()) == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "authentication required")
		return
	}
	h.mux.ServeHTTP(w, r)
}

// ── shared helpers ───────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeJSONList always writes a JSON array, never `null` (a nil slice
// marshals to null — every list route in this package must return `[]`).
func writeJSONList[T any](w http.ResponseWriter, out []T) {
	if out == nil {
		out = []T{}
	}
	writeJSON(w, http.StatusOK, out)
}
