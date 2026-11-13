// admin_federation.go — Pillar C1 Task 8: the admin allow-list/anchor-
// exchange console. GET/POST/DELETE /admin/federation/peers[/{domain}],
// federation.manage-gated (V139, sensitive, outside the SoD class map — the
// drive.view/chat.ediscovery precedent).
//
// federation_allowlist is FORCE RLS deny-all-to-setjoin_app (V138 — no
// membership axis on per-domain transport infrastructure) so List reads run
// on workerPool (BYPASSRLS, the admin_meet_recordings.go W6/W7 carve-out
// shape); workerPool aliases pool until DB_WORKER_DSN is set, so this is
// INERT today. Writes (upsert/delete) go through the SECURITY DEFINER
// federation_peer_set/federation_peer_delete reducers, which is why they run
// on the normal app pool via dbscope.RunUserScoped — the reducer itself
// bypasses RLS on federation_allowlist, this only needs the actor GUC set
// the way every other admin write does it.
//
// Two validations live HERE, not in the reducer (the reducer's own checks
// are a shallow defense-in-depth backstop only):
//   - the real x509 parse of the pasted anchor PEM (the reducer only checks
//     for a "-----BEGIN CERTIFICATE-----" marker);
//   - self-domain refusal against the formalized FederationLocalDomain
//     (Task 5: mailserver/internal/config.Config.FederationLocalDomain,
//     loaded from FEDERATION_LOCAL_DOMAIN — no more direct os.Getenv here).
//     Empty config makes the check a no-op (never matches a real domain),
//     the same "absent env ⇒ inert" posture the SFU proxy / Service static
//     gate use.
package admin

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/audit"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/smime"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/reducererr"
)

// FederationHandler serves the admin federation allow-list console.
type FederationHandler struct {
	pool        *pgxpool.Pool // app pool: RunUserScoped writes (reducers are DEFINER/worker-owned)
	workerPool  *pgxpool.Pool // BYPASSRLS pool: raw reads of federation_allowlist (FORCE RLS deny-all)
	localDomain string        // config.Config.FederationLocalDomain, lowercased+trimmed by the caller; empty = self-domain check is a no-op
	logger      *slog.Logger
}

// NewFederationHandler creates a FederationHandler. localDomain is
// config.Config.FederationLocalDomain (Task 5) — empty when this box has no
// FEDERATION_LOCAL_DOMAIN configured, which makes UpsertPeer's self-domain
// refusal a no-op (never matches a real domain), not a hard requirement.
func NewFederationHandler(pool, workerPool *pgxpool.Pool, localDomain string, logger *slog.Logger) *FederationHandler {
	return &FederationHandler{pool: pool, workerPool: workerPool, localDomain: strings.ToLower(strings.TrimSpace(localDomain)), logger: logger}
}

// requireManageClaims returns claims if the caller holds federation.manage;
// writes 401/403 on failure. Mirrors the ApprovalsHandler/MeetRecordingsHandler
// in-handler gate — defense-in-depth alongside the route-declared middleware.
func (h *FederationHandler) requireManageClaims(w http.ResponseWriter, r *http.Request) (*auth.Claims, bool) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblem(w, r, httputil.NewUnauthorizedProblem("authentication required"))
		return nil, false
	}
	if !claims.HasPermission(permissions.PermFederationManage) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "federation.manage required"})
		return nil, false
	}
	return claims, true
}

// federationPeerResponse is the wire shape for one federation_allowlist row,
// merged with its federation_peer_health() reading. The anchor PEM is NEVER
// echoed back (matches the audit act's fingerprint-only posture) — an admin
// re-pastes the anchor to change it, never round-trips it.
type federationPeerResponse struct {
	PeerDomain        string `json:"peerDomain"`
	Scope             string `json:"scope"`
	Enabled           bool   `json:"enabled"`
	CreatedAt         string `json:"createdAt"`
	UpdatedAt         string `json:"updatedAt"`
	UnackedDepth      *int64 `json:"unackedDepth,omitempty"`
	LastAckAgeSeconds *int64 `json:"lastAckAgeSeconds,omitempty"`
}

// federationPeerHealth is the shape federation_peer_health() returns (NULL
// for a domain with no federation_peers row yet — no traffic ever sent).
type federationPeerHealth struct {
	UnackedDepth      int64 `json:"unackedDepth"`
	LastAckAgeSeconds int64 `json:"lastAckAgeSeconds"`
}

// ListPeers implements GET /admin/federation/peers. federation.manage.
func (h *FederationHandler) ListPeers(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.requireManageClaims(w, r)
	if !ok {
		return
	}
	ctx := r.Context()

	rows, err := h.workerPool.Query(ctx, `
		SELECT peer_domain, scope, enabled, created_at::TEXT, updated_at::TEXT
		  FROM federation_allowlist
		 ORDER BY peer_domain`)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "list federation peers failed", err)
		return
	}
	defer rows.Close()

	out := []federationPeerResponse{}
	for rows.Next() {
		var p federationPeerResponse
		if err := rows.Scan(&p.PeerDomain, &p.Scope, &p.Enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "scan federation peer row failed", err)
			return
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "list federation peers failed", err)
		return
	}

	// Per-peer health (unacked depth / last-ack age) — a second, cheap query
	// per row; the admin allow-list is expected to hold a handful of peers,
	// not thousands, so N+1 here is not worth a JOIN/LATERAL rewrite.
	for i := range out {
		var healthJSON []byte
		if err := h.workerPool.QueryRow(ctx, `SELECT federation_peer_health($1)`, out[i].PeerDomain).Scan(&healthJSON); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "read federation peer health failed", err)
			return
		}
		if healthJSON == nil {
			continue // no federation_peers row yet — no traffic ever sent to this peer
		}
		var health federationPeerHealth
		if err := json.Unmarshal(healthJSON, &health); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "decode federation peer health failed", err)
			return
		}
		out[i].UnackedDepth = &health.UnackedDepth
		out[i].LastAckAgeSeconds = &health.LastAckAgeSeconds
	}

	// AUDITED read (the meet_recordings/ListChannels precedent): browsing
	// the org's cross-org trust-anchor allow-list is itself surveillance-
	// relevant metadata a compliance-conscious deployment expects logged.
	_ = audit.Write(ctx, h.pool, audit.Entry{
		Actor: claims.UserID, Action: "federation_peers_list", TargetType: "federation_peer",
		IP: httputil.ClientIP(r), Tier: "core",
	})

	httputil.WriteJSON(w, http.StatusOK, out)
}

// upsertPeerRequest is the JSON body for POST /admin/federation/peers.
type upsertPeerRequest struct {
	Domain    string `json:"domain"`
	AnchorPEM string `json:"anchorPem"`
	Scope     string `json:"scope"`
	Enabled   bool   `json:"enabled"`
}

// UpsertPeer implements POST /admin/federation/peers (add or update).
// federation.manage. Real x509 parse + self-domain refusal happen here;
// federation_peer_set's own checks are a shallow backstop.
//
// anchorPem is OPTIONAL on an update: the console's own anchor PEM is never
// echoed back to the client (List/GET never sends it), so a one-click
// enable/disable toggle on an EXISTING peer cannot re-submit it. When the
// body's anchorPem is blank AND the domain already has a row, this handler
// reads the peer's current peer_anchor (workerPool, BYPASSRLS — the table is
// FORCE RLS deny-all) and carries it forward unchanged; only scope/enabled
// change. A blank anchorPem for a domain with NO existing row is a real
// error (there is nothing to carry forward) — DES-011's fast-disable need
// does not extend to skipping the anchor on first add.
func (h *FederationHandler) UpsertPeer(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.requireManageClaims(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req upsertPeerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	if domain == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "domain is required"})
		return
	}
	if req.Scope != "dm" && req.Scope != "room" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "scope must be dm or room"})
		return
	}
	if h.localDomain != "" && domain == h.localDomain {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "cannot allow-list this server's own domain"})
		return
	}

	anchorPEM := req.AnchorPEM
	if strings.TrimSpace(anchorPEM) == "" {
		if err := h.workerPool.QueryRow(ctx, `SELECT peer_anchor FROM federation_allowlist WHERE peer_domain = $1`, domain).Scan(&anchorPEM); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "anchor is required for a new peer"})
				return
			}
			httputil.WriteDBErr(w, r, h.logger, "read existing federation peer anchor failed", err)
			return
		}
	}
	// Real x509 parse (the reducer's own check is only a PEM-shape backstop)
	// — reuses smime.Fingerprint (admin_trust_anchors.go's own validator),
	// not a second hand-rolled pem.Decode/x509.ParseCertificate.
	if _, _, _, _, err := smime.Fingerprint(anchorPEM); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "anchor must be a valid PEM-encoded X.509 certificate"})
		return
	}

	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT federation_peer_set($1, $2, $3, $4, $5)`,
			claims.UserID, domain, anchorPEM, req.Scope, req.Enabled)
		return err
	})
	if err != nil {
		if reducererr.WriteClassified(w, r, err) {
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "upsert federation peer failed", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// DeletePeer implements DELETE /admin/federation/peers/{domain}.
// federation.manage. Requires the peer to already be disabled — the reducer
// (BZ208) enforces that lifecycle, this handler just projects it.
func (h *FederationHandler) DeletePeer(w http.ResponseWriter, r *http.Request) {
	claims, ok := h.requireManageClaims(w, r)
	if !ok {
		return
	}
	ctx := r.Context()

	domain := strings.ToLower(strings.TrimSpace(r.PathValue("domain")))
	if domain == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid domain"})
		return
	}

	var deleted bool
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT federation_peer_delete($1, $2)`, claims.UserID, domain).Scan(&deleted)
	})
	if err != nil {
		if reducererr.WriteClassified(w, r, err) {
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "delete federation peer failed", err)
		return
	}
	if !deleted {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "peer not found"})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
