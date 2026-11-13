// P5 export-grant routes (spec §7, §9.2): request (mint/route-to-approval)
// and single-use consume. Gated by the same G5 feature.drive check every
// drive route gets in ServeHTTP; the gxp compliance FLOOR (export always
// requires approval on gxp, WORM-pending block) lives in the
// drive_export_request/drive_export_consume reducers — this file is a thin
// translator, same posture as every other route in this package.
package drive

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
)

// registerExportRoutes wires the two P5 export routes.
func (h *Handler) registerExportRoutes(mux router) {
	mux.HandleFunc("POST /drive/export", h.handleExportRequest)
	mux.HandleFunc("GET /drive/export/{token}", h.handleExportConsume)
}

const maxExportBodyBytes = 1 << 10 // 1 KiB — {versionId, action, ttlMinutes}

// mintExportToken returns (plaintextToken, sha256Hex). The plaintext exists
// only in the requester's HTTPS response; the DB stores the hash (spec §6.4).
func mintExportToken() (string, string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", "", fmt.Errorf("mint export token: %w", err)
	}
	tok := base64.RawURLEncoding.EncodeToString(b[:])
	return tok, hashExportToken(tok), nil
}

// hashExportToken is the DB-side identity of a token — never store the
// plaintext (plan Global constraints: "token custody").
func hashExportToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

type exportRequestBody struct {
	VersionID  int64  `json:"versionId"`
	Action     string `json:"action"`
	TTLMinutes int    `json:"ttlMinutes"`
}

// handleExportRequest is POST /api/drive/export. It mints a fresh token
// client-side (crypto/rand — the plaintext never touches the DB), calls
// drive_export_request with the hash, and merges the plaintext token back
// into the reducer's JSON response on BOTH statuses ("granted" and
// "pending"): the approval path mints its grant at DECIDE time from the
// payload's token_hash (a hash cannot be inverted), so the requester must
// receive the plaintext now or lose it — the plan's Global Constraints
// "resolved spec conflict" (§7 said "token only on granted", which is
// unimplementable with hash-only storage). The webmail persists a pending
// token client-side (Task 11, ponytail-flagged: a server-side re-issue verb
// is the upgrade if lost-token complaints show).
func (h *Handler) handleExportRequest(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	r.Body = http.MaxBytesReader(w, r.Body, maxExportBodyBytes)
	var body exportRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	ttl := body.TTLMinutes
	if ttl == 0 {
		ttl = 60 // reducer default — explicit here so the merged response is honest about what TTL applies
	}
	tok, hash, err := mintExportToken()
	if err != nil {
		h.logger.Error("drive: export token mint failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "token mint failed")
		return
	}

	ctx := r.Context()
	var out json.RawMessage
	err = dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT drive_export_request($1, $2, $3, $4, $5)`,
			claims.UserID, body.VersionID, body.Action, hash, ttl).Scan(&out)
	})
	if err != nil {
		h.logger.Error("drive: export request failed",
			"user_id", claims.UserID, "version_id", body.VersionID, "error", err)
		writeDriveProblem(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(mergeJSONField(out, "token", tok))
}

// handleExportConsume is GET /api/drive/export/{token} — single-use,
// BURNING on success (drive_export_consume flips consumed_at in the same
// statement that authorizes the read, before any bytes are streamed — a
// dropped connection wastes the grant, the compliance-safe direction). The
// client must NEVER render this URL as an anchor: a browser/extension
// prefetcher would burn the grant before the user clicks — reached only via
// window.location.assign (Task 11; AUTOPLAN correction #5-Task8).
func (h *Handler) handleExportConsume(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	tok := r.PathValue("token")
	hash := hashExportToken(tok)

	ctx := r.Context()
	var consumed struct {
		VersionID int64  `json:"versionId"`
		Action    string `json:"action"`
		SpaceID   int64  `json:"spaceId"`
	}
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		var out json.RawMessage
		if err := tx.QueryRow(ctx, `SELECT drive_export_consume($1, $2)`, claims.UserID, hash).Scan(&out); err != nil {
			return err
		}
		return json.Unmarshal(out, &consumed)
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}

	vm, manifest, err := h.versionMetaAndManifest(ctx, claims.UserID, consumed.VersionID)
	if err != nil {
		// The consume already burned the grant. A membership gap here (the
		// requester was removed from the space between approve and download)
		// is a real but narrow edge case the P5 spec/pgTAP suite does not
		// cover — surfaces as 404 rather than a silent empty stream.
		h.logger.Warn("drive: export consume succeeded but content lookup failed",
			"version", consumed.VersionID, "error", err)
		httputil.WriteProblemStatus(w, http.StatusNotFound, "content not found")
		return
	}

	name := h.exportNodeName(ctx, claims.UserID, consumed.VersionID)
	contentType := "application/octet-stream"
	if vm.contentType != nil && *vm.contentType != "" {
		contentType = *vm.contentType
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	w.Header().Set("Content-Length", strconv.FormatInt(vm.size, 10))
	w.WriteHeader(http.StatusOK)
	h.streamManifest(ctx, w, manifest, 0, vm.size-1, false)
}

// exportNodeName resolves the file name for Content-Disposition. Best-effort:
// an empty name (lookup failure) degrades to a generic filename rather than
// failing an already-authorized, already-consumed download.
func (h *Handler) exportNodeName(ctx context.Context, userID, versionID int64) string {
	var name string
	err := dbscope.RunUserScoped(ctx, h.pool, userID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT n.name FROM drive_nodes n
			  JOIN drive_files f ON f.node_id = n.id
			  JOIN drive_file_versions v ON v.file_node_id = f.node_id
			 WHERE v.id = $1`, versionID).Scan(&name)
	})
	if err != nil || name == "" {
		return "download"
	}
	return name
}

// mergeJSONField merges a single field into a JSON object response,
// preserving every other field. Falls back to the unmodified input if it is
// not a JSON object — a cosmetic merge must never fail an otherwise-good
// response. Shared by handleExportRequest (token) and postVersion (P5
// wormPending override, content.go).
func mergeJSONField(in json.RawMessage, key string, value any) json.RawMessage {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(in, &m); err != nil {
		return in
	}
	b, err := json.Marshal(value)
	if err != nil {
		return in
	}
	m[key] = b
	out, err := json.Marshal(m)
	if err != nil {
		return in
	}
	return out
}
