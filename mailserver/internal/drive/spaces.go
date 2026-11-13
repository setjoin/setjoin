package drive

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
)

// ── spaces ───────────────────────────────────────────────────────────────

type spaceOut struct {
	ID                      int64    `json:"id"`
	Name                    string   `json:"name"`
	IsPersonal              bool     `json:"isPersonal"`
	Classification          string   `json:"classification"`
	Role                    string   `json:"role"`
	UsedBytes               int64    `json:"usedBytes"`
	QuotaBytes              *int64   `json:"quotaBytes,omitempty"`
	ChangeSeq               int64    `json:"changeSeq"`
	ACLMode                 string   `json:"aclMode"`
	ACLEpoch                int64    `json:"aclEpoch"`
	RootCapabilities        []string `json:"rootCapabilities"`
	AccessGovernanceEnabled bool     `json:"accessGovernanceEnabled"`
	// WormPending is the count of gxp chunks whose Object-Lock apply is still
	// outstanding (G1). Only populated on the ?admin=1 read (0 elsewhere → the
	// omitempty drops it); the admin compliance queue reads it per space.
	WormPending int64 `json:"wormPending,omitempty"`
}

// listSpaces auto-provisions the caller's personal space (idempotent — the
// V114 partial unique index makes a second call a no-op read) then returns
// every space the caller is a member of, personal pinned first. ?admin=1
// switches to the all-spaces metadata variant for a drive.view admin
// (workerPool, BYPASSRLS — no member join, role reported as "admin").
//
// Chat A2 Task 5 (Grill D1): a chat-bound space (chat_channel_id NOT NULL)
// is EXCLUDED from both variants, always — it is reached only through chat
// (attachment chip) plus a per-file "Open in Drive" deep-link, never browsed
// as a Drive workspace (DES-009 D5). Hundreds of auto-provisioned per-channel
// spaces must not flood a user's space list or the admin console.
func (h *Handler) listSpaces(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	ctx := r.Context()

	if r.URL.Query().Get("admin") == "1" {
		h.listSpacesAdmin(w, r, claims.UserID)
		return
	}

	var out []spaceOut
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		var displayName string
		if err := tx.QueryRow(ctx, `SELECT display_name FROM users WHERE id = $1`, claims.UserID).Scan(&displayName); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT drive_space_create($1, $2, 'regular', true)`, claims.UserID, displayName); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `
			SELECT s.id, s.name, s.is_personal, s.classification,
			       drive_space_access_role($1,s.id),
			       s.used_bytes, s.quota_bytes, s.change_seq,s.acl_mode,g.epoch,
			       ARRAY(SELECT c FROM unnest(drive_acl_capability_catalog()) c
			              WHERE drive_runtime_has_space_root_capability($1,s.id,c)),
			       COALESCE((SELECT enabled FROM feature_toggles
			                 WHERE key='feature.drive_access_governance'),false)
			  FROM drive_spaces s
			  JOIN drive_acl_generations g ON g.space_id=s.id
			 -- meeting_id IS NULL: a meeting-bound space is chat-bound-space
			 -- parity (DES-009 D5) — reached via /meet content deep-links only,
			 -- never browsed as a general Drive workspace (B2 spec §5).
			 WHERE s.chat_channel_id IS NULL AND s.meeting_id IS NULL
			   AND drive_user_has_space_access($1,s.id)
			 ORDER BY s.is_personal DESC, s.name`, claims.UserID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var sp spaceOut
			if err := rows.Scan(&sp.ID, &sp.Name, &sp.IsPersonal, &sp.Classification, &sp.Role, &sp.UsedBytes, &sp.QuotaBytes, &sp.ChangeSeq, &sp.ACLMode, &sp.ACLEpoch, &sp.RootCapabilities, &sp.AccessGovernanceEnabled); err != nil {
				return err
			}
			out = append(out, sp)
		}
		return rows.Err()
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	writeJSONList(w, out)
}

// listSpacesAdmin serves the ?admin=1 cross-tenant metadata read: probe
// drive.view on the app (RLS-scoped) pool, then read on the worker
// (BYPASSRLS) pool — the same two-pool split the approval package uses for
// its own admin-visibility carve-outs.
func (h *Handler) listSpacesAdmin(w http.ResponseWriter, r *http.Request, userID int64) {
	ctx := r.Context()
	var hasPerm bool
	err := dbscope.RunUserScoped(ctx, h.pool, userID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT drive_has_admin_perm($1, 'drive.view')`, userID).Scan(&hasPerm)
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	if !hasPerm {
		httputil.WriteProblem(w, r, httputil.NewForbiddenProblem("drive.view required"))
		return
	}
	if h.workerPool == nil {
		httputil.WriteProblemStatus(w, http.StatusServiceUnavailable, "admin read pool unavailable")
		return
	}
	// Grill D1: chat-bound spaces are hidden from the admin list too — an
	// auto-provisioned per-channel space is chat-governed, not a general
	// Drive workspace, and hundreds of them would flood the console. B2
	// extends the same hide to meeting-bound spaces (DES-009 D5 parity).
	rows, err := h.workerPool.Query(ctx, `
		SELECT s.id,s.name,s.is_personal,s.classification,'admin',s.used_bytes,s.quota_bytes,
		       s.change_seq,s.acl_mode,g.epoch,ARRAY[]::text[],false
		  FROM drive_spaces s JOIN drive_acl_generations g ON g.space_id=s.id
		 WHERE s.chat_channel_id IS NULL AND s.meeting_id IS NULL ORDER BY s.is_personal DESC,s.name`)
	if err != nil {
		h.logger.Error("drive: admin space list failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()
	var out []spaceOut
	for rows.Next() {
		var sp spaceOut
		if err := rows.Scan(&sp.ID, &sp.Name, &sp.IsPersonal, &sp.Classification, &sp.Role, &sp.UsedBytes, &sp.QuotaBytes, &sp.ChangeSeq, &sp.ACLMode, &sp.ACLEpoch, &sp.RootCapabilities, &sp.AccessGovernanceEnabled); err != nil {
			h.logger.Error("drive: admin space list scan failed", "error", err)
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
			return
		}
		out = append(out, sp)
	}
	if err := rows.Err(); err != nil {
		h.logger.Error("drive: admin space list iterate failed", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}
	// Merge per-space WORM-pending counts (G1 admin visibility). One DEFINER
	// call returns every space's pending count for a drive.view admin; a failure
	// here degrades to 0/clean rather than failing the whole list.
	var wormJSON []byte
	if err := h.workerPool.QueryRow(ctx, `SELECT drive_worm_pending($1)`, userID).Scan(&wormJSON); err != nil {
		h.logger.Error("drive: worm-pending merge failed (degrading to 0)", "error", err)
	} else {
		var pend []struct {
			SpaceID int64 `json:"spaceId"`
			Pending int64 `json:"pending"`
		}
		if err := json.Unmarshal(wormJSON, &pend); err != nil {
			h.logger.Error("drive: worm-pending decode failed (degrading to 0)", "error", err)
		} else {
			byID := make(map[int64]int64, len(pend))
			for _, p := range pend {
				byID[p.SpaceID] = p.Pending
			}
			for i := range out {
				out[i].WormPending = byID[out[i].ID]
			}
		}
	}
	writeJSONList(w, out)
}

type createSpaceBody struct {
	Name           string          `json:"name"`
	Classification string          `json:"classification"`
	IsPersonal     bool            `json:"isPersonal"`
	RetentionDays  *int            `json:"retentionDays"`
	WormMode       *string         `json:"wormMode"`
	ExportPolicy   json.RawMessage `json:"exportPolicy"`
}

func (h *Handler) createSpace(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var body createSpaceBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if body.Classification == "" {
		body.Classification = "regular"
	}
	policy := body.ExportPolicy
	if len(policy) == 0 {
		policy = json.RawMessage(`{}`)
	}

	var id int64
	ctx := r.Context()
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT drive_space_create($1, $2, $3, $4, $5, $6, $7)`,
			claims.UserID, body.Name, body.Classification, body.IsPersonal, body.RetentionDays, body.WormMode, string(policy)).Scan(&id)
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

// patchSpace is field-driven (spec §7): a "classification" key routes to
// drive_space_set_classification; exportPolicy/retentionDays/wormMode/
// vaultQuotaMb route to drive_space_set_policy; "quotaBytes" routes to
// drive_space_set_quota (its own BZ140 gates the drive.manage perm). Presence
// (not zero-value) decides the route, so the body is decoded as a raw field
// map first.
func (h *Handler) patchSpace(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	spaceID, ok := httputil.ParseIDPath(w, r, "id", "invalid space id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var fields map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&fields); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}

	ctx := r.Context()
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		if raw, present := fields["classification"]; present {
			var classification string
			if err := json.Unmarshal(raw, &classification); err != nil {
				return errInvalidField
			}
			_, err := tx.Exec(ctx, `SELECT drive_space_set_classification($1, $2, $3)`, claims.UserID, spaceID, classification)
			return err
		}
		if _, hasExport := fields["exportPolicy"]; hasExport {
			return h.execSetPolicy(ctx, tx, claims.UserID, spaceID, fields)
		}
		if _, hasRet := fields["retentionDays"]; hasRet {
			return h.execSetPolicy(ctx, tx, claims.UserID, spaceID, fields)
		}
		if _, hasWorm := fields["wormMode"]; hasWorm {
			return h.execSetPolicy(ctx, tx, claims.UserID, spaceID, fields)
		}
		if _, hasVault := fields["vaultQuotaMb"]; hasVault {
			return h.execSetPolicy(ctx, tx, claims.UserID, spaceID, fields)
		}
		if raw, present := fields["quotaBytes"]; present {
			var quotaBytes *int64
			if err := json.Unmarshal(raw, &quotaBytes); err != nil {
				return errInvalidField
			}
			_, err := tx.Exec(ctx, `SELECT drive_space_set_quota($1, $2, $3)`, claims.UserID, spaceID, quotaBytes)
			return err
		}
		return errNoRecognizedField
	})
	if err != nil {
		if err == errInvalidField || err == errNoRecognizedField {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "no recognized patch field"})
			return
		}
		writeDriveProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) execSetPolicy(ctx context.Context, tx pgx.Tx, userID, spaceID int64, fields map[string]json.RawMessage) error {
	policy := json.RawMessage(`{}`)
	if raw, ok := fields["exportPolicy"]; ok {
		policy = raw
	}
	var retentionDays *int
	if raw, ok := fields["retentionDays"]; ok {
		if err := json.Unmarshal(raw, &retentionDays); err != nil {
			return errInvalidField
		}
	}
	var wormMode *string
	if raw, ok := fields["wormMode"]; ok {
		if err := json.Unmarshal(raw, &wormMode); err != nil {
			return errInvalidField
		}
	}
	var vaultQuotaMb *int
	if raw, ok := fields["vaultQuotaMb"]; ok {
		if err := json.Unmarshal(raw, &vaultQuotaMb); err != nil {
			return errInvalidField
		}
	}
	_, err := tx.Exec(ctx, `SELECT drive_space_set_policy($1, $2, $3, $4, $5, $6)`,
		userID, spaceID, string(policy), retentionDays, wormMode, vaultQuotaMb)
	return err
}
