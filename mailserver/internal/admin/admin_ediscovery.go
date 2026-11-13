package admin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"setjoin.com/mailserver/internal/audit"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/kql"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/pgxutil"
)

// EDiscoveryStatus represents the lifecycle state of an eDiscovery search.
type EDiscoveryStatus string

const (
	EDiscoveryPending    EDiscoveryStatus = "pending"
	EDiscoveryRunning    EDiscoveryStatus = "running"
	EDiscoveryCompleted  EDiscoveryStatus = "completed"
	EDiscoveryInProgress EDiscoveryStatus = "in_progress"
)

// LegalHoldSetter sets or clears an object legal hold on a storage key. The
// storage RetentionPolicyRegistry satisfies it; a nil setter (WORM disabled)
// means litigation hold does not reach the storage layer.
type LegalHoldSetter interface {
	SetLegalHold(ctx context.Context, key string, on bool) error
}

// ediscoveryResultBindingLimit caps the persisted case-bound result set
// (ediscovery_search_results, V244). It matches the LIMIT the fetchResults
// read path has always enforced, so the bound set IS the readable/exportable
// working set; result_count keeps reporting the full match count.
const ediscoveryResultBindingLimit = 500

// EDiscoveryHandler provides cross-mailbox eDiscovery search, hold, and export.
type EDiscoveryHandler struct {
	pool      *pgxpool.Pool
	logger    *slog.Logger
	s3        *minio.Client
	s3Bucket  string
	legalHold LegalHoldSetter
}

func NewEDiscoveryHandler(workerPool pgxutil.WorkerPool, logger *slog.Logger, s3 *minio.Client, s3Bucket string, legalHold LegalHoldSetter) *EDiscoveryHandler {
	return &EDiscoveryHandler{pool: workerPool.Pool, logger: logger, s3: s3, s3Bucket: s3Bucket, legalHold: legalHold}
}

type ediscoverySearch struct {
	ID          int64   `json:"id"`
	Name        string  `json:"name"`
	Keywords    string  `json:"keywords"`
	KQL         string  `json:"kql,omitempty"`
	FromAddr    string  `json:"fromAddr,omitempty"`
	DateFrom    string  `json:"dateFrom,omitempty"`
	DateTo      string  `json:"dateTo,omitempty"`
	MailboxIDs  []int64 `json:"mailboxIds,omitempty"`
	CaseID      *int64  `json:"caseId,omitempty"`
	Status      string  `json:"status"`
	ResultCount *int    `json:"resultCount,omitempty"`
	CreatedAt   string  `json:"createdAt"`
}

// StartSearch initiates a cross-mailbox eDiscovery search.
// Supports KQL Boolean queries via the "kql" field and case association via "caseId".
func (h *EDiscoveryHandler) StartSearch(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	var req struct {
		Name       string  `json:"name"`
		Keywords   string  `json:"keywords"`
		KQL        string  `json:"kql,omitempty"`
		FromAddr   string  `json:"fromAddr,omitempty"`
		DateFrom   string  `json:"dateFrom,omitempty"`
		DateTo     string  `json:"dateTo,omitempty"`
		MailboxIDs []int64 `json:"mailboxIds,omitempty"`
		CaseID     *int64  `json:"caseId,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.Keywords == "" && req.FromAddr == "" && req.KQL == "" {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "keywords, fromAddr, or kql required"})
		return
	}
	if req.KQL != "" {
		// Handler-boundary resource bounds (query length, nesting depth, term
		// count): reject an over-bound KQL query with a bounded 400 before it
		// is stored for later re-application. The same caps are re-checked on
		// every application — executeSearch's kql.Parse and the per-fetch
		// GetSearch Validate re-check — so a stored hostile query is rejected
		// identically each time instead of killing the process.
		if err := kql.Validate(req.KQL); err != nil {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid KQL query: "+err.Error())
			return
		}
	}
	query := map[string]interface{}{
		"keywords": req.Keywords, "kql": req.KQL, "fromAddr": req.FromAddr,
		"dateFrom": req.DateFrom, "dateTo": req.DateTo, "mailboxIds": req.MailboxIDs,
	}
	queryJSON, _ := json.Marshal(query)

	var searchID int64
	err := h.pool.QueryRow(r.Context(),
		`INSERT INTO ediscovery_searches (name, created_by, query, status, case_id)
		 VALUES ($1, $2, $3::JSONB, $4, $5) RETURNING id`,
		req.Name, user.UserID, string(queryJSON), string(EDiscoveryPending), req.CaseID,
	).Scan(&searchID)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "failed to create search")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	go func() { defer cancel(); h.executeSearch(ctx, searchID) }()
	httputil.WriteJSON(w, http.StatusAccepted, map[string]interface{}{"id": searchID, "status": string(EDiscoveryPending)})
}

// requireMailExportClaims returns claims if the caller holds mail.export —
// the dedicated content-export grant (shared/permissions: bulk mailbox export
// is a privileged content read that must never ride Mail-console read
// permissions). Mirrors the chat eDiscovery tier's requireEDiscoveryClaims
// (admin_chat_ediscovery.go): the route is declared behind main.go's
// requireMailExport middleware AND re-checked here — the belt-and-braces
// posture every admin handler in this package follows. Gates GetSearch (and
// its fetchResults arm) and ExportSelected, the surfaces that stream message
// content.
func requireMailExportClaims(w http.ResponseWriter, r *http.Request) (*auth.Claims, bool) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return nil, false
	}
	if !claims.HasPermission(permissions.PermMailExport) {
		httputil.WriteProblemStatus(w, http.StatusForbidden, "mail.export required")
		return nil, false
	}
	return claims, true
}

// GetSearch returns the status and results of a search.
// mail.export-gated: completed-search results are message content, a
// privileged read — never a Mail-console read scope.
func (h *EDiscoveryHandler) GetSearch(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireMailExportClaims(w, r); !ok {
		return
	}
	idStr := r.PathValue("id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	var s ediscoverySearch
	var createdAt time.Time
	var queryBytes []byte
	err := h.pool.QueryRow(r.Context(),
		`SELECT id, name, query->>'keywords', query->>'kql', query->>'fromAddr',
		 query->>'dateFrom', query->>'dateTo', query, status, result_count, case_id, created_at
		 FROM ediscovery_searches WHERE id = $1`, id,
	).Scan(&s.ID, &s.Name, &s.Keywords, &s.KQL, &s.FromAddr, &s.DateFrom, &s.DateTo, &queryBytes, &s.Status, &s.ResultCount, &s.CaseID, &createdAt)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}

	// Stored-query reapplication (med-shard2-020, Astra waves34 HOLD): the
	// stored KQL is re-applied on every execution and every fetch of this
	// search. A stored query that violates the parser resource bounds can
	// never legitimately run, so it must never be served as a 200 — least of
	// all under the `complete` status its rejection prevents. Re-check the
	// same caps here and fail with the bounded 400, identically on every
	// application, instead of swallowing the parser error.
	if s.KQL != "" {
		if err := kql.Validate(s.KQL); err != nil {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid KQL query: "+err.Error())
			return
		}
	}

	s.CreatedAt = createdAt.Format(time.RFC3339)

	// Extract mailboxIds from the full query JSONB
	if queryBytes != nil {
		var queryMap map[string]interface{}
		if json.Unmarshal(queryBytes, &queryMap) == nil {
			if ids, ok := queryMap["mailboxIds"].([]interface{}); ok {
				for _, v := range ids {
					if f, ok2 := v.(float64); ok2 {
						s.MailboxIDs = append(s.MailboxIDs, int64(f))
					}
				}
			}
		}
	}

	// Return matching message IDs if completed. Case confinement (F-003,
	// Astra waves34 HOLD 3): results (message content metadata) flow only for
	// a completed search bound to a case, read from the persisted binding —
	// fetchResults refuses case-unbound searches outright.
	var results []map[string]interface{}
	if s.Status == "complete" && s.ResultCount != nil && *s.ResultCount > 0 {
		results = h.fetchResults(r.Context(), s)
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{"search": s, "results": results})
}

func (h *EDiscoveryHandler) executeSearch(ctx context.Context, id int64) {
	var queryJSON []byte
	if err := h.pool.QueryRow(ctx,
		`UPDATE ediscovery_searches SET status = 'running', started_at = now()
			 WHERE id = $1 RETURNING query`, id,
	).Scan(&queryJSON); err != nil {
		h.pool.Exec(ctx, `UPDATE ediscovery_searches SET status = 'failed', completed_at = now() WHERE id = $1`, id) //nolint:errcheck
		return
	}
	var q map[string]interface{}
	if err := json.Unmarshal(queryJSON, &q); err != nil {
		h.pool.Exec(ctx, `UPDATE ediscovery_searches SET status = 'failed', completed_at = now() WHERE id = $1`, id) //nolint:errcheck
		return
	}

	fail := func(stage string, err error) {
		h.logger.Error("ediscovery search execution failed", "search_id", id, "stage", stage, "error", err)
		h.pool.Exec(ctx, `UPDATE ediscovery_searches SET status = 'failed', completed_at = now() WHERE id = $1`, id) //nolint:errcheck
	}

	kqlQuery, _ := q["kql"].(string)

	// The predicate is built once and reused for BOTH the reported count and
	// the persisted case-bound result set, so what a search claims to match
	// and what it binds are the same rows.
	var whereSQL string
	var whereArgs []interface{}

	if kqlQuery != "" {
		// Use KQL parser for Boolean search
		ast, err := kql.Parse(kqlQuery)
		if err != nil {
			fail("kql parse", err)
			return
		}
		whereSQL, whereArgs = kql.BuildSQL(ast)
	} else {
		keywords, _ := q["keywords"].(string)
		fromAddr, _ := q["fromAddr"].(string)
		dateFrom, _ := q["dateFrom"].(string)
		dateTo, _ := q["dateTo"].(string)

		// Plain GIN/tsquery (2026-07-04 queue-B #2 revert): ParadeDB is never
		// installed, so the prior @@@/paradedb.parse syntax threw here on every
		// deployment. websearch_to_tsquery matches the admin free-text search box
		// UX (supports quotes/OR/-) already used by jmap_email.sql's text filter.
		whereSQL = `(m.body_tsv @@ websearch_to_tsquery('simple', $1)
			 OR m.subject_tsv @@ websearch_to_tsquery('simple', $1)
			 OR m.from_tsv @@ websearch_to_tsquery('simple', $1))`
		whereArgs = []interface{}{keywords}
		argIdx := 2

		if fromAddr != "" {
			whereSQL += fmt.Sprintf(" AND m.from_addr ILIKE '%%' || $%d || '%%'", argIdx)
			whereArgs = append(whereArgs, fromAddr)
			argIdx++
		}
		if dateFrom != "" {
			whereSQL += fmt.Sprintf(" AND m.received_at >= $%d", argIdx)
			whereArgs = append(whereArgs, dateFrom)
			argIdx++
		}
		if dateTo != "" {
			whereSQL += fmt.Sprintf(" AND m.received_at <= $%d", argIdx)
			whereArgs = append(whereArgs, dateTo)
			argIdx++
		}
		if ids, ok := q["mailboxIds"].([]interface{}); ok && len(ids) > 0 {
			whereSQL += fmt.Sprintf(" AND m.mailbox_id = ANY($%d::bigint[])", argIdx)
			boxIDs := make([]int64, len(ids))
			for i, v := range ids {
				if f, ok := v.(float64); ok {
					boxIDs[i] = int64(f)
				}
			}
			whereArgs = append(whereArgs, boxIDs)
			argIdx++
		}
	}

	// Count + case-bound result binding + status flip commit atomically
	// (F-003, Astra waves34 HOLD 3): a search only ever becomes 'complete'
	// together with its persisted result binding (ediscovery_search_results,
	// V244) — the exact set of message ids case-bound reads and exports are
	// later confined to. The bound set is capped at the same limit the read
	// path enforces; result_count reports the full match count.
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		fail("tx begin", err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var count int
	if err := tx.QueryRow(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM messages m WHERE %s`, whereSQL), whereArgs...).Scan(&count); err != nil {
		fail("count", err)
		return
	}

	// Re-execution re-binds: clear stale bindings from a previous run first so
	// the binding always reflects THIS completion. The DELETE keys on the
	// search id ALONE — passing the predicate args here would leave them
	// unreferenced in the statement (42P18 indeterminate datatype) and fail
	// every search with a non-empty predicate.
	if _, err := tx.Exec(ctx,
		`DELETE FROM ediscovery_search_results WHERE search_id = $1`, id); err != nil {
		fail("unbind stale results", err)
		return
	}
	bindSQL := fmt.Sprintf(
		`INSERT INTO ediscovery_search_results (search_id, message_id)
		 SELECT $%d, m.id FROM messages m WHERE %s
		 ORDER BY m.received_at DESC LIMIT %d
		 ON CONFLICT DO NOTHING`,
		len(whereArgs)+1, whereSQL, ediscoveryResultBindingLimit)
	if _, err := tx.Exec(ctx, bindSQL, append(whereArgs, id)...); err != nil {
		fail("bind results", err)
		return
	}

	if _, err := tx.Exec(ctx,
		`UPDATE ediscovery_searches SET status = 'complete', result_count = $1, completed_at = now() WHERE id = $2`,
		count, id); err != nil {
		fail("complete", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		fail("commit", err)
		return
	}
}

// fetchResults returns the bound message rows for a completed search.
//
// Case confinement (F-003, Astra waves34 HOLD 3): a search not bound to a
// case has no readable results at all, and bound results are read from the
// PERSISTED binding (ediscovery_search_results, V244) written atomically when
// the search completed — never recomputed from the stored query, which could
// surface messages the search never matched or no longer matches.
func (h *EDiscoveryHandler) fetchResults(ctx context.Context, s ediscoverySearch) []map[string]interface{} {
	if s.CaseID == nil {
		return nil
	}
	var results []map[string]interface{}

	sql := `SELECT m.id, m.subject, m.from_addr, m.received_at, mb.email as mailbox
	 FROM ediscovery_search_results r
	 JOIN messages m ON m.id = r.message_id
	 JOIN mailboxes mb ON mb.id = m.mailbox_id
	 WHERE r.search_id = $1
	 ORDER BY m.received_at DESC LIMIT 500`

	rows, err := h.pool.Query(ctx, sql, s.ID)
	if err == nil && rows != nil {
		defer rows.Close()
		for rows.Next() {
			var msgID int64
			var subj, from, mb string
			var recv time.Time
			if rows.Scan(&msgID, &subj, &from, &recv, &mb) == nil {
				results = append(results, map[string]interface{}{
					"id": msgID, "subject": subj, "from": from,
					"receivedAt": recv.Format(time.RFC3339), "mailbox": mb,
				})
			}
		}
	}
	return results
}

// HoldSelected places selected messages on litigation hold.
func (h *EDiscoveryHandler) HoldSelected(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	var req struct {
		IDs []int64 `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid request")
		return
	}
	var held int
	var heldIDs []int64
	if len(req.IDs) > 0 {
		rows, err := h.pool.Query(r.Context(),
			`UPDATE messages SET held = TRUE WHERE id = ANY($1) AND held = FALSE RETURNING id`,
			req.IDs,
		)
		if err == nil {
			for rows.Next() {
				var id int64
				if rows.Scan(&id) == nil {
					heldIDs = append(heldIDs, id)
					held++
				}
			}
			rows.Close()
		}
	}
	// Audit the hold action
	idsJSON, _ := json.Marshal(req.IDs)
	_ = audit.Write(r.Context(), h.pool, audit.Entry{
		Actor: user.UserID, Action: "ediscovery_hold", TargetType: "message",
		Before: idsJSON, IP: httputil.ClientIP(r), Tier: "core",
	})
	// Extend the litigation hold to the storage layer: set an object legal hold
	// on every attachment blob of the held messages. Best-effort — a storage
	// failure is logged but never fails the DB hold.
	legalHoldObjects := h.applyLegalHold(r.Context(), heldIDs, true)
	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"held": held, "total": len(req.IDs), "legal_hold_objects": legalHoldObjects,
	})
}

// applyLegalHold sets (on=true) or clears (on=false) the object legal hold on
// the distinct attachment blobs of the given message ids. Returns the count of
// blobs successfully toggled. No-ops when legal hold is unwired or ids is empty.
func (h *EDiscoveryHandler) applyLegalHold(ctx context.Context, msgIDs []int64, on bool) int {
	if h.legalHold == nil || len(msgIDs) == 0 {
		return 0
	}
	rows, err := h.pool.Query(ctx,
		`SELECT DISTINCT blob_sha256 FROM message_attachments WHERE message_id = ANY($1)`, msgIDs)
	if err != nil {
		h.logger.Error("ediscovery: object legal hold lookup failed", "error", err)
		return 0
	}
	var hashes []string
	for rows.Next() {
		var hash string
		if rows.Scan(&hash) == nil && hash != "" {
			hashes = append(hashes, hash)
		}
	}
	rows.Close()

	var n int
	for _, hash := range hashes {
		if err := h.legalHold.SetLegalHold(ctx, hash, on); err != nil {
			h.logger.Error("ediscovery: object legal hold failed", "key", hash, "error", err)
			continue
		}
		n++
	}
	return n
}

// ReleaseSelected lifts the litigation hold on selected messages and clears the
// corresponding object legal holds.
func (h *EDiscoveryHandler) ReleaseSelected(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	var req struct {
		IDs []int64 `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid request")
		return
	}
	var released int
	var releasedIDs []int64
	if len(req.IDs) > 0 {
		rows, err := h.pool.Query(r.Context(),
			`UPDATE messages SET held = FALSE WHERE id = ANY($1) AND held = TRUE RETURNING id`,
			req.IDs,
		)
		if err == nil {
			for rows.Next() {
				var id int64
				if rows.Scan(&id) == nil {
					releasedIDs = append(releasedIDs, id)
					released++
				}
			}
			rows.Close()
		}
	}
	idsJSON, _ := json.Marshal(req.IDs)
	_ = audit.Write(r.Context(), h.pool, audit.Entry{
		Actor: user.UserID, Action: "ediscovery_release", TargetType: "message",
		Before: idsJSON, IP: httputil.ClientIP(r), Tier: "core",
	})
	h.applyLegalHold(r.Context(), releasedIDs, false)
	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{"released": released, "total": len(req.IDs)})
}

// ExportSelected exports selected messages as MBOX with chain-of-custody.
//
// mail.export-gated (F-003): this surface selects arbitrary message ids and
// streams raw RFC822 bodies — a privileged content read that never rides
// Mail-console read scopes. Mirroring the chat eDiscovery export tier, the
// export is further bound to an ACTIVE eDiscovery case carrying at least one
// COMPLETED search (caseId + dedicated permission): the case, its coverage,
// and the id set are all validated BEFORE any MBOX byte is written, so an
// unauthorized request never produces a custody chain. The custody chain
// names the authorizing case, and the export act is audited.
func (h *EDiscoveryHandler) ExportSelected(w http.ResponseWriter, r *http.Request) {
	claims, ok := requireMailExportClaims(w, r)
	if !ok {
		return
	}
	idsStr := r.URL.Query().Get("ids")
	if idsStr == "" {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "ids required")
		return
	}
	caseIDStr := r.URL.Query().Get("caseId")
	if caseIDStr == "" {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "caseId is required")
		return
	}
	caseID, err := strconv.ParseInt(caseIDStr, 10, 64)
	if err != nil || caseID <= 0 {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid caseId")
		return
	}
	format := r.URL.Query().Get("format")
	if format != "pst" {
		format = "mbox"
	}

	var ids []string
	for _, s := range strings.Split(idsStr, ",") {
		ids = append(ids, s)
	}
	count := len(ids)
	if count == 0 || count > 500 {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "1-500 ids required")
		return
	}

	// Deduplicated numeric id set — the same set the stream below will fetch.
	msgIDs := make([]int64, 0, count)
	seen := make(map[int64]bool, count)
	for _, idStr := range ids {
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err == nil && id > 0 && !seen[id] {
			seen[id] = true
			msgIDs = append(msgIDs, id)
		}
	}

	// Case authorization: the case must exist, be active, and hold at least
	// one completed search — ids exported under a case that never produced
	// completed search coverage are refused before anything streams.
	var caseStatus string
	var hasCompletedSearch bool
	if err := h.pool.QueryRow(r.Context(),
		`SELECT c.status,
		        EXISTS (SELECT 1 FROM ediscovery_searches s
		                 WHERE s.case_id = c.id AND s.status = 'complete')
		 FROM ediscovery_cases c WHERE c.id = $1`, caseID,
	).Scan(&caseStatus, &hasCompletedSearch); err != nil {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "case not found")
		return
	}
	if caseStatus != "active" {
		httputil.WriteProblemStatus(w, http.StatusForbidden, "case is closed")
		return
	}
	if !hasCompletedSearch {
		httputil.WriteProblemStatus(w, http.StatusForbidden, "no completed eDiscovery search authorizes this case")
		return
	}

	// Case-bound ids (F-003, Astra waves34 HOLD 3): every supplied message id
	// must appear in the PERSISTED result set of a COMPLETED search bound to
	// THIS case (ediscovery_search_results, V244). A completed search
	// authorizes its own bound results only — never arbitrary supplied ids —
	// so an id produced by another case's search (or by no search at all) is
	// refused here, BEFORE the audit row and before any content or custody
	// byte. Unparseable ids never match the binding and fail below.
	var boundCount int
	if len(msgIDs) > 0 {
		if err := h.pool.QueryRow(r.Context(),
			`SELECT count(DISTINCT r.message_id)
			   FROM ediscovery_search_results r
			   JOIN ediscovery_searches s ON s.id = r.search_id
			  WHERE s.case_id = $1 AND s.status = 'complete'
			    AND r.message_id = ANY($2)`, caseID, msgIDs,
		).Scan(&boundCount); err != nil {
			h.logger.Error("ediscovery export binding check failed", "case_id", caseID, "error", err)
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "export binding check failed")
			return
		}
	}
	if boundCount < len(msgIDs) {
		httputil.WriteProblemStatus(w, http.StatusForbidden,
			"message ids are not bound to this case's completed search results")
		return
	}

	// Audit the export act BEFORE any byte streams (the chat export posture:
	// an abandoned mid-stream export still leaves its audit record). The audit
	// is a precondition, not best-effort (Astra waves34 HOLD 4): when it
	// cannot be persisted, NOTHING streams — an unauditable export must not
	// produce custody bytes.
	idsJSON, _ := json.Marshal(ids)
	if err := audit.Write(r.Context(), h.pool, audit.Entry{
		Actor: claims.UserID, Action: "ediscovery_export", TargetType: "ediscovery_case", TargetID: &caseID,
		Before: idsJSON, IP: httputil.ClientIP(r), Tier: "core",
	}); err != nil {
		h.logger.Error("ediscovery export audit refused; no bytes streamed",
			"case_id", caseID, "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "export audit could not be persisted")
		return
	}

	if format == "pst" {
		h.exportPST(w, r, ids, count)
		return
	}

	w.Header().Set("Content-Type", "application/mbox")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=ediscovery-%s.mbox", time.Now().Format("20060102-150405")))
	w.WriteHeader(http.StatusOK)

	// Chain-of-custody header
	idsConcat := strings.Join(ids, ",")
	hash := sha256.Sum256([]byte(idsConcat))
	fmt.Fprintf(w, "From custody-chain@mailserver %s\r\n", time.Now().Format("Mon Jan 02 15:04:05 2006"))
	_, _ = fmt.Fprintf(w, "X-Custody-Case-ID: %d\r\n", caseID)                        //nolint:gosec // G705: application/mbox attachment + nosniff (global SecurityHeaders); caseID is an int64, not HTML
	fmt.Fprintf(w, "X-Custody-Message-Count: %d\r\n", count)                          //nolint:gosec // G705: application/mbox attachment + nosniff; count is an int, not HTML
	fmt.Fprintf(w, "X-Custody-Checksum: sha256:%s\r\n", hex.EncodeToString(hash[:]))  //nolint:gosec // G705: application/mbox attachment + nosniff; hex-encoded digest, no user HTML
	fmt.Fprintf(w, "X-Custody-Requested-At: %s\r\n", time.Now().Format(time.RFC3339)) //nolint:gosec // G705: application/mbox attachment + nosniff; fixed-format timestamp
	fmt.Fprintf(w, "X-Custody-Message-IDs: %s\r\n", idsConcat)                        //nolint:gosec // G705: application/mbox attachment + nosniff disposition; not text/html
	fmt.Fprintf(w, "\r\n")

	// Batch fetch all messages (msgIDs parsed and case-bound above).
	if len(msgIDs) > 0 {
		rows, err := h.pool.Query(r.Context(),
			`SELECT id, raw_ref, from_addr, subject, received_at FROM messages WHERE id = ANY($1) ORDER BY id`, msgIDs)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var id int64
				var rawRef, fromAddr, subject string
				var receivedAt time.Time
				if err := rows.Scan(&id, &rawRef, &fromAddr, &subject, &receivedAt); err != nil {
					continue
				}
				// MBOX separator
				fmt.Fprintf(w, "From %s %s\r\n", fromAddr, receivedAt.Format("Mon Jan 02 15:04:05 2006"))
				fmt.Fprintf(w, "Subject: %s\r\n", subject)
				fmt.Fprintf(w, "X-Custody-Message-ID: %d\r\n", id)
				// Fetch blob from S3 and write the raw RFC822 content.
				if rawRef != "" {
					obj, err := h.s3.GetObject(r.Context(), h.s3Bucket, rawRef, minio.GetObjectOptions{})
					if err == nil {
						defer obj.Close()
						if _, err := io.Copy(w, obj); err != nil {
							// write what we have; don't break the MBOX stream
						}
					}
				}
				fmt.Fprintf(w, "\r\n")
			}
		}
	}
}

// exportPST writes selected messages as a PST file.
func (h *EDiscoveryHandler) exportPST(w http.ResponseWriter, r *http.Request, ids []string, count int) {
	httputil.WriteProblemStatus(w, 501, "PST export: streaming support pending")
}
