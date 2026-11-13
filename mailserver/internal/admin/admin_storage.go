package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"setjoin.com/shared/httputil"
)

var seaweedHTTPClient = &http.Client{Timeout: 30 * time.Second}

// StorageHandler provides storage status and DR scan endpoints.
type StorageHandler struct {
	minio     *minio.Client
	masterURL string // SeaweedFS/object storage master API URL
	pool      *pgxpool.Pool
	bucket    string
	logger    *slog.Logger
}

func NewStorageHandler(minio *minio.Client, masterURL string, pool *pgxpool.Pool, bucket string, logger *slog.Logger) *StorageHandler {
	return &StorageHandler{minio: minio, masterURL: masterURL, pool: pool, bucket: bucket, logger: logger}
}

// Status returns SeaweedFS cluster health and storage information.
func (h *StorageHandler) Status(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// SeaweedFS: GET /cluster/status (master API)
	clusterStatus, err := h.seaweedGet(ctx, h.masterURL+"/cluster/status")
	if err != nil {
		h.logger.Error("storage cluster status failed", "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusServiceUnavailable, Detail: "Could not reach object storage. The storage service may be restarting."})
		return
	}

	// SeaweedFS: GET /dir/status (topology + volumes)
	dirStatus, _ := h.seaweedGet(ctx, h.masterURL+"/dir/status")

	// Build simplified response
	var version string
	var topology []map[string]any
	var volumes []map[string]any
	if dirStatus != nil {
		version = stringField(dirStatus, "Version")
		if topo, ok := dirStatus["Topology"].(map[string]any); ok {
			for dcName, dcRaw := range topo {
				dc, _ := dcRaw.(map[string]any)
				dataCenters, _ := dc["DataCenters"].([]any)
				if dataCenters == nil {
					racks := make([]map[string]any, 0)
					for rackName, rackRaw := range dc {
						rack, _ := rackRaw.(map[string]any)
						nodes, _ := rack["DataNodes"].([]any)
						if nodes == nil {
							// Legacy format: flat node list
							continue
						}
						racks = append(racks, map[string]any{
							"name":  rackName,
							"nodes": len(nodes),
						})
						for _, nRaw := range nodes {
							if n, ok := nRaw.(map[string]any); ok {
								vols, _ := n["Volumes"].([]any)
								volumes = append(volumes, map[string]any{
									"url":     n["Url"],
									"volumes": len(vols),
									"free":    n["Free"],
									"max":     n["Max"],
								})
							}
						}
					}
					topology = append(topology, map[string]any{
						"name":  dcName,
						"racks": racks,
					})
					_ = dataCenters
				}
			}
		}
	}

	isLeader := boolField(clusterStatus, "IsLeader")
	leader := stringField(clusterStatus, "Leader")

	resp := map[string]any{
		"mode":     "distributed",
		"version":  version,
		"isLeader": isLeader,
		"leader":   leader,
		"buckets": map[string]any{
			"count": bucketCount(ctx, h.minio),
		},
		"volumes":  volumes,
		"topology": topology,
	}

	httputil.WriteJSON(w, http.StatusOK, resp)
}

// DRScan starts a background scan of MinIO vs the blobs table, plus
// a ref_count reconciliation to detect counter drift.
func (h *StorageHandler) DRScan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var scanID int64
	err := h.pool.QueryRow(ctx,
		`INSERT INTO storage_dr_scans (status) VALUES ('running') RETURNING id`,
	).Scan(&scanID)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "dr scan insert failed", err)
		return
	}

	ctx2, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	go func() { defer cancel(); h.runDRScan(ctx2, scanID) }()

	httputil.WriteJSON(w, http.StatusAccepted, map[string]int64{"id": scanID})
}

func (h *StorageHandler) runDRScan(ctx context.Context, scanID int64) {
	logger := h.logger.With("dr_scan_id", scanID)
	logger.Info("dr scan started")

	// Phase 1: Load all blob SHA-256s into memory for fast comparison
	rows, err := h.pool.Query(ctx, `SELECT sha256 FROM blobs`)
	if err != nil {
		logger.Error("dr scan: failed to load blobs", "error", err)
		h.markScanFailed(ctx, scanID, "failed to load blobs: "+err.Error())
		return
	}
	blobSet := make(map[string]bool, 100000)
	for rows.Next() {
		var sha string
		if err := rows.Scan(&sha); err == nil {
			blobSet[sha] = true
		}
	}
	rows.Close()
	logger.Info("dr scan: loaded blobs", "count", len(blobSet))

	var totalScanned, orphaned, missing, refcountDrift int64
	var details []map[string]any

	// Phase 2: Walk MinIO bucket. Objects in MinIO but not in blobs are orphaned.
	// Objects in blobs but not in MinIO are marked missing after the walk.
	for obj := range h.minio.ListObjects(ctx, h.bucket, minio.ListObjectsOptions{Recursive: true}) {
		if obj.Err != nil {
			logger.Warn("dr scan: list object error", "error", obj.Err)
			continue
		}
		totalScanned++
		key := obj.Key
		if blobSet[key] {
			delete(blobSet, key) // mark as found
		} else {
			// Orphaned: in MinIO but not in blobs table
			orphaned++
			details = append(details, map[string]any{
				"sha256": key,
				"issue":  "orphaned",
				"size":   obj.Size,
			})
		}

		// Update progress every 1000 objects
		if totalScanned%1000 == 0 {
			h.updateScanProgress(ctx, scanID, totalScanned, orphaned, missing, refcountDrift, details)
			details = nil // reset batch to avoid unbounded growth
		}
	}

	// Remaining keys in blobSet are missing from MinIO
	for sha := range blobSet {
		missing++
		details = append(details, map[string]any{
			"sha256": sha,
			"issue":  "missing",
		})
	}

	// Phase 3: ref_count reconciliation — compare blobs.ref_count against
	// the actual attachment row count from message_attachments. A mismatch
	// means the counter drifted, which can happen after a power outage
	// during complex multi-table transactions, or from a bug that inserts
	// or updates message_attachments without going through the trigger.
	//
	// The HAVING clause ensures only drifted rows are returned.
	// A blob with ref_count=0 and zero attachments is normal (queued for
	// cleanup) and is not reported as drift.
	driftRows, err := h.pool.Query(ctx,
		`SELECT b.sha256, b.ref_count, COUNT(ma.id) AS actual
		 FROM blobs b
		 LEFT JOIN message_attachments ma ON ma.blob_sha256 = b.sha256
		 GROUP BY b.sha256, b.ref_count
		 HAVING b.ref_count != COUNT(ma.id)`)
	if err != nil {
		logger.Warn("dr scan: ref_count reconciliation query failed", "error", err)
	} else {
		defer driftRows.Close()
		for driftRows.Next() {
			var sha string
			var expected, actual int64
			if err := driftRows.Scan(&sha, &expected, &actual); err == nil {
				refcountDrift++
				details = append(details, map[string]any{
					"sha256":           sha,
					"issue":            "refcount_drift",
					"refCountExpected": expected,
					"refCountActual":   actual,
				})
			}
		}
	}

	h.completeScan(ctx, scanID, totalScanned, orphaned, missing, refcountDrift, details)
	logger.Info("dr scan completed",
		"total", totalScanned,
		"orphaned", orphaned,
		"missing", missing,
		"refcountDrift", refcountDrift,
	)
}

func (h *StorageHandler) updateScanProgress(ctx context.Context, scanID int64, total, orphaned, missing, refcountDrift int64, details []map[string]any) {
	if len(details) == 0 {
		if _, err := h.pool.Exec(ctx,
			`UPDATE storage_dr_scans SET total_scanned = $1, orphaned_count = $2,
			 missing_count = $3, refcount_drift_count = $4 WHERE id = $5`,
			total, orphaned, missing, refcountDrift, scanID); err != nil {
			h.logger.Warn("dr scan progress update failed", "scan_id", scanID, "error", err)
		}
		return
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		h.logger.Warn("dr scan progress marshal failed", "scan_id", scanID, "error", err)
		return
	}
	if _, err := h.pool.Exec(ctx,
		`UPDATE storage_dr_scans SET total_scanned = $1, orphaned_count = $2,
		 missing_count = $3, refcount_drift_count = $4,
		 details = COALESCE(details, '[]'::jsonb) || $5::jsonb WHERE id = $6`,
		total, orphaned, missing, refcountDrift, detailsJSON, scanID); err != nil {
		h.logger.Warn("dr scan progress update failed", "scan_id", scanID, "error", err)
	}
}

func (h *StorageHandler) completeScan(ctx context.Context, scanID, total, orphaned, missing, refcountDrift int64, details []map[string]any) {
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		h.logger.Warn("dr scan complete marshal failed", "scan_id", scanID, "error", err)
		detailsJSON = []byte("[]")
	}
	if _, err := h.pool.Exec(ctx,
		`UPDATE storage_dr_scans SET status = 'completed', total_scanned = $1,
		 orphaned_count = $2, missing_count = $3, refcount_drift_count = $4,
		 details = COALESCE(details, '[]'::jsonb) || $5::jsonb, completed_at = now() WHERE id = $6`,
		total, orphaned, missing, refcountDrift, detailsJSON, scanID); err != nil {
		h.logger.Error("dr scan complete update failed", "scan_id", scanID, "error", err)
	}
}

func (h *StorageHandler) markScanFailed(ctx context.Context, scanID int64, reason string) {
	if _, err := h.pool.Exec(ctx,
		`UPDATE storage_dr_scans SET status = 'failed', completed_at = now() WHERE id = $1`, scanID); err != nil {
		h.logger.Error("dr scan mark failed update failed", "scan_id", scanID, "error", err)
	}
}

// DRScanGet returns a single scan's status and results.
func (h *StorageHandler) DRScanGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid scan id"})
		return
	}

	var s struct {
		ID                 int64      `json:"id"`
		Status             string     `json:"status"`
		TotalScanned       int64      `json:"totalScanned"`
		OrphanedCount      int64      `json:"orphanedCount"`
		MissingCount       int64      `json:"missingCount"`
		RefcountDriftCount int64      `json:"refcountDriftCount"`
		ReimportedCount    int64      `json:"reimportedCount"`
		Details            []byte     `json:"-"`
		StartedAt          time.Time  `json:"startedAt"`
		CompletedAt        *time.Time `json:"completedAt,omitempty"`
	}
	err = h.pool.QueryRow(ctx,
		`SELECT id, status, total_scanned, orphaned_count, missing_count,
		 refcount_drift_count, reimported_count, details, started_at, completed_at
		 FROM storage_dr_scans WHERE id = $1`, id,
	).Scan(&s.ID, &s.Status, &s.TotalScanned, &s.OrphanedCount, &s.MissingCount,
		&s.RefcountDriftCount, &s.ReimportedCount, &s.Details, &s.StartedAt, &s.CompletedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "scan not found"})
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "dr scan get failed", err)
		return
	}

	resp := map[string]any{
		"id":                 s.ID,
		"status":             s.Status,
		"totalScanned":       s.TotalScanned,
		"orphanedCount":      s.OrphanedCount,
		"missingCount":       s.MissingCount,
		"refcountDriftCount": s.RefcountDriftCount,
		"reimportedCount":    s.ReimportedCount,
		"startedAt":          s.StartedAt,
		"completedAt":        s.CompletedAt,
	}
	var respDetails []map[string]any
	if len(s.Details) > 0 {
		_ = json.Unmarshal(s.Details, &respDetails)
	}
	resp["details"] = respDetails

	httputil.WriteJSON(w, http.StatusOK, resp)
}

// DRScanList returns all scans ordered by most recent.
func (h *StorageHandler) DRScanList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rows, err := h.pool.Query(ctx,
		`SELECT id, status, total_scanned, orphaned_count, missing_count,
		 refcount_drift_count, reimported_count, started_at, completed_at
		 FROM storage_dr_scans ORDER BY started_at DESC LIMIT 100`)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "dr scan list failed", err)
		return
	}
	defer rows.Close()

	out := make([]map[string]any, 0)
	for rows.Next() {
		var id, total, orphaned, missing, refcountDrift, reimported int64
		var status string
		var started time.Time
		var completed *time.Time
		if err := rows.Scan(&id, &status, &total, &orphaned, &missing, &refcountDrift, &reimported, &started, &completed); err == nil {
			item := map[string]any{
				"id": id, "status": status, "totalScanned": total,
				"orphanedCount": orphaned, "missingCount": missing,
				"refcountDriftCount": refcountDrift, "reimportedCount": reimported,
				"startedAt": started,
			}
			if completed != nil {
				item["completedAt"] = completed
			}
			out = append(out, item)
		}
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

// DRScanReconcile re-imports orphaned objects back into the blobs table.
func (h *StorageHandler) DRScanReconcile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid scan id"})
		return
	}

	// Load scan details
	var detailsJSON []byte
	var status string
	err = h.pool.QueryRow(ctx,
		`SELECT status, details FROM storage_dr_scans WHERE id = $1`, id,
	).Scan(&status, &detailsJSON)
	if err != nil {
		if err == pgx.ErrNoRows {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "scan not found"})
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "dr scan reconcile query failed", err)
		return
	}
	if status != "completed" {
		httputil.WriteProblem(w, r, httputil.NewConflictProblem("scan must be completed before reconcile"))
		return
	}

	var details []map[string]any
	if err := json.Unmarshal(detailsJSON, &details); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "invalid scan details"})
		return
	}

	var reimported int64
	for _, d := range details {
		issue, _ := d["issue"].(string)
		if issue != "orphaned" {
			continue
		}
		sha, _ := d["sha256"].(string)
		if sha == "" {
			continue
		}

		// Stat object in MinIO to get metadata
		info, err := h.minio.StatObject(ctx, h.bucket, sha, minio.StatObjectOptions{})
		if err != nil {
			h.logger.Warn("dr reconcile: stat failed", "sha256", sha, "error", err)
			continue
		}

		ct := info.ContentType
		if ct == "" {
			ct = "application/octet-stream"
		}

		_, dbErr := h.pool.Exec(ctx,
			`INSERT INTO blobs (sha256, minio_ref, size_bytes, content_type, ref_count)
			 VALUES ($1, $2, $3, $4, 0)
			 ON CONFLICT (sha256) DO NOTHING`,
			sha, fmt.Sprintf("%s/%s", h.bucket, sha), info.Size, ct,
		)
		if dbErr != nil {
			h.logger.Warn("dr reconcile: insert failed", "sha256", sha, "error", dbErr)
			continue
		}
		reimported++
	}

	_, _ = h.pool.Exec(ctx,
		`UPDATE storage_dr_scans SET reimported_count = $1 WHERE id = $2`,
		reimported, id)

	httputil.WriteJSON(w, http.StatusOK, map[string]int64{"reimported": reimported})
}

// seaweedGet fetches JSON from a SeaweedFS/S3 admin endpoint.
func (h *StorageHandler) seaweedGet(ctx context.Context, url string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := seaweedHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse %s: %w", url, err)
	}
	return result, nil
}

func stringField(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func boolField(m map[string]any, key string) bool {
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

func bucketCount(ctx context.Context, mc *minio.Client) int {
	buckets, err := mc.ListBuckets(ctx)
	if err != nil {
		return 0
	}
	return len(buckets)
}
