package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/spam"
	"setjoin.com/shared/httputil"
)

// SpamHandler provides the ML spam classifier admin dashboard.
type SpamHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
	// batchStats is the process-wide feature.spam_model_batch_load counter
	// source (PGModelStore.BatchLoadStats). Optional: without it the
	// dashboard's batch-load fields stay zero (unit-test construction).
	batchStats func() spam.BatchLoadStats
}

// NewSpamHandler creates a new spam admin handler.
func NewSpamHandler(pool *pgxpool.Pool, logger *slog.Logger) *SpamHandler {
	return &SpamHandler{pool: pool, logger: logger}
}

// SetBatchLoadStats wires the live batch-loading counters
// (feature.spam_model_batch_load, owner decision A6): resident model
// count/bytes and lifetime loads/hits, so the memory footprint the toggle's
// warning declares stays inspectable from the admin surface.
func (h *SpamHandler) SetBatchLoadStats(fn func() spam.BatchLoadStats) { h.batchStats = fn }

type spamDashboard struct {
	Enabled         bool            `json:"enabled"`
	TotalModels     int             `json:"total_models"`
	TotalSamples    int64           `json:"total_samples"`
	AvgSamples      float64         `json:"avg_samples"`
	ActiveWeek      int             `json:"active_week"`
	DisabledUsers   int             `json:"disabled_users"`
	TotalFP         int64           `json:"total_fp"`
	TotalFN         int64           `json:"total_fn"`
	TotalClassified int64           `json:"total_classified"`
	FPRate          float64         `json:"fp_rate"`
	TopUsers        []userModelStat `json:"top_users"`
	FeatureSize     int             `json:"feature_size"`
	MinSamples      int             `json:"min_samples"`

	BatchLoadResidentModels int64 `json:"batch_load_resident_models"`
	BatchLoadResidentBytes  int64 `json:"batch_load_resident_bytes"`
	BatchLoadLoads          int64 `json:"batch_load_loads"`
	BatchLoadHits           int64 `json:"batch_load_hits"`
}

type userModelStat struct {
	UserID      int64  `json:"user_id"`
	Email       string `json:"email"`
	SampleCount int    `json:"sample_count"`
	TrainedAt   string `json:"trained_at"`
	ModelSizeKB int    `json:"model_size_kb"`
	Disabled    bool   `json:"disabled"`
}

// GetDashboard returns the ML spam classifier health dashboard.
func (h *SpamHandler) GetDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	d := spamDashboard{
		Enabled:     true, // feature toggle checked separately
		FeatureSize: 1 << 20,
		MinSamples:  50,
	}

	// Check feature toggle.
	var mlEnabled bool
	h.pool.QueryRow(ctx,
		`SELECT enabled FROM feature_toggles WHERE key = 'feature.ml_spam'`,
	).Scan(&mlEnabled)
	d.Enabled = mlEnabled

	// Total models and aggregate stats.
	h.pool.QueryRow(ctx,
		`SELECT COALESCE(COUNT(*), 0), COALESCE(SUM(sample_count), 0),
		        COALESCE(AVG(sample_count), 0)
		 FROM user_spam_model`,
	).Scan(&d.TotalModels, &d.TotalSamples, &d.AvgSamples)

	// Disabled (opted-out) users.
	h.pool.QueryRow(ctx,
		`SELECT COALESCE(COUNT(*), 0) FROM user_spam_model WHERE disabled = TRUE`,
	).Scan(&d.DisabledUsers)

	// Active in last week.
	h.pool.QueryRow(ctx,
		`SELECT COALESCE(COUNT(*), 0) FROM user_spam_model
		 WHERE trained_at > now() - INTERVAL '7 days'`,
	).Scan(&d.ActiveWeek)

	// Accuracy aggregates.
	h.pool.QueryRow(ctx,
		`SELECT COALESCE(SUM(fp_count), 0), COALESCE(SUM(fn_count), 0), COALESCE(SUM(classified_count), 0)
		 FROM user_spam_model`,
	).Scan(&d.TotalFP, &d.TotalFN, &d.TotalClassified)
	if d.TotalClassified > 0 {
		d.FPRate = float64(d.TotalFP) / float64(d.TotalClassified)
	}

	// Batch-load footprint (feature.spam_model_batch_load): current resident
	// models/bytes across active delivery-scoring batches + lifetime loads/hits.
	if h.batchStats != nil {
		s := h.batchStats()
		d.BatchLoadResidentModels = s.ResidentModels
		d.BatchLoadResidentBytes = s.ResidentBytes
		d.BatchLoadLoads = s.Loads
		d.BatchLoadHits = s.Hits
	}

	// Top users by sample count.
	d.TopUsers = []userModelStat{}
	rows, err := h.pool.Query(ctx,
		`SELECT m.user_id, COALESCE(u.email, 'unknown'), m.sample_count,
		        to_char(m.trained_at, 'YYYY-MM-DD HH24:MI') AS trained,
		        octet_length(m.model_bytes) / 1024 AS size_kb, m.disabled
		 FROM user_spam_model m
		 LEFT JOIN users u ON u.id = m.user_id
		 ORDER BY m.sample_count DESC LIMIT 10`,
	)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var u userModelStat
			if err := rows.Scan(&u.UserID, &u.Email, &u.SampleCount, &u.TrainedAt, &u.ModelSizeKB, &u.Disabled); err == nil {
				d.TopUsers = append(d.TopUsers, u)
			}
		}
	}

	httputil.WriteJSON(w, http.StatusOK, d)
}

// ResetModel deletes a user's spam model, resetting it to untrained.
func (h *SpamHandler) ResetModel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}
	targetID, err := strconv.ParseInt(r.PathValue("userId"), 10, 64)
	if err != nil || targetID <= 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid userId"})
		return
	}
	// ponytail: reach check — actor must administer the target user's OU/domain.
	var ok bool
	if err := h.pool.QueryRow(ctx, `SELECT admin_can_reach($1, $2)`, claims.UserID, targetID).Scan(&ok); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "spam reset reach check failed", err)
		return
	}
	if !ok {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "target user not within your administrative scope"})
		return
	}
	if _, err := h.pool.Exec(ctx, `DELETE FROM user_spam_model WHERE user_id = $1`, targetID); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "spam reset exec failed", err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "reset"})
}

// DisableModel opts a user out of FTRL scoring (keeps training data, just skips scoring).
func (h *SpamHandler) DisableModel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}
	targetID, err := strconv.ParseInt(r.PathValue("userId"), 10, 64)
	if err != nil || targetID <= 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid userId"})
		return
	}
	// ponytail: reach check — actor must administer the target user's OU/domain.
	var ok bool
	if err := h.pool.QueryRow(ctx, `SELECT admin_can_reach($1, $2)`, claims.UserID, targetID).Scan(&ok); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "spam disable reach check failed", err)
		return
	}
	if !ok {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "target user not within your administrative scope"})
		return
	}
	if _, err := h.pool.Exec(ctx,
		`INSERT INTO user_spam_model (user_id, model_bytes, sample_count, disabled) VALUES ($1, '\x', 0, TRUE)
		 ON CONFLICT (user_id) DO UPDATE SET disabled = TRUE`,
		targetID); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "spam disable exec failed", err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "disabled"})
}

// EnableModel re-enables FTRL scoring for a user.
func (h *SpamHandler) EnableModel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}
	targetID, err := strconv.ParseInt(r.PathValue("userId"), 10, 64)
	if err != nil || targetID <= 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid userId"})
		return
	}
	// ponytail: reach check — actor must administer the target user's OU/domain.
	var ok bool
	if err := h.pool.QueryRow(ctx, `SELECT admin_can_reach($1, $2)`, claims.UserID, targetID).Scan(&ok); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "spam enable reach check failed", err)
		return
	}
	if !ok {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "target user not within your administrative scope"})
		return
	}
	if _, err := h.pool.Exec(ctx,
		`UPDATE user_spam_model SET disabled = FALSE WHERE user_id = $1`, targetID); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "spam enable exec failed", err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "enabled"})
}

// Ensure json import used.
var _ = json.Encoder{}
