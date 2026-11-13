package threat

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SignInRecorder persists a per-evaluation telemetry row to ca_signin_log.
// Best-effort: Record must never block or fail the sign-in. Injected so the
// pure Evaluate stays DB-free in tests (a fake recorder captures the call).
type SignInRecorder interface {
	Record(ctx context.Context, pectx PolicyEvalContext, res PolicyResult)
}

// NoopSignInRecorder discards records — used when conditional access is off or no
// pool is wired.
type NoopSignInRecorder struct{}

func (NoopSignInRecorder) Record(context.Context, PolicyEvalContext, PolicyResult) {}

type pgxSignInRecorder struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewPgxSignInRecorder builds a ca_signin_log-backed recorder.
func NewPgxSignInRecorder(pool *pgxpool.Pool, logger *slog.Logger) SignInRecorder {
	return &pgxSignInRecorder{pool: pool, logger: logger}
}

func (r *pgxSignInRecorder) Record(ctx context.Context, pectx PolicyEvalContext, res PolicyResult) {
	row := buildSignInRow(pectx, res)
	if _, err := r.pool.Exec(ctx, `SELECT ca_signin_log_append($1::jsonb)`, mustJSON(row)); err != nil {
		// Best-effort: a telemetry write must never fail the sign-in.
		r.logger.Warn("ca_signin_log append failed (telemetry, ignored)", "error", err)
	}
}

// buildSignInRow flattens the evaluation into the JSON shape ca_signin_log_append
// expects. would_decision is derived from the matched report-only outcome (if any).
func buildSignInRow(pectx PolicyEvalContext, res PolicyResult) map[string]any {
	row := map[string]any{
		"user_id":     pectx.UserID,
		"source_ip":   pectx.SourceIP,
		"protocol":    pectx.Protocol,
		"client_type": pectx.ClientType,
		"device_fp":   pectx.DeviceFP,
		"country":     pectx.Country,
		"decision":    res.Decision.String(),
		"report_only": false,
		"evaluated":   res.Evaluated,
	}
	if res.PolicyID != 0 {
		row["matched_policy_id"] = res.PolicyID
	}
	if res.CorrelationID != "" {
		row["correlation_id"] = res.CorrelationID
	}
	// Only annotate report_only/would_decision when there was NO enforcing match
	// (res.PolicyID == 0 → default-allow path). An enforced block whose trace
	// also contains an earlier would_ entry must NOT be mislabeled report_only.
	if res.PolicyID == 0 {
		for _, o := range res.Evaluated {
			if strings.HasPrefix(o.Outcome, "would_") {
				row["report_only"] = true
				row["would_decision"] = strings.TrimPrefix(o.Outcome, "would_")
				break
			}
		}
	}
	return row
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
