package telemetry

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PGStore persists telemetry records to the device_telemetry table.
type PGStore struct {
	pool *pgxpool.Pool
}

// NewPGStore creates a telemetry store backed by PostgreSQL.
func NewPGStore(pool *pgxpool.Pool) *PGStore {
	return &PGStore{pool: pool}
}

// Insert writes a telemetry record to the database.
func (s *PGStore) Insert(ctx context.Context, r TelemetryRecord) error {
	usageJSON, err := json.Marshal(r.FeatureUsage)
	if err != nil {
		// Fall back to empty object rather than failing the report.
		usageJSON = []byte("{}")
	}

	_, err = s.pool.Exec(ctx,
		`INSERT INTO device_telemetry (device_id, app_version, os_version, crash_count, uptime_hours, feature_usage)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		r.DeviceID, r.AppVersion, r.OSVersion, r.CrashCount, r.UptimeHours, usageJSON,
	)
	return err
}
