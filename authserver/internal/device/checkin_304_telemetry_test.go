package device

// Telemetry integrity on the 304 short-circuit
// (D-AUTHSERVER-INTERNAL-DEVICE-007): a check-in whose If-None-Match matches
// the current policy version used to return 304 BEFORE event ingestion and
// the last_seen heartbeat — a success status that silently discarded every
// reported event. The short-circuit now runs only after the side effects:
// 304 means "policy body withheld", never "telemetry dropped".
//
// Against the pre-fix ordering this test FAILS: the os_update event row is
// never appended and last_seen keeps its forced stale value.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestHandleCheckin_304StillIngestsTelemetry proves a matching If-None-Match
// no longer bypasses event ingestion and the last_seen heartbeat.
func TestHandleCheckin_304StillIngestsTelemetry(t *testing.T) {
	pool := openDevicePool(t)
	ctx := context.Background()
	deviceID, secret := registerTestDevice(t, pool)

	// Force last_seen to a known stale value so the heartbeat assertion is
	// deterministic (registration stamps it with now()).
	if _, err := pool.Exec(ctx,
		`UPDATE devices SET last_seen = now() - interval '1 hour' WHERE id = $1`, deviceID); err != nil {
		t.Fatalf("force stale last_seen: %v", err)
	}

	// The client's If-None-Match must equal the CURRENT policy version, so the
	// request takes the 304 path.
	policy, err := resolveDevicePolicy(ctx, pool, deviceID)
	if err != nil {
		t.Fatalf("resolve policy version: %v", err)
	}
	etag := fmt.Sprintf("%d", policy.PolicyVersion)

	// A check-in that reports an event AND carries the matching etag.
	body, err := json.Marshal(CheckinRequest{
		DeviceID: deviceID,
		Events:   []CheckinEvent{{Type: "os_update", Timestamp: time.Now().UTC().Format(time.RFC3339), Data: "304-telemetry"}},
	})
	if err != nil {
		t.Fatalf("marshal checkin body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/device/checkin", bytes.NewReader(body))
	req.Header.Set("If-None-Match", etag)
	signRequestProof(t, req, secret, deviceID, time.Now().UTC().Format(time.RFC3339), "nonce-304-telemetry")

	h := HandleCheckin(pool, discardLogger(), testSecretCodec())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotModified {
		t.Fatalf("matching etag must still yield 304, got %d — body: %s", rec.Code, rec.Body.String())
	}

	// The reported event must be ingested even on the 304 path.
	var events int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM device_events WHERE device_id = $1 AND event_type = 'os_update'`,
		deviceID).Scan(&events); err != nil {
		t.Fatalf("count device_events: %v", err)
	}
	if events == 0 {
		t.Fatal("304 short-circuit dropped the reported event — telemetry must be ingested before the Not Modified return")
	}

	// The heartbeat must be bumped off its forced stale value.
	var lastSeen time.Time
	if err := pool.QueryRow(ctx,
		`SELECT last_seen FROM devices WHERE id = $1`, deviceID).Scan(&lastSeen); err != nil {
		t.Fatalf("read last_seen: %v", err)
	}
	if fresh := time.Now().Add(-55 * time.Minute); lastSeen.Before(fresh) {
		t.Fatalf("304 short-circuit skipped the last_seen heartbeat: got %v, want >= %v", lastSeen, fresh)
	}
}
