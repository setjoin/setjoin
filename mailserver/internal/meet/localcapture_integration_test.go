// localcapture_integration_test.go — MEET M5 slice 2: the local-capture
// wire arc against the live schema (the TestPresentationLifecycleHappyPath
// genre; DB-gated — skipped without DB_DSN). Proves the four NEW routes end
// to end through the real handlers + reducers: acquire → heartbeat
// (refresh, exact-replay retry, seq regression, stale generation, the final
// stopped frame) → re-acquire generation → owner stop → TRUTHFUL
// registration (tampered seal refuses before the reducer, the sealed
// descriptor registers, the replay is idempotent), plus the flag-OFF
// inertness at the wire. The reducer-side semantics have their own pgTAP
// suite (meet_local_capture.pg); this file proves the HTTP surface
// composes it.
package meet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/toggle"
)

func localCaptureHandlerLive(t *testing.T, pool *pgxpool.Pool, localRecordingEnabled bool) *Handler {
	t.Helper()
	return NewHandler(pool, toggle.NewTestFlags(map[string]bool{
		"feature.meet":                 true,
		"feature.meet_local_recording": localRecordingEnabled,
	}), configuredCfg, nil, nil, nil, nil)
}

func localDescriptorDigestForTest(t *testing.T, raw string) string {
	t.Helper()
	var value any
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		t.Fatalf("fixture decode: %v", err)
	}
	obj, ok := value.(map[string]any)
	if !ok {
		t.Fatal("fixture is not an object")
	}
	obj["integrityDigest"] = nil // the Seal genre: cleared, never absent
	canonical, err := canonicalJSON(obj)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

func TestLocalCaptureWireArc(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := localCaptureHandlerLive(t, pool, true)

	host := meetTestUser(t, pool, "m5wirehost")
	meetingID := createTestMeeting(t, h, host, "m5 wire arc")
	startMeetingLive(t, pool, meetingID)

	// ── acquire: 201 with the lease facts ──
	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/local/lease", meetingID),
		`{"deviceId":"wire-dev","surfaces":["microphone"],
		  "producer":{"platform":"darwin","platformVersion":"24.0","captureApiVersion":"electron-test"},
		  "heartbeatSeconds":10}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("acquire: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var lease struct {
		RecordingID     int64 `json:"recordingId"`
		LeaseGeneration int64 `json:"leaseGeneration"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &lease); err != nil {
		t.Fatalf("decode lease: %v", err)
	}
	if lease.RecordingID <= 0 || lease.LeaseGeneration != 1 {
		t.Fatalf("lease facts = %+v", lease)
	}
	base := fmt.Sprintf("/meet/%d/local/%d", meetingID, lease.RecordingID)

	// ── heartbeat: refresh, seq regression, stale generation, exact replay ──
	if rr := meetDo(t, h, host, "POST", base+"/heartbeat",
		`{"leaseGeneration":1,"seq":3,"captureState":"capturing","diskFreeBytes":4242}`); rr.Code != http.StatusOK {
		t.Fatalf("heartbeat: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	// An omitted captureState defaults to 'capturing' (the wire default).
	if rr := meetDo(t, h, host, "POST", base+"/heartbeat",
		`{"leaseGeneration":1,"seq":3}`); rr.Code != http.StatusOK {
		t.Fatalf("heartbeat default state: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	// A reducer error reaches the wire as its RFC7807 problem (the
	// anti-oracle not-found for an unknown lease).
	if rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/local/%d/heartbeat", meetingID, lease.RecordingID+9999),
		`{"leaseGeneration":1,"seq":1}`); rr.Code != http.StatusConflict || problemCode(t, rr) != "BZ282" {
		t.Fatalf("unknown-lease heartbeat: want 409 BZ282, got %d %s", rr.Code, problemCode(t, rr))
	}
	if rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/local/lease", meetingID+9999),
		`{"deviceId":"d","surfaces":["microphone"],"producer":{"platform":"p","captureApiVersion":"c"}}`); rr.Code != http.StatusNotFound || problemCode(t, rr) != "BZ185" {
		t.Fatalf("unknown-meeting acquire: want 404 BZ185, got %d %s: %s", rr.Code, problemCode(t, rr), rr.Body.String())
	}
	if rr := meetDo(t, h, host, "POST", base+"/heartbeat",
		`{"leaseGeneration":1,"seq":2,"captureState":"capturing"}`); rr.Code != http.StatusUnprocessableEntity || problemCode(t, rr) != "BZ283" {
		t.Fatalf("seq regression: want 422 BZ283, got %d %s: %s", rr.Code, problemCode(t, rr), rr.Body.String())
	}
	if rr := meetDo(t, h, host, "POST", base+"/heartbeat",
		`{"leaseGeneration":9,"seq":4,"captureState":"capturing"}`); rr.Code != http.StatusConflict || problemCode(t, rr) != "BZ282" {
		t.Fatalf("stale generation: want 409 BZ282, got %d %s: %s", rr.Code, problemCode(t, rr), rr.Body.String())
	}
	if rr := meetDo(t, h, host, "POST", base+"/heartbeat",
		`{"leaseGeneration":1,"seq":3,"captureState":"capturing"}`); rr.Code != http.StatusOK {
		t.Fatalf("exact replay: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// ── the final stopped frame stops the lease AND the recording ──
	rr = meetDo(t, h, host, "POST", base+"/heartbeat",
		`{"leaseGeneration":1,"seq":4,"captureState":"stopped","diskFreeBytes":4242}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("final frame: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var stopFact struct {
		Stop       bool   `json:"stop"`
		StopReason string `json:"stopReason"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &stopFact); err != nil {
		t.Fatalf("decode stop fact: %v", err)
	}
	if !stopFact.Stop || stopFact.StopReason != "device_stopped" {
		t.Fatalf("stop fact = %+v", stopFact)
	}

	// ── re-acquire after the stop: generation 2, a fresh recording ──
	rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/local/lease", meetingID),
		`{"deviceId":"wire-dev","surfaces":["microphone"],
		  "producer":{"platform":"darwin","captureApiVersion":"electron-test"}}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("re-acquire: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &lease); err != nil {
		t.Fatalf("decode re-lease: %v", err)
	}
	if lease.LeaseGeneration != 2 {
		t.Fatalf("re-acquire generation = %d, want 2", lease.LeaseGeneration)
	}

	// ── stop: the owner revokes; an unknown lease is the BZ282 problem;
	// an empty body defaults the reason (user_stop) before the same fence ──
	if rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/local/%d/stop", meetingID, lease.RecordingID+9999),
		`{}`); rr.Code != http.StatusConflict || problemCode(t, rr) != "BZ282" {
		t.Fatalf("empty-body stop: want 409 BZ282, got %d %s", rr.Code, problemCode(t, rr))
	}
	if rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/local/%d/stop", meetingID, lease.RecordingID+9999),
		`{"reason":"user_stop"}`); rr.Code != http.StatusConflict || problemCode(t, rr) != "BZ282" {
		t.Fatalf("unknown-lease stop: want 409 BZ282, got %d %s", rr.Code, problemCode(t, rr))
	}
	rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/local/%d/stop", meetingID, lease.RecordingID),
		`{"leaseGeneration":2,"reason":"revoked"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("stop: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// ── register: the truthful sealed descriptor ──
	segDigest := "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
	descriptor := fmt.Sprintf(`{
	  "schema": "sjrec-local-v1", "meetingId": %d, "recordingId": %d,
	  "packageState": "interrupted", "captureMode": "local_registered",
	  "policyMode": "local_only", "surfaces": ["microphone"],
	  "producer": {"platform": "darwin", "platformVersion": "24.0", "captureApiVersion": "electron-test"},
	  "startedAtUnixMs": 500, "endedAtUnixMs": 1800, "registeredAtUnixMs": 1900,
	  "segments": [
	    {"seq": 1, "state": "verified", "contentSha256": %q, "byteSize": 100,
	     "mimeType": "audio/webm", "codec": "opus", "container": "webm",
	     "interval": {"startMs": 0, "endMs": 1000},
	     "wallStartUnixMs": 500, "wallEndUnixMs": 1500, "interruptReason": null},
	    {"seq": 2, "state": "interrupted",
	     "interval": {"startMs": 1000, "endMs": 1500},
	     "wallStartUnixMs": 1500, "wallEndUnixMs": 1800, "interruptReason": "consent revoked"}
	  ],
	  "uploadedToDrive": false,
	  "coverage": {"available": [{"startMs": 0, "endMs": 1000}], "gaps": [{"startMs": 1000, "endMs": 1500}]},
	  "integrityDigest": "%s"
	}`, meetingID, lease.RecordingID, segDigest, segDigest)
	regPath := fmt.Sprintf("/meet/%d/local/%d/register", meetingID, lease.RecordingID)

	// A tampered seal refuses BEFORE the reducer is contacted (BZ284).
	tampered := strings.Replace(descriptor, `"integrityDigest": "`+segDigest+`"`,
		`"integrityDigest": "`+strings.Repeat("ff", 32)+`"`, 1)
	if tampered == descriptor {
		t.Fatal("tamper target not found")
	}
	if rr := meetDo(t, h, host, "POST", regPath, tampered); rr.Code != http.StatusForbidden || problemCode(t, rr) != "local-package-not-admitted" {
		t.Fatalf("tampered seal: want 403 local-package-not-admitted, got %d %s: %s", rr.Code, problemCode(t, rr), rr.Body.String())
	}

	// The truthful registration carries the digest the descriptor actually
	// seals (the same canonical form, computed here).
	sealed := strings.Replace(descriptor, `"integrityDigest": "`+segDigest+`"`,
		`"integrityDigest": "`+localDescriptorDigestForTest(t, descriptor)+`"`, 1)
	rr = meetDo(t, h, host, "POST", regPath, sealed)
	if rr.Code != http.StatusOK {
		t.Fatalf("register: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var reg struct {
		RecordingID       int64  `json:"recordingId"`
		DescriptorDigest  string `json:"descriptorDigest"`
		SegmentCount      int    `json:"segmentCount"`
		AlreadyRegistered bool   `json:"alreadyRegistered"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &reg); err != nil {
		t.Fatalf("decode register: %v", err)
	}
	if reg.AlreadyRegistered || reg.SegmentCount != 2 || reg.RecordingID != lease.RecordingID {
		t.Fatalf("register fact = %+v", reg)
	}

	// Idempotent replay: the same sealed descriptor replays its receipt.
	rr = meetDo(t, h, host, "POST", regPath, sealed)
	if rr.Code != http.StatusOK {
		t.Fatalf("register replay: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &reg); err != nil || !reg.AlreadyRegistered {
		t.Fatalf("register replay fact = %+v (%v)", reg, err)
	}

	// A conflicting re-registration rewrites settled history: refused at
	// the reducer with the BZ284 problem. The conflicting descriptor is
	// FULLY self-consistent (its own correct seal, valid segments) so it
	// passes Go's admission and reaches the reducer's immutability fence.
	conflicting := strings.Replace(sealed, `"byteSize": 100`, `"byteSize": 101`, 1)
	if conflicting == sealed {
		t.Fatal("conflict target not found")
	}
	conflicting = strings.Replace(conflicting, `"integrityDigest": "`+localDescriptorDigestForTest(t, descriptor)+`"`,
		`"integrityDigest": "`+localDescriptorDigestForTest(t, conflicting)+`"`, 1)
	if rr := meetDo(t, h, host, "POST", regPath, conflicting); rr.Code != http.StatusForbidden || problemCode(t, rr) != "BZ284" {
		t.Fatalf("conflicting re-registration: want 403 BZ284, got %d %s: %s", rr.Code, problemCode(t, rr), rr.Body.String())
	}

	// ── the flag-OFF handler is inert at the wire ──
	off := localCaptureHandlerLive(t, pool, false)
	if rr := meetDo(t, off, host, "POST", fmt.Sprintf("/meet/%d/local/lease", meetingID),
		`{"deviceId":"d","surfaces":["microphone"]}`); rr.Code != http.StatusNotFound {
		t.Fatalf("flag-off acquire: want 404, got %d", rr.Code)
	}

	// Cleanup guard: the arc must not leave a live capture behind.
	var live int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM meeting_local_capture_leases WHERE lease_state = 'live'`).Scan(&live); err != nil {
		t.Fatalf("live lease count: %v", err)
	}
	if live != 0 {
		t.Fatalf("arc left %d live lease(s) behind", live)
	}
}
