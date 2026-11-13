package device

// Gap coverage for the check-in seams (checkin.go): the oversized-body
// ingress cap and the resolveDevicePolicy error/default arms the mounted-path
// tests do not reach.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestHandleCheckin_RejectsOversizedBody: a check-in body beyond the 1 MiB
// handler cap is a 400 before any device resolution — the proof headers may
// even be validly signed; the ingress cap wins.
func TestHandleCheckin_RejectsOversizedBody(t *testing.T) {
	pool := openDevicePool(t)
	deviceID, secret := registerTestDevice(t, pool)

	// A validly-signed request whose body exceeds the handler cap.
	big := bytes.Repeat([]byte("a"), (1<<20)+4096)
	req := httptest.NewRequest(http.MethodPost, "/device/checkin", bytes.NewReader(big))
	ts := time.Now().UTC().Format(time.RFC3339)
	signRequestProof(t, req, secret, deviceID, ts, "nonce-oversized")

	h := HandleCheckin(pool, discardLogger(), testSecretCodec())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized body status = %d body %s, want 400", rec.Code, rec.Body.String())
	}
}

// TestResolveDevicePolicy_EvaluatorFailureFailsClosed pins the evaluator
// error arm: when the policy evaluation cannot complete (canceled request
// context), resolveDevicePolicy returns a wrapped error — the caller turns it
// into a loud 500, never a fabricated empty policy.
func TestResolveDevicePolicy_EvaluatorFailureFailsClosed(t *testing.T) {
	pool := openDevicePool(t)
	deviceID, _ := registerTestDevice(t, pool)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := resolveDevicePolicy(ctx, pool, deviceID)
	if err == nil || !strings.Contains(err.Error(), "device: effective policy evaluation") {
		t.Fatalf("resolveDevicePolicy(canceled ctx) = %v, want wrapped evaluation failure", err)
	}
}

// TestResolveDevicePolicy_FreshDeviceResolves pins the fresh-device contract:
// the evaluator returns a non-nil policy map (global rows in the shared test
// DB merge in), never a wipe, and the version is exactly the content hash of
// the resolved map — the value If-None-Match comparisons rely on.
func TestResolveDevicePolicy_FreshDeviceResolves(t *testing.T) {
	pool := openDevicePool(t)
	deviceID, _ := registerTestDevice(t, pool)

	policy, err := resolveDevicePolicy(context.Background(), pool, deviceID)
	if err != nil {
		t.Fatalf("resolveDevicePolicy(fresh device): %v", err)
	}
	if policy.Policies == nil {
		t.Fatal("Policies = nil, want non-nil map (defaulting arm)")
	}
	if policy.WipeRequested {
		t.Fatal("WipeRequested = true for a fresh device")
	}
	if policy.WipeReason != "" {
		t.Fatalf("WipeReason = %q for a fresh device, want empty", policy.WipeReason)
	}

	// The content hash of the resolved policy is deterministic.
	want := policyVersion(policy.Policies, policy.WipeRequested)
	if policy.PolicyVersion != want {
		t.Fatalf("PolicyVersion = %d, want %d (content hash of the resolved map)", policy.PolicyVersion, want)
	}
}

// TestHandleCheckin_CheckinResponseWireShape pins the response contract the
// gap arms depend on: 400 bodies are JSON errors and a successful check-in
// echoes the policy version with an ETag (compile-shaped guard for the paths
// above).
func TestHandleCheckin_CheckinResponseWireShape(t *testing.T) {
	pool := openDevicePool(t)
	deviceID, secret := registerTestDevice(t, pool)

	body, _ := json.Marshal(CheckinRequest{DeviceID: deviceID})
	req := httptest.NewRequest(http.MethodPost, "/device/checkin", bytes.NewReader(body))
	ts := time.Now().UTC().Format(time.RFC3339)
	signRequestProof(t, req, secret, deviceID, ts, "nonce-wire-shape")

	h := HandleCheckin(pool, discardLogger(), testSecretCodec())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("valid check-in status = %d body %s, want 200", rec.Code, rec.Body.String())
	}
	var resp CheckinResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response body is not a CheckinResponse: %v", err)
	}
	if rec.Header().Get("ETag") != fmt.Sprintf("%d", resp.PolicyVersion) {
		t.Fatalf("ETag %q does not match policy_version %d", rec.Header().Get("ETag"), resp.PolicyVersion)
	}
	if rec.Header().Get("Cache-Control") == "" {
		t.Fatal("check-in response is missing Cache-Control")
	}
}
