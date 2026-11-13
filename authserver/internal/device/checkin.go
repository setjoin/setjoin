package device

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	shareddevice "setjoin.com/shared/device"
	"setjoin.com/shared/httputil"
)

// bodySHA256Hex returns the lowercase hex SHA-256 of raw — the server-computed
// digest stamped via shared/device.WithServerBodyDigest so a device proof can
// be bound to body bytes a caller consumed before verification.
func bodySHA256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// CheckinRequest is the body of POST /device/checkin.
type CheckinRequest struct {
	DeviceID      int64          `json:"device_id"`
	Events        []CheckinEvent `json:"events,omitempty"`
	PolicyVersion int64          `json:"policy_version"` // client's current policy version
}

// CheckinEvent is a single event reported by the client.
type CheckinEvent struct {
	Type      string `json:"type"`      // "crash", "jailbreak_detected", "os_update", "app_update"
	Timestamp string `json:"timestamp"` // ISO 8601
	Data      string `json:"data,omitempty"`
}

// CheckinResponse is the response to a device check-in.
type CheckinResponse struct {
	PolicyVersion int64             `json:"policy_version"`
	Policy        map[string]string `json:"policy"` // only if version changed
	WipeRequested bool              `json:"wipe_requested"`
	WipeReason    string            `json:"wipe_reason,omitempty"`
	Notifications []string          `json:"notifications,omitempty"`
}

// HandleCheckin handles POST /device/checkin. The caller must be authenticated
// (claims attached to context by auth middleware). codec is the process
// SecretCodec that opens the at-rest device HMAC secret (nil fails closed).
func HandleCheckin(pool *pgxpool.Pool, logger *slog.Logger, codec *shareddevice.SecretCodec) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httputil.WriteJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}

		ctx := r.Context()

		// med-shard2-006 body binding: the device proof is bound to the SHA-256
		// of the exact request body, but the decode below consumes that body
		// before VerifyDeviceRequest runs (the device_id needed for the proof
		// comes FROM the body). Buffer the bytes once and record the
		// server-computed digest via WithServerBodyDigest — the trusted evidence
		// binding the signed X-Device-Body-SHA256 commitment to the exact bytes
		// this handler observed. Without it the verifier fails closed on the
		// now-consumed body. (On the mounted route RequireDeviceHMAC already
		// verified and stamped the request; this keeps the handler's own
		// defense-in-depth verification coherent when it runs for real.)
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		r = shareddevice.WithServerBodyDigest(r, bodySHA256Hex(raw))
		r.Body = io.NopCloser(bytes.NewReader(raw))

		var req CheckinRequest
		if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&req); err != nil {
			httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		if req.DeviceID <= 0 {
			httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "device_id is required"})
			return
		}

		// Authenticate the device: the request must carry a valid HMAC (keyed by
		// the per-device secret issued once at registration) over the canonical
		// challenge for this device_id. Without this, device_id is spoofable and
		// any caller could check in as, and pull policy/wipe state for, any
		// device. Reject (401) on any failure: missing header, unknown device,
		// or mismatch.
		if err := VerifyDeviceRequest(ctx, pool, req.DeviceID, r, codec); err != nil {
			logger.Warn("device: checkin HMAC verification failed", "device_id", req.DeviceID, "error", err)
			httputil.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "device authentication failed"})
			return
		}

		// Resolve the current policy for this device.
		policy, err := resolveDevicePolicy(ctx, pool, req.DeviceID)
		if err != nil {
			logger.Error("device: policy resolution failed", "device_id", req.DeviceID, "error", err)
			httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			return
		}

		// Log events.
		//
		// V254 FORCE-RLS trusted seam (L2-C2 r2.2): device_events is Posture B
		// and the checkin path has no GUC, so evidence writes go through the
		// worker-owned SECURITY DEFINER append, which resolves the device row
		// in-DB before the insert (R1 by resolution, not caller assertion).
		// Checked propagation: a NULL return means the device row did not
		// resolve — the evidence write is a loud 5xx, never a silently dropped
		// row under FORCE.
		for _, ev := range req.Events {
			eventJSON, _ := json.Marshal(map[string]string{"data": ev.Data})
			var appended *int64
			if err := pool.QueryRow(ctx,
				`SELECT mdm_checkin_event_append($1, $2, $3::jsonb)`,
				req.DeviceID, ev.Type, string(eventJSON),
			).Scan(&appended); err != nil || appended == nil {
				logger.Error("device: checkin event append failed", "device_id", req.DeviceID, "event_type", ev.Type, "error", err)
				httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
				return
			}
		}

		// Update last seen.
		UpdateLastSeen(ctx, pool, req.DeviceID)

		// Check ETag — if client has current version, return 304.
		//
		// The short-circuit runs ONLY after the check-in's side effects: the
		// 304 previously sat before event ingestion and last_seen, so a
		// client that sent If-None-Match got a success status while every
		// reported event was discarded and the heartbeat was skipped
		// (D-AUTHSERVER-INTERNAL-DEVICE-007). Telemetry ingestion and the
		// policy-body saving are orthogonal: 304 means "policy body withheld",
		// never "telemetry dropped".
		if etag := r.Header.Get("If-None-Match"); etag != "" {
			if fmt.Sprintf("%d", policy.PolicyVersion) == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}

		// Build response.
		resp := CheckinResponse{
			PolicyVersion: policy.PolicyVersion,
			WipeRequested: policy.WipeRequested,
			WipeReason:    policy.WipeReason,
		}

		// Only include the full policy when the client's version differs. Gate on
		// inequality, NOT `<`: PolicyVersion is a content hash (not monotonic), so a
		// policy edit that hashes lower than the client's current version is still a
		// change and must be delivered. `<` silently kept stale policy on any such edit.
		if req.PolicyVersion != policy.PolicyVersion {
			resp.Policy = policy.Policies
		}

		w.Header().Set("ETag", fmt.Sprintf("%d", policy.PolicyVersion))
		w.Header().Set("Cache-Control", "private, max-age=300")
		httputil.WriteJSON(w, http.StatusOK, resp)
	}
}

// ResolvedPolicy is the effective policy for a device after merging
// global, group, and per-device layers.
type ResolvedPolicy struct {
	PolicyVersion int64
	Policies      map[string]string
	WipeRequested bool
	WipeReason    string
}

// resolveDevicePolicy returns the effective policy for a device by calling
// the mdm_effective_policy SECURITY DEFINER evaluator.
//
// V254 FORCE-RLS trusted seam (L2-C2 r2.2): under the Posture C FORCE flip the
// device-HMAC path (per-device auth only — RequireDeviceHMAC, no user session,
// no admin GUC) can no longer SELECT device_policy / device_policy_groups
// directly — those arms are perm-keyed and fail closed without a GUC. The
// worker-owned (BYPASSRLS definer) evaluator applies the documented
// device > group > global merge IN the database (only group_type='department'
// is resolved today — users has no role/domain mapping) and returns merged
// key/values + the wipe flag, NEVER raw policy rows: the non-admin consumer
// has policies APPLIED without being able to SELECT them (ARCH-018 choke
// point; a direct SELECT of the same rows as plain setjoin_app returns 0).
// The wipe flag comes from the device's own row, resolved in-DB — the old
// separate devices lookup (whose ErrNoRows produced a 500 on a nonexistent
// device, unreachable on the live HMAC-verified path) is folded into the
// evaluator. PolicyVersion stays a Go-side content hash (unchanged contract).
func resolveDevicePolicy(ctx context.Context, pool *pgxpool.Pool, deviceID int64) (*ResolvedPolicy, error) {
	var payload struct {
		Policies      map[string]string `json:"policies"`
		WipeRequested bool              `json:"wipe_requested"`
	}
	var raw []byte
	if err := pool.QueryRow(ctx, `SELECT mdm_effective_policy($1)`, deviceID).Scan(&raw); err != nil {
		return nil, fmt.Errorf("device: effective policy evaluation: %w", err)
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("device: effective policy decode: %w", err)
	}
	if payload.Policies == nil {
		payload.Policies = map[string]string{}
	}

	wipeReason := ""
	if payload.WipeRequested {
		wipeReason = "Administrator requested remote wipe"
	}

	return &ResolvedPolicy{
		PolicyVersion: policyVersion(payload.Policies, payload.WipeRequested),
		Policies:      payload.Policies,
		WipeRequested: payload.WipeRequested,
		WipeReason:    wipeReason,
	}, nil
}

// policyVersion is a content hash of the resolved policy (sorted, length-delimited
// key/value pairs + the wipe flag). It replaces the old additive char-sum, which
// was both non-monotonic and collision-prone:
//   - lowering a value's char-sum (shorten/remove a key, lower-codepoint edit)
//     produced a SMALLER number, so the checkin diff `client < server` never fired
//     and the device kept running the stale security policy forever;
//   - any char rearrangement across keys/values (an anagram) yielded an IDENTICAL
//     number, so the change went undetected on both the checkin diff and the GET
//     304 path; and a routine edit could collide with the wipe `+1`.
//
// Length-delimiting each field makes {"ab":"c"} and {"a":"bc"} distinct, and
// sorting keys makes the hash independent of map iteration order. FNV-1a (stdlib)
// is sufficient for change-detection — the version is opaque to clients (echoed
// back via If-None-Match) and the server gates on inequality, so it need not be
// monotonic or collision-resistant against an adversary.
func policyVersion(policies map[string]string, wipeRequested bool) int64 {
	h := fnv.New64a()
	keys := make([]string, 0, len(policies))
	for k := range policies {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var lenBuf [8]byte
	writeField := func(s string) {
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(s)))
		_, _ = h.Write(lenBuf[:])
		_, _ = h.Write([]byte(s))
	}
	for _, k := range keys {
		writeField(k)
		writeField(policies[k])
	}
	if wipeRequested {
		_, _ = h.Write([]byte{1})
	} else {
		_, _ = h.Write([]byte{0})
	}
	return int64(h.Sum64())
}

// HandleGetDevicePolicy handles GET /device/policy with ETag support.
// Returns 304 Not Modified if the client already has the latest version.
// codec is the process SecretCodec that opens the at-rest device HMAC secret
// (nil fails closed).
func HandleGetDevicePolicy(pool *pgxpool.Pool, logger *slog.Logger, codec *shareddevice.SecretCodec) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			httputil.WriteJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}

		ctx := r.Context()
		deviceIDStr := r.URL.Query().Get("device_id")

		var deviceID int64
		if _, err := fmt.Sscanf(deviceIDStr, "%d", &deviceID); err != nil || deviceID <= 0 {
			httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "device_id is required"})
			return
		}

		// Authenticate exactly as the checkin endpoint does: the request must
		// carry a valid per-device HMAC (over the canonical challenge for this
		// device_id, with a fresh timestamp) before any policy/wipe state is
		// returned. Without this, device_id is spoofable and any caller could
		// read another device's policy and wipe flag. This is the SIBLING of the
		// checkin guard; both call the single VerifyDeviceRequest seam so no
		// device endpoint can be exposed unauthenticated.
		if err := VerifyDeviceRequest(ctx, pool, deviceID, r, codec); err != nil {
			logger.Warn("device: policy-read HMAC verification failed", "device_id", deviceID, "error", err)
			httputil.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "device authentication failed"})
			return
		}

		policy, err := resolveDevicePolicy(ctx, pool, deviceID)
		if err != nil {
			logger.Error("device: policy resolution failed", "device_id", deviceID, "error", err)
			httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			return
		}

		// ETag: return 304 if client has current version.
		if etag := r.Header.Get("If-None-Match"); etag != "" {
			if fmt.Sprintf("%d", policy.PolicyVersion) == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}

		resp := map[string]any{
			"device_id":      deviceID,
			"policy_version": policy.PolicyVersion,
			"policies":       policy.Policies,
			"wipe_requested": policy.WipeRequested,
			"updated_at":     time.Now().UTC(),
		}

		w.Header().Set("ETag", fmt.Sprintf("%d", policy.PolicyVersion))
		w.Header().Set("Cache-Control", "private, max-age=300")
		httputil.WriteJSON(w, http.StatusOK, resp)
	}
}
