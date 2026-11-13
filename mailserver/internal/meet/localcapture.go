// localcapture.go — MEET plan M5 slice 2: the Electron local-first capture
// lease + truthful local-package registration routes
// (retired-docs:superpowers/plans/2026-08-25-meet-document-presentation-semantic-
// recording.md, M5). The server half of the slice-1 client substrate in
// clients/desktop/electron/src/meet/ (the sjrec-local-v1 descriptor, the
// meet-local-heartbeat-v1 frames, the non-dismissible consent machine):
//
//   - POST /meet/{id}/local/lease           — reducer-commit-before-capture:
//     the lease acquire (the local_registered semantic recording + banner
//     commit FIRST inside the reducer, then the lease — policy.go's
//     InvariantLeaseAfterReducerCommit; single-primary-mode and the BZ199
//     guest arm ride meeting_semantic_recording_start verbatim).
//   - POST /meet/{id}/local/{rid}/heartbeat — the keepalive: refreshes the
//     lease deadline, enforces monotonic seq, answers the stop FACT the
//     device's stop evaluator consumes (revocation / meeting end / expiry).
//   - POST /meet/{id}/local/{rid}/stop      — the revocation/user stop: the
//     device owner or host/cohost stops the lease AND its recording.
//   - POST /meet/{id}/local/{rid}/register  — truthful local-package
//     registration: the sjrec-local-v1 descriptor, validated with the SAME
//     rules as presentation/segment.go (this file routes every segment
//     through presentation.MediaSegment.Validate and every coverage claim
//     through presentation.ComputeCoverage), its canonical-JSON seal
//     re-derived here, then stored via the wave-4 ingest contract
//     (meeting_semantic_segment_ingest) as a RECEIPT on the local_only row
//     — never a claim of centrally retained bytes (a local_registered
//     package exports nothing centrally, BZ281 local_only).
//
// Flag posture (the M2 split): ALL FOUR are NEW INTENT —
// feature.meet_local_recording must be ON, else 404, indistinguishable
// from an absent route. The Electron substrate ships inert (rollout mode
// 'off'), so the wire stays cold until a separate trusted rollout.
//
// BZ codes: BZ282 (lease conflict), BZ283 (local capture invalid),
// BZ284 (registration not admitted) — meet/errors.go + reducererr.codeClass.
package meet

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/meet/presentation"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/toggle"
)

func (h *Handler) registerLocalCaptureRoutes(mux router) {
	mux.HandleFunc("POST /meet/{id}/local/lease", h.acquireLocalCaptureLease)
	mux.HandleFunc("POST /meet/{id}/local/{rid}/heartbeat", h.localCaptureHeartbeat)
	mux.HandleFunc("POST /meet/{id}/local/{rid}/stop", h.stopLocalCaptureLease)
	mux.HandleFunc("POST /meet/{id}/local/{rid}/register", h.registerLocalPackage)
}

// localRecordingFlagOff is the M5 gate every local-capture route shares:
// feature.meet_local_recording must be ON — a disabled surface 404s,
// indistinguishable from an absent route (the presentationFlagOff genre).
func (h *Handler) localRecordingFlagOff() bool {
	return !h.flags.IsEnabled(toggle.FeatureMeetLocalRecording)
}

// ── The sjrec-local-v1 descriptor (the wire mirror of the slice-1 TS) ────

// LocalPackageSchema is the frozen descriptor schema. Other versions fail
// closed (the client's LOCAL_PACKAGE_SCHEMA pin, mirrored server-side).
const LocalPackageSchema = "sjrec-local-v1"

// maxLocalPackageSegments mirrors the client's MAX_LOCAL_SEGMENTS cap.
const maxLocalPackageSegments = 10_000

type localSegmentInterval struct {
	StartMs int64 `json:"startMs"`
	EndMs   int64 `json:"endMs"`
}

type localPackageSegment struct {
	Seq             int64                `json:"seq"`
	State           string               `json:"state"`
	ContentSha256   *string              `json:"contentSha256"`
	ByteSize        *int64               `json:"byteSize"`
	MimeType        *string              `json:"mimeType"`
	Codec           *string              `json:"codec"`
	Container       *string              `json:"container"`
	Interval        localSegmentInterval `json:"interval"`
	WallStartUnixMs int64                `json:"wallStartUnixMs"`
	WallEndUnixMs   int64                `json:"wallEndUnixMs"`
	InterruptReason *string              `json:"interruptReason"`
}

type localPackageDescriptor struct {
	Schema       string   `json:"schema"`
	MeetingID    int64    `json:"meetingId"`
	RecordingID  *int64   `json:"recordingId"`
	PackageState string   `json:"packageState"`
	CaptureMode  string   `json:"captureMode"`
	PolicyMode   string   `json:"policyMode"`
	Surfaces     []string `json:"surfaces"`
	Producer     struct {
		Platform          string `json:"platform"`
		PlatformVersion   string `json:"platformVersion"`
		CaptureAPIVersion string `json:"captureApiVersion"`
	} `json:"producer"`
	StartedAtUnixMs    int64                 `json:"startedAtUnixMs"`
	EndedAtUnixMs      *int64                `json:"endedAtUnixMs"`
	RegisteredAtUnixMs *int64                `json:"registeredAtUnixMs"`
	Segments           []localPackageSegment `json:"segments"`
	UploadedToDrive    *bool                 `json:"uploadedToDrive"`
	Coverage           struct {
		Available []localSegmentInterval `json:"available"`
		Gaps      []localSegmentInterval `json:"gaps"`
	} `json:"coverage"`
	IntegrityDigest *string `json:"integrityDigest"`
}

// validateLocalDescriptor enforces the descriptor truthfulness contract —
// the server mirror of the slice-1 registration.ts rules, expressed through
// the wave-4 segment.go contract so both planes refuse with the SAME
// vocabulary (MediaSegment.Validate) and the SAME coverage math
// (ComputeCoverage). Returns a human-named problem; the wire refusal is
// BZ284 (admitted-path semantics — a truthful descriptor registers).
func validateLocalDescriptor(d *localPackageDescriptor, meetingID, recordingID int64) error {
	if d.Schema != LocalPackageSchema {
		return fmt.Errorf("descriptor schema %q is not %s", d.Schema, LocalPackageSchema)
	}
	if d.CaptureMode != "local_registered" {
		return fmt.Errorf("descriptor captureMode %q is not local_registered", d.CaptureMode)
	}
	if d.UploadedToDrive == nil || *d.UploadedToDrive {
		return fmt.Errorf("descriptor claims an upload path that does not exist")
	}
	switch d.PolicyMode {
	case "local_preferred", "server_only", "local_only", "disabled":
	default:
		return fmt.Errorf("unknown policy mode fails closed")
	}
	if d.MeetingID != meetingID {
		return fmt.Errorf("descriptor binds meeting %d, not %d", d.MeetingID, meetingID)
	}
	if d.RecordingID != nil && *d.RecordingID != recordingID {
		return fmt.Errorf("descriptor binds recording %d, not %d", *d.RecordingID, recordingID)
	}
	switch d.PackageState {
	case "finalized", "interrupted", "registered":
	default:
		return fmt.Errorf("a %q descriptor is not a sealed package", d.PackageState)
	}
	if d.EndedAtUnixMs == nil {
		return fmt.Errorf("a %s descriptor must carry its end time", d.PackageState)
	}
	if d.StartedAtUnixMs <= 0 {
		return fmt.Errorf("descriptor missing start time")
	}
	if *d.EndedAtUnixMs < d.StartedAtUnixMs {
		return fmt.Errorf("descriptor ends before it starts")
	}
	if d.PackageState == "registered" && d.RegisteredAtUnixMs == nil {
		return fmt.Errorf("a registered descriptor must carry its registration time")
	}
	if d.Producer.Platform == "" || d.Producer.CaptureAPIVersion == "" {
		return fmt.Errorf("descriptor producer must pin platform and captureApiVersion")
	}
	if len(d.Surfaces) == 0 {
		return fmt.Errorf("descriptor covers no capture surface")
	}
	seenSurfaces := map[string]bool{}
	for _, s := range d.Surfaces {
		if s != "microphone" && s != "systemAudio" {
			return fmt.Errorf("descriptor surface %q is not a capture surface", s)
		}
		if seenSurfaces[s] {
			return fmt.Errorf("descriptor surface %q is duplicated", s)
		}
		seenSurfaces[s] = true
	}
	if len(d.Segments) < 1 || len(d.Segments) > maxLocalPackageSegments {
		return fmt.Errorf("descriptor segments must number 1..%d", maxLocalPackageSegments)
	}

	segments := make([]presentation.MediaSegment, 0, len(d.Segments))
	for i := range d.Segments {
		s := &d.Segments[i]
		if s.State == "capturing" {
			return fmt.Errorf("sealed descriptor segment %d carries state capturing", s.Seq)
		}
		ack := presentation.AckNone
		if s.State == "verified" {
			// The registration IS the acknowledgement: the descriptor's
			// sealed digest pins these exact segment facts.
			ack = presentation.AckAcknowledged
		}
		seg := presentation.MediaSegment{
			RecordingID: recordingID,
			MeetingID:   meetingID,
			Seq:         s.Seq,
			State:       presentation.SegmentState(s.State),
			Ack:         ack,
			Interval: presentation.MediaInterval{
				StartMs: s.Interval.StartMs,
				EndMs:   s.Interval.EndMs,
			},
			WallStartUnixMs: s.WallStartUnixMs,
			WallEndUnixMs:   s.WallEndUnixMs,
		}
		if s.ContentSha256 != nil {
			seg.ContentSHA256 = *s.ContentSha256
		}
		if s.ByteSize != nil {
			seg.ByteSize = *s.ByteSize
		}
		if s.MimeType != nil {
			seg.MIMEType = *s.MimeType
		}
		if s.Codec != nil {
			seg.Codec = *s.Codec
		}
		if s.Container != nil {
			seg.Container = *s.Container
		}
		if s.InterruptReason != nil {
			seg.InterruptReason = *s.InterruptReason
		}
		// The SAME rules as presentation/segment.go, verbatim.
		if err := seg.Validate(); err != nil {
			return err
		}
		segments = append(segments, seg)
	}

	// Coverage truthfulness: recompute over the recorded media window and
	// refuse ANY drift from the descriptor's claimed map (no fabricated
	// coverage, no hidden gap). ComputeCoverage also fails closed on
	// overlapping verified segments (duplicate media).
	var maxEnd int64
	for _, seg := range segments {
		if seg.Interval.EndMs > maxEnd {
			maxEnd = seg.Interval.EndMs
		}
	}
	computed, err := presentation.ComputeCoverage(segments, presentation.MediaInterval{StartMs: 0, EndMs: maxEnd})
	if err != nil {
		return err
	}
	if !intervalsEqual(computed.Available, d.Coverage.Available) ||
		!intervalsEqual(computed.Gaps, d.Coverage.Gaps) {
		return fmt.Errorf("descriptor coverage does not match its segments (fabricated coverage)")
	}
	return nil
}

func intervalsEqual(computed []presentation.MediaInterval, claimed []localSegmentInterval) bool {
	if len(computed) != len(claimed) {
		return false
	}
	for i := range computed {
		if computed[i].StartMs != claimed[i].StartMs || computed[i].EndMs != claimed[i].EndMs {
			return false
		}
	}
	return true
}

// verifyDescriptorDigest re-derives the descriptor's integrity seal the
// slice-1 builder applied: sha256 over the CANONICAL JSON (recursively
// key-sorted, arrays in order, number literals preserved) with the
// integrityDigest field cleared to null — the client's descriptorDigest
// genre, mirrored byte-for-byte. A descriptor that does not seal its own
// bytes is not admissible (no fabricated completeness).
func verifyDescriptorDigest(raw []byte, claimed string) error {
	var value any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		return fmt.Errorf("descriptor is not valid JSON")
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("descriptor is not a JSON object")
	}
	if _, carried := obj["integrityDigest"]; !carried {
		return fmt.Errorf("descriptor carries no integrityDigest field")
	}
	obj["integrityDigest"] = nil // the Seal genre: cleared, never absent
	canonical, err := canonicalJSON(obj)
	if err != nil {
		return err
	}
	if claimed == "" {
		return fmt.Errorf("descriptor carries no sealed integrity digest")
	}
	sum := sha256.Sum256([]byte(canonical))
	if hex.EncodeToString(sum[:]) != claimed {
		return fmt.Errorf("descriptor integrity digest does not seal its own bytes")
	}
	return nil
}

// canonicalJSON is the byte-exact mirror of the slice-1 canonicalJson:
// object keys sorted recursively, arrays in order, json.Number literals
// preserved verbatim, and strings escaped the way ECMAScript
// JSON.stringify escapes them (quote, backslash, and the C0 controls —
// nothing else, so the digest both planes compute is one digest).
func canonicalJSON(v any) (string, error) {
	var b strings.Builder
	if err := appendCanonicalJSON(&b, v); err != nil {
		return "", err
	}
	return b.String(), nil
}

func appendCanonicalJSON(b *strings.Builder, v any) error {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case json.Number:
		b.WriteString(t.String())
	case string:
		appendJSONString(b, t)
	case []any:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := appendCanonicalJSON(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			appendJSONString(b, k)
			b.WriteByte(':')
			if err := appendCanonicalJSON(b, t[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("descriptor carries a value canonical form cannot pin (%T)", v)
	}
	return nil
}

// appendJSONString escapes exactly like ECMAScript JSON.stringify: the two
// mandatory escapes, short escapes for \b \f \n \r \t, \u00xx for the other
// C0 controls, and every other rune verbatim (no HTML escaping, no U+2028
// rewriting — the canonical bytes must match the client's byte for byte).
func appendJSONString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
				continue
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}

// ── Request bodies ────────────────────────────────────────────────────────

type localLeaseBody struct {
	DeviceID string   `json:"deviceId"`
	Surfaces []string `json:"surfaces"`
	Producer struct {
		Platform          string `json:"platform"`
		PlatformVersion   string `json:"platformVersion"`
		CaptureAPIVersion string `json:"captureApiVersion"`
	} `json:"producer"`
	HeartbeatSeconds *int `json:"heartbeatSeconds"`
}

type localHeartbeatBody struct {
	LeaseGeneration int64  `json:"leaseGeneration"`
	Seq             int64  `json:"seq"`
	CaptureState    string `json:"captureState"`
	DiskFreeBytes   *int64 `json:"diskFreeBytes"`
}

type localStopBody struct {
	LeaseGeneration *int64 `json:"leaseGeneration"`
	Reason          string `json:"reason"`
}

// ── Routes ────────────────────────────────────────────────────────────────

// acquireLocalCaptureLease serves POST …/local/lease — the lease acquire.
func (h *Handler) acquireLocalCaptureLease(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if h.localRecordingFlagOff() {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	id, ok := httputil.ParseIDPath(w, r, "id", "invalid meeting id")
	if !ok {
		return
	}
	var body localLeaseBody
	if !decodeMeetBody(w, r, &body) {
		return
	}
	if len(body.DeviceID) == 0 || len(body.DeviceID) > 256 {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusUnprocessableEntity, Detail: "deviceId must be 1..256 characters",
		})
		return
	}
	if len(body.Surfaces) == 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusUnprocessableEntity, Detail: "surfaces must cover at least one capture surface",
		})
		return
	}
	surfaces := make([]string, 0, len(body.Surfaces))
	seen := map[string]bool{}
	for _, s := range body.Surfaces {
		if s != "microphone" && s != "systemAudio" {
			httputil.WriteProblem(w, r, &httputil.Problem{
				Status: http.StatusUnprocessableEntity, Detail: "surfaces must be microphone/systemAudio only",
			})
			return
		}
		if seen[s] {
			httputil.WriteProblem(w, r, &httputil.Problem{
				Status: http.StatusUnprocessableEntity, Detail: "surfaces must not repeat a surface",
			})
			return
		}
		seen[s] = true
		surfaces = append(surfaces, s)
	}
	if body.Producer.Platform == "" || body.Producer.CaptureAPIVersion == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusUnprocessableEntity, Detail: "producer must pin platform and captureApiVersion",
		})
		return
	}
	seconds := 10 // the slice-1 HEARTBEAT_INTERVAL_MS default
	if body.HeartbeatSeconds != nil {
		seconds = *body.HeartbeatSeconds
	}
	if seconds < 5 || seconds > 60 {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusUnprocessableEntity, Detail: "heartbeatSeconds must be 5..60",
		})
		return
	}

	surfacesJSON, _ := json.Marshal(surfaces)
	producerJSON, _ := json.Marshal(map[string]string{
		"platform":          body.Producer.Platform,
		"platformVersion":   body.Producer.PlatformVersion,
		"captureApiVersion": body.Producer.CaptureAPIVersion,
	})
	var out json.RawMessage
	err := dbscope.RunUserScoped(r.Context(), h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(),
			`SELECT meeting_local_capture_lease_acquire($1, $2, $3, $4::jsonb, $5::jsonb, $6)`,
			claims.UserID, id, body.DeviceID, string(surfacesJSON), string(producerJSON), seconds).Scan(&out)
	})
	if err != nil {
		writeMeetProblem(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusCreated, out)
}

// localCaptureHeartbeat serves POST …/local/{rid}/heartbeat — the
// keepalive. The response IS the stop evaluator's input: {stop:false,…}
// keeps capturing; {stop:true, stopReason,…} forces the stop.
func (h *Handler) localCaptureHeartbeat(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if h.localRecordingFlagOff() {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	id, rid, ok := h.parseSemanticPath(w, r)
	if !ok {
		return
	}
	var body localHeartbeatBody
	if !decodeMeetBody(w, r, &body) {
		return
	}
	switch body.CaptureState {
	case "", "capturing", "stopping", "stopped":
	default:
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusUnprocessableEntity, Detail: "captureState must be capturing/stopping/stopped",
		})
		return
	}
	if body.Seq < 1 {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusUnprocessableEntity, Detail: "seq numbers from 1",
		})
		return
	}
	state := body.CaptureState
	if state == "" {
		state = "capturing"
	}
	var out json.RawMessage
	err := dbscope.RunUserScoped(r.Context(), h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(),
			`SELECT meeting_local_capture_lease_heartbeat($1, $2, $3, $4, $5, $6, $7)`,
			claims.UserID, id, rid, body.LeaseGeneration, body.Seq, state, body.DiskFreeBytes).Scan(&out)
	})
	if err != nil {
		writeMeetProblem(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

// stopLocalCaptureLease serves POST …/local/{rid}/stop — the
// revocation/user stop (owner or host/cohost; the recording stops in the
// same txn as the lease).
func (h *Handler) stopLocalCaptureLease(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if h.localRecordingFlagOff() {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	id, rid, ok := h.parseSemanticPath(w, r)
	if !ok {
		return
	}
	var body localStopBody
	if !decodeMeetBody(w, r, &body) {
		return
	}
	reason := body.Reason
	if reason == "" {
		reason = "user_stop"
	}
	switch reason {
	case "user_stop", "revoked":
	default:
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusUnprocessableEntity, Detail: "a lease stop names user_stop or revoked",
		})
		return
	}
	var out json.RawMessage
	err := dbscope.RunUserScoped(r.Context(), h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(),
			`SELECT meeting_local_capture_lease_stop($1, $2, $3, $4, $5)`,
			claims.UserID, id, rid, body.LeaseGeneration, reason).Scan(&out)
	})
	if err != nil {
		writeMeetProblem(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

// registerLocalPackage serves POST …/local/{rid}/register — the truthful
// local-package registration. Validation order: the raw bytes are read once
// (the 1 MiB body cap holds), the typed descriptor is validated with the
// segment.go rules, the canonical-JSON seal is re-derived, and ONLY THEN do
// the exact received bytes reach the reducer — which re-derives every
// segment binding through the wave-4 ingest contract in the same
// transaction (R2/R3: identity from the path + auth context, never from
// request-owned fields).
func (h *Handler) registerLocalPackage(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if h.localRecordingFlagOff() {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	id, rid, ok := h.parseSemanticPath(w, r)
	if !ok {
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			httputil.WriteProblem(w, r, &httputil.Problem{
				Status: http.StatusRequestEntityTooLarge, Detail: "request body exceeds the allowed size",
			})
			return
		}
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusBadRequest, Detail: "invalid JSON",
		})
		return
	}
	var descriptor localPackageDescriptor
	if err := json.Unmarshal(raw, &descriptor); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusBadRequest, Detail: "invalid JSON",
		})
		return
	}
	claimedDigest := ""
	if descriptor.IntegrityDigest != nil {
		claimedDigest = *descriptor.IntegrityDigest
	}
	if err := validateLocalDescriptor(&descriptor, id, rid); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusForbidden,
			Type:   "https://setjoin.com/problems/meet/local-package-not-admitted",
			Code:   "local-package-not-admitted",
			Detail: err.Error(),
		})
		return
	}
	if err := verifyDescriptorDigest(raw, claimedDigest); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusForbidden,
			Type:   "https://setjoin.com/problems/meet/local-package-not-admitted",
			Code:   "local-package-not-admitted",
			Detail: err.Error(),
		})
		return
	}

	var out json.RawMessage
	err = dbscope.RunUserScoped(r.Context(), h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(),
			`SELECT meeting_local_capture_register($1, $2, $3, $4::jsonb)`,
			claims.UserID, id, rid, string(raw)).Scan(&out)
	})
	if err != nil {
		writeMeetProblem(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}
