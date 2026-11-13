// localcapture_test.go — MEET M5 slice 2 route + descriptor-contract tests.
// The flag gate pins full inertness (feature.meet_local_recording OFF ⇒
// every route 404s before any pool work), the body validators refuse before
// any database contact, and the descriptor truthfulness tests pin the
// validateLocalDescriptor + verifyDescriptorDigest contract against the
// slice-1 client substrate — including a CROSS-LANGUAGE known-answer
// vector: the fixture's integrity digest is the one the shipped
// clients/desktop/electron/src/meet/registration.ts canonicalJson+digest
// produces for the same descriptor, so the two planes' Seal genres are
// pinned byte-identical, not just shape-identical. The pin is TWO-SIDED:
// the shipped TS module asserts this same constant against the same fixture
// in registration.test.ts (the cross-language seal KAT describe block), so
// a digest drift on either plane fails a test THERE, not only here.
package meet

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/toggle"
)

func localCaptureHandler(t *testing.T, enabled bool) *Handler {
	t.Helper()
	return NewHandler(nil, toggle.NewTestFlags(map[string]bool{
		"feature.meet":                 true,
		"feature.meet_local_recording": enabled,
	}), configuredCfg, nil, nil, nil, nil)
}

func authedLocalReq(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	return r.WithContext(auth.ContextWithUser(r.Context(), &auth.Claims{UserID: 7}))
}

// TestLocalCaptureFlagOffNewIntentVerbs404 pins the M5 gate: every
// local-capture route is NEW INTENT — with the flag OFF the surface is
// INERT (404, indistinguishable from an absent route), even with meet ON.
func TestLocalCaptureFlagOffNewIntentVerbs404(t *testing.T) {
	cases := []struct {
		verb, path, body string
	}{
		{"POST", "/meet/5/local/lease", `{"deviceId":"dev","surfaces":["microphone"]}`},
		{"POST", "/meet/5/local/9/heartbeat", `{"leaseGeneration":1,"seq":1}`},
		{"POST", "/meet/5/local/9/stop", `{}`},
		{"POST", "/meet/5/local/9/register", `{"schema":"sjrec-local-v1"}`},
	}
	h := localCaptureHandler(t, false)
	for _, c := range cases {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, authedLocalReq(c.verb, c.path, c.body))
		if rr.Code != http.StatusNotFound {
			t.Errorf("%s %s with flag OFF: want 404, got %d: %s", c.verb, c.path, rr.Code, rr.Body.String())
		}
	}
}

// TestLocalCaptureBodyValidationRefusesBeforeDB pins the request-shape
// refusals that fire before any pool work (the handler here carries a nil
// pool: reaching it would panic, so any 2xx/5xx in this table is a bug).
func TestLocalCaptureBodyValidationRefusesBeforeDB(t *testing.T) {
	cases := []struct {
		name, verb, path, body string
		wantStatus             int
	}{
		{"lease missing deviceId", "POST", "/meet/5/local/lease",
			`{"surfaces":["microphone"]}`, http.StatusUnprocessableEntity},
		{"lease empty deviceId", "POST", "/meet/5/local/lease",
			`{"deviceId":"","surfaces":["microphone"]}`, http.StatusUnprocessableEntity},
		{"lease unknown surface", "POST", "/meet/5/local/lease",
			`{"deviceId":"dev","surfaces":["screen"]}`, http.StatusUnprocessableEntity},
		{"lease empty surfaces", "POST", "/meet/5/local/lease",
			`{"deviceId":"dev","surfaces":[]}`, http.StatusUnprocessableEntity},
		{"lease duplicated surface", "POST", "/meet/5/local/lease",
			`{"deviceId":"dev","surfaces":["microphone","microphone"]}`, http.StatusUnprocessableEntity},
		{"lease missing producer pins", "POST", "/meet/5/local/lease",
			`{"deviceId":"dev","surfaces":["microphone"],"producer":{"platform":"darwin"}}`, http.StatusUnprocessableEntity},
		{"lease cadence out of range", "POST", "/meet/5/local/lease",
			`{"deviceId":"dev","surfaces":["microphone"],"producer":{"platform":"darwin","captureApiVersion":"e1"},"heartbeatSeconds":61}`,
			http.StatusUnprocessableEntity},
		{"heartbeat bad captureState", "POST", "/meet/5/local/9/heartbeat",
			`{"leaseGeneration":1,"seq":1,"captureState":"flying"}`, http.StatusUnprocessableEntity},
		{"heartbeat seq below 1", "POST", "/meet/5/local/9/heartbeat",
			`{"leaseGeneration":1,"seq":0}`, http.StatusUnprocessableEntity},
		{"stop unknown reason", "POST", "/meet/5/local/9/stop",
			`{"reason":"because"}`, http.StatusUnprocessableEntity},
		{"register invalid JSON", "POST", "/meet/5/local/9/register",
			`{`, http.StatusBadRequest},
		{"register wrong schema", "POST", "/meet/5/local/9/register",
			`{"schema":"sjrec-local-v2"}`, http.StatusForbidden},
		{"register over the body cap", "POST", "/meet/5/local/9/register",
			`{"pad":"` + strings.Repeat("x", 1<<21) + `"}`, http.StatusRequestEntityTooLarge},
		{"lease bad meeting id", "POST", "/meet/notanumber/local/lease",
			`{"deviceId":"dev","surfaces":["microphone"]}`, http.StatusBadRequest},
		{"lease malformed body", "POST", "/meet/5/local/lease",
			`{`, http.StatusBadRequest},
		{"register bad rid", "POST", "/meet/5/local/notanumber/register",
			`{"schema":"sjrec-local-v1"}`, http.StatusBadRequest},
		{"heartbeat bad rid", "POST", "/meet/5/local/notanumber/heartbeat",
			`{"leaseGeneration":1,"seq":1}`, http.StatusBadRequest},
		{"stop bad rid", "POST", "/meet/5/local/notanumber/stop",
			`{}`, http.StatusBadRequest},
		{"heartbeat malformed body", "POST", "/meet/5/local/9/heartbeat",
			`{`, http.StatusBadRequest},
		{"stop malformed body", "POST", "/meet/5/local/9/stop",
			`{`, http.StatusBadRequest},
	}
	h := localCaptureHandler(t, true)
	for _, c := range cases {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, authedLocalReq(c.verb, c.path, c.body))
		if rr.Code != c.wantStatus {
			t.Errorf("%s: want %d, got %d: %s", c.name, c.wantStatus, rr.Code, rr.Body.String())
		}
	}
}

// descriptorFixtureJSON is the known-answer descriptor: a verified segment
// plus a truthful interrupted one over [0,1500). Its integrity digest is
// the byte-identical seal the slice-1 TS module computes.
const descriptorFixtureDigest = "969f4e1d930f4fcb4bb64260bc831bbe9c77799feb97b1262cae6fe432b7fe10"

const descriptorFixtureJSON = `{
  "schema": "sjrec-local-v1",
  "meetingId": 5,
  "recordingId": null,
  "packageState": "finalized",
  "captureMode": "local_registered",
  "policyMode": "local_only",
  "surfaces": ["microphone"],
  "producer": {"platform": "darwin", "platformVersion": "24.0.0", "captureApiVersion": "electron-1+chromium-2"},
  "startedAtUnixMs": 500,
  "endedAtUnixMs": 1500,
  "registeredAtUnixMs": null,
  "segments": [
    {"seq": 1, "state": "verified",
     "contentSha256": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
     "byteSize": 100, "mimeType": "audio/webm", "codec": "opus", "container": "webm",
     "interval": {"startMs": 0, "endMs": 1000},
     "wallStartUnixMs": 500, "wallEndUnixMs": 1500, "interruptReason": null},
    {"seq": 2, "state": "interrupted",
     "contentSha256": null, "byteSize": null, "mimeType": null, "codec": null, "container": null,
     "interval": {"startMs": 1000, "endMs": 1500},
     "wallStartUnixMs": 1500, "wallEndUnixMs": 1800, "interruptReason": "device_stopped"}
  ],
  "uploadedToDrive": false,
  "coverage": {"available": [{"startMs": 0, "endMs": 1000}], "gaps": [{"startMs": 1000, "endMs": 1500}]},
  "integrityDigest": "` + descriptorFixtureDigest + `"
}`

func validFixtureDescriptor(t *testing.T) *localPackageDescriptor {
	t.Helper()
	d, err := decodeDescriptorForTest([]byte(descriptorFixtureJSON))
	if err != nil {
		t.Fatalf("fixture does not decode: %v", err)
	}
	return d
}

// TestValidateLocalDescriptorAcceptsTruthful pins the truthful path: the
// known-answer fixture validates AND seals against the TS-computed digest.
func TestValidateLocalDescriptorAcceptsTruthful(t *testing.T) {
	d := validFixtureDescriptor(t)
	if err := validateLocalDescriptor(d, 5, 9); err != nil {
		t.Fatalf("truthful descriptor refused: %v", err)
	}
	if err := verifyDescriptorDigest([]byte(descriptorFixtureJSON), descriptorFixtureDigest); err != nil {
		t.Fatalf("cross-language seal mismatch: %v", err)
	}
}

// TestValidateLocalDescriptorRefusesUntruthful pins the named refusals —
// every untruthful shape fails closed with the segment.go vocabulary.
func TestValidateLocalDescriptorRefusesUntruthful(t *testing.T) {
	mutate := func(f func(d *localPackageDescriptor)) string {
		d := validFixtureDescriptor(t)
		f(d)
		err := validateLocalDescriptor(d, 5, 9)
		if err == nil {
			return ""
		}
		return err.Error()
	}
	cases := []struct {
		name   string
		mutate func(d *localPackageDescriptor)
		wantIn string
	}{
		{"schema drift", func(d *localPackageDescriptor) { d.Schema = "sjrec-local-v2" }, "is not sjrec-local-v1"},
		{"capture mode drift", func(d *localPackageDescriptor) { d.CaptureMode = "server_audio" }, "local_registered"},
		{"claimed upload", func(d *localPackageDescriptor) { t := true; d.UploadedToDrive = &t }, "upload path"},
		{"missing upload field", func(d *localPackageDescriptor) { d.UploadedToDrive = nil }, "upload path"},
		{"foreign meeting", func(d *localPackageDescriptor) { d.MeetingID = 6 }, "not 5"},
		{"foreign recording", func(d *localPackageDescriptor) { r := int64(10); d.RecordingID = &r }, "not 9"},
		{"unsealed package state", func(d *localPackageDescriptor) { d.PackageState = "recording" }, "not a sealed package"},
		{"missing end time", func(d *localPackageDescriptor) { d.EndedAtUnixMs = nil }, "end time"},
		{"ends before start", func(d *localPackageDescriptor) { e := int64(499); d.EndedAtUnixMs = &e }, "ends before it starts"},
		{"unknown policy mode", func(d *localPackageDescriptor) { d.PolicyMode = "yolo" }, "unknown policy mode"},
		{"missing producer pin", func(d *localPackageDescriptor) { d.Producer.CaptureAPIVersion = "" }, "captureApiVersion"},
		{"no surfaces", func(d *localPackageDescriptor) { d.Surfaces = nil }, "no capture surface"},
		{"video surface", func(d *localPackageDescriptor) { d.Surfaces = []string{"screen"} }, "not a capture surface"},
		{"duplicated surface", func(d *localPackageDescriptor) {
			d.Segments = d.Segments[:1]
			d.Surfaces = []string{"microphone", "microphone"}
		}, "duplicated"},
		{"missing start time", func(d *localPackageDescriptor) { d.StartedAtUnixMs = 0 }, "start time"},
		{"registered without registration time", func(d *localPackageDescriptor) {
			d.PackageState = "registered"
			d.RegisteredAtUnixMs = nil
		}, "registration time"},
		{"no segments", func(d *localPackageDescriptor) { d.Segments = nil }, "must number 1"},
		{"capturing segment in sealed package", func(d *localPackageDescriptor) {
			d.Segments[1].State = "capturing"
			d.Segments[1].InterruptReason = nil
		}, "capturing"},
		{"verified without digest", func(d *localPackageDescriptor) { d.Segments[0].ContentSha256 = nil }, "digest"},
		{"verified with short digest", func(d *localPackageDescriptor) {
			h := "a1b2"
			d.Segments[0].ContentSha256 = &h
		}, "digest"},
		{"verified without size", func(d *localPackageDescriptor) { d.Segments[0].ByteSize = nil }, "byte size"},
		{"verified without codec", func(d *localPackageDescriptor) { c := ""; d.Segments[0].Codec = &c }, "MIME/codec/container"},
		{"zero interval", func(d *localPackageDescriptor) {
			d.Segments[0].Interval.EndMs = 0
			d.Segments[0].Interval.StartMs = 0
		}, "positive interval"},
		{"interrupted without reason", func(d *localPackageDescriptor) { d.Segments[1].InterruptReason = nil }, "must name why it stopped"},
		{"coverage gap hidden", func(d *localPackageDescriptor) { d.Coverage.Gaps = nil }, "fabricated coverage"},
		{"coverage inflated", func(d *localPackageDescriptor) {
			d.Coverage.Available[0].EndMs = 1500
		}, "fabricated coverage"},
	}
	for _, c := range cases {
		got := mutate(c.mutate)
		if got == "" {
			t.Errorf("%s: expected refusal containing %q, got none", c.name, c.wantIn)
			continue
		}
		if !strings.Contains(got, c.wantIn) {
			t.Errorf("%s: refusal %q does not name %q", c.name, got, c.wantIn)
		}
	}
}

// TestValidateLocalDescriptorRefusesDuplicateMedia pins the overlap arm:
// two verified segments sharing media time fail closed (segment.go's
// duplicate-media rule, met through ComputeCoverage).
func TestValidateLocalDescriptorRefusesDuplicateMedia(t *testing.T) {
	d := validFixtureDescriptor(t)
	d.Segments[1] = d.Segments[0]
	d.Segments[1].Seq = 2
	d.Segments[1].InterruptReason = nil
	err := validateLocalDescriptor(d, 5, 9)
	if err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("duplicate verified media: want overlap refusal, got %v", err)
	}
}

// TestValidateLocalDescriptorRefusesSegmentCap pins the 10k cap mirror.
func TestValidateLocalDescriptorRefusesSegmentCap(t *testing.T) {
	d := validFixtureDescriptor(t)
	d.Segments = make([]localPackageSegment, maxLocalPackageSegments+1)
	for i := range d.Segments {
		d.Segments[i] = d.Segments[0]
		d.Segments[i].Seq = int64(i + 1)
		d.Segments[i].Interval = localSegmentInterval{StartMs: int64(i) * 100, EndMs: int64(i)*100 + 100}
	}
	err := validateLocalDescriptor(d, 5, 9)
	if err == nil || !strings.Contains(err.Error(), "1..10000") {
		t.Fatalf("over-cap descriptor: want cap refusal, got %v", err)
	}
}

// TestVerifyDescriptorDigestRefusesTampering pins the Seal genre: any byte
// drift the digest covers, a digest-field absence, and a wrong claim all
// refuse — a descriptor cannot claim a seal its bytes do not hash to.
func TestVerifyDescriptorDigestRefusesTampering(t *testing.T) {
	tampered := strings.Replace(descriptorFixtureJSON, `"byteSize": 100`, `"byteSize": 101`, 1)
	if tampered == descriptorFixtureJSON {
		t.Fatal("tamper target not found")
	}
	if err := verifyDescriptorDigest([]byte(tampered), descriptorFixtureDigest); err == nil {
		t.Fatal("tampered descriptor accepted its original seal")
	}
	if err := verifyDescriptorDigest([]byte(descriptorFixtureJSON), strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong claimed digest accepted")
	}
	noSeal := `{"schema":"sjrec-local-v1"}`
	if err := verifyDescriptorDigest([]byte(noSeal), descriptorFixtureDigest); err == nil {
		t.Fatal("descriptor without the integrityDigest field accepted")
	}
	if err := verifyDescriptorDigest([]byte(`[]`), descriptorFixtureDigest); err == nil {
		t.Fatal("non-object descriptor accepted")
	}
	if err := verifyDescriptorDigest([]byte(`not json`), descriptorFixtureDigest); err == nil {
		t.Fatal("invalid JSON accepted")
	}
	if err := verifyDescriptorDigest([]byte(descriptorFixtureJSON), ""); err == nil {
		t.Fatal("empty claimed digest accepted")
	}
}

// TestCanonicalJSONRefusesUnpinnableValues pins the encoder's fail-closed
// arms: values no JSON decode can produce (and their propagation through
// arrays/objects) error instead of silently emitting non-canonical bytes.
func TestCanonicalJSONRefusesUnpinnableValues(t *testing.T) {
	type unpinnable struct{}
	if _, err := canonicalJSON(unpinnable{}); err == nil {
		t.Fatal("struct value accepted")
	}
	if _, err := canonicalJSON([]any{unpinnable{}}); err == nil {
		t.Fatal("unpinnable array element accepted")
	}
	if _, err := canonicalJSON(map[string]any{"k": unpinnable{}}); err == nil {
		t.Fatal("unpinnable object value accepted")
	}
	if got, err := canonicalJSON(true); err != nil || got != "true" {
		t.Fatalf("bool canonical = %q (%v)", got, err)
	}
}

// TestVerifyDescriptorDigestKnownAnswerEscaping pins the string-escaping
// genre byte-for-byte against ECMAScript JSON.stringify (probed via the
// shipped TS canonicalJson): quote, backslash, \n, \t, and the \u0001
// lowercase-hex control escape — plus number-literal preservation. The
// remaining short escapes (\b \f \r) pin the same table below.
func TestVerifyDescriptorDigestKnownAnswerEscaping(t *testing.T) {
	const input = `{"a":"quote\"back\\slash\nnew\ttab\u0001ctl","integrityDigest":null,"b":{"k":[1,-2.5,1e+21]}}`
	const want = `{"a":"quote\"back\\slash\nnew\ttab\u0001ctl","b":{"k":[1,-2.5,1e+21]},"integrityDigest":null}`
	got, err := canonicalForTest([]byte(input))
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if got != want {
		t.Fatalf("canonical bytes diverge from the TS genre:\n got %s\nwant %s", got, want)
	}
	const bsInput = `{"a":"\b\f\r","integrityDigest":null}`
	const bsWant = `{"a":"\b\f\r","integrityDigest":null}`
	bsGot, err := canonicalForTest([]byte(bsInput))
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if bsGot != bsWant {
		t.Fatalf("short escapes diverge:\n got %s\nwant %s", bsGot, bsWant)
	}
}

// decodeDescriptorForTest mirrors the route's typed decode for fixtures.
func decodeDescriptorForTest(raw []byte) (*localPackageDescriptor, error) {
	var d localPackageDescriptor
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// canonicalForTest feeds raw JSON through the number-literal-preserving
// decode the route uses, then the canonical encoder under test.
func canonicalForTest(raw []byte) (string, error) {
	var value any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		return "", err
	}
	return canonicalJSON(value)
}
