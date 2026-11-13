package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/geoip"
	"setjoin.com/shared/threat"
	"setjoin.com/shared/toggle"
)

// The GeoIP database is the enforcement input for GEO_BLOCK_COUNTRIES and
// country conditional-access conditions. These tests pin the arming contract
// across the TWO path topologies (med-shard3-006): the default download-cache
// path is remote-channel input and arms only on a pinned-digest match — never
// on file presence, no matter how the bytes arrived — while an explicitly
// configured GEOIP_DB_PATH (operator topology) arms on structural validity
// with digest validation when pinned. A missing/tampered/malformed/unpinned
// input is a loud failure signal — never a "ready" claim, never a silently
// dead control.

// TestArmGeoIPResolution_CacheArmsWithMatchingPinnedDigestAndFires is the
// startup contract for the default cache path: with the database present at
// the cache path and the operator pin matching its bytes, country resolution
// arms and the geo-block control actually rejects a connection from a
// configured country through the real pipeline.
func TestArmGeoIPResolution_CacheArmsWithMatchingPinnedDigestAndFires(t *testing.T) {
	capture := &captureHandler{}
	logger := slog.New(capture)

	dbPath := writeTestGeoIPDB(t)
	data, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}

	reader := armGeoIPResolution(geoip.SourceDownloadCache, dbPath, sha256Hex(data), []string{"DE"}, logger)
	if reader == nil {
		t.Fatal("expected country resolution to arm when the cache bytes match the pin")
	}
	defer reader.Close()

	joined := strings.Join(capture.messages(), "\n")
	if !strings.Contains(joined, "country resolution armed") {
		t.Errorf("expected armed signal, got %q", joined)
	}
	if strings.Contains(joined, "database ready") {
		t.Errorf("readiness is claimed by the validated open only: %q", joined)
	}

	// The armed input must actually drive the control: DE is blocked through
	// the same pipeline steps production uses (geo_block enabled by registry
	// default; DB-backed steps disabled/nil here).
	ti := threat.New(nil, nil,
		toggle.NewTestFlags(map[string]bool{toggle.FeatureThreatFeed: false}),
		reader,
		threat.ThreatConfig{BlockCountries: []string{"DE"}},
		logger, nil)
	result, reason, _ := ti.Intercept(context.Background(), &threat.ConnectionMeta{
		SourceIP: "203.0.113.7",
		Protocol: threat.ProtocolIMAP,
		Country:  "", // resolved from the database by Intercept
	})
	if result != threat.ActionReject {
		t.Errorf("expected geo_block to reject a DE connection, got action=%v reason=%q", result, reason)
	}
	if reason != "geo_blocked" {
		t.Errorf("expected geo_blocked reason, got %q", reason)
	}
}

// TestArmGeoIPResolution_CacheWithoutPinNotArmedEvenWhenPresent is the
// med-shard3-006 regression: a well-formed database already sitting at the
// default (download-cache) path does NOT arm when no digest is pinned — a
// cache file is remote-channel input, never operator authority, regardless of
// how it arrived (legacy download, substitution). The failure must be loud
// and name the non-enforcing control when geo-block is configured.
func TestArmGeoIPResolution_CacheWithoutPinNotArmedEvenWhenPresent(t *testing.T) {
	capture := &captureHandler{}
	logger := slog.New(capture)

	dbPath := writeTestGeoIPDB(t) // well-formed, pre-existing, no pin

	reader := armGeoIPResolution(geoip.SourceDownloadCache, dbPath, "", strings.Split("DE,CN", ","), logger)
	if reader != nil {
		t.Fatal("cache path without a pin must not arm, even with a well-formed file present")
	}

	joined := strings.Join(capture.messages(), "\n")
	if !strings.Contains(joined, "country resolution NOT armed") {
		t.Errorf("expected NOT-armed failure signal, got %q", joined)
	}
	// The mandatory-pin refusal text rides in the failure record's error
	// attribute, so flatten messages and attrs for this assertion.
	if flat := flattenRecords(capture.records); !strings.Contains(flat, "requires a pinned digest") {
		t.Errorf("expected the mandatory-pin refusal to be recorded, got %q", flat)
	}
	if !strings.Contains(joined, "GEO_BLOCK_COUNTRIES is configured but non-enforcing") {
		t.Errorf("expected explicit non-enforcing signal for configured geo-block, got %q", joined)
	}
	for _, r := range capture.records {
		if r.Level < slog.LevelError {
			continue
		}
		if strings.Contains(r.Message, "database ready") {
			t.Errorf("failure path must never claim readiness: %q", r.Message)
		}
	}
}

// TestArmGeoIPResolution_OperatorFileWithoutPinArms: an explicitly configured
// GEOIP_DB_PATH is operator-supplied input — the operator topology keeps
// arming on structural validity without a pin (unchanged contract).
func TestArmGeoIPResolution_OperatorFileWithoutPinArms(t *testing.T) {
	capture := &captureHandler{}
	logger := slog.New(capture)

	dbPath := writeTestGeoIPDB(t)

	reader := armGeoIPResolution(geoip.SourceOperatorFile, dbPath, "", nil, logger)
	if reader == nil {
		t.Fatal("operator topology must arm on a structurally valid file without a pin")
	}
	defer reader.Close()

	joined := strings.Join(capture.messages(), "\n")
	if !strings.Contains(joined, "country resolution armed") {
		t.Errorf("expected armed signal, got %q", joined)
	}
}

// TestArmGeoIPResolutionRefusesTamperedDBLoudly: a database that fails digest
// validation must not arm, and the failure must state that configured country
// controls are non-enforcing.
func TestArmGeoIPResolutionRefusesTamperedDBLoudly(t *testing.T) {
	capture := &captureHandler{}
	logger := slog.New(capture)

	dbPath := writeTestGeoIPDB(t)
	// Pin a digest of different bytes — the cached file no longer matches.
	pinned := sha256Hex([]byte("not-the-database"))

	reader := armGeoIPResolution(geoip.SourceDownloadCache, dbPath, pinned, strings.Split("DE,CN", ","), logger)
	if reader != nil {
		t.Fatal("tampered database must not arm country resolution")
	}

	joined := strings.Join(capture.messages(), "\n")
	if !strings.Contains(joined, "country resolution NOT armed") {
		t.Errorf("expected NOT-armed failure signal, got %q", joined)
	}
	if !strings.Contains(joined, "GEO_BLOCK_COUNTRIES is configured but non-enforcing") {
		t.Errorf("expected explicit non-enforcing signal for configured geo-block, got %q", joined)
	}
	for _, r := range capture.records {
		if r.Level < slog.LevelError {
			continue
		}
		if strings.Contains(r.Message, "database ready") {
			t.Errorf("failure path must never claim readiness: %q", r.Message)
		}
	}
}

// TestArmGeoIPResolutionRefusesMissingDB: a missing database is a failure
// signal even without geo-block configured (country CA conditions would also
// silently lose their input).
func TestArmGeoIPResolutionRefusesMissingDB(t *testing.T) {
	capture := &captureHandler{}
	logger := slog.New(capture)

	reader := armGeoIPResolution(geoip.SourceDownloadCache, "/nonexistent/geoip.mmdb", "", nil, logger)
	if reader != nil {
		t.Fatal("missing database must not arm country resolution")
	}

	joined := strings.Join(capture.messages(), "\n")
	if !strings.Contains(joined, "country resolution NOT armed") {
		t.Errorf("expected NOT-armed failure signal, got %q", joined)
	}
	if strings.Contains(joined, "GEO_BLOCK_COUNTRIES is configured") {
		t.Errorf("geo-block hint must not fire when GEO_BLOCK_COUNTRIES is unset: %q", joined)
	}
}

// TestGeoBlockCountriesConfigured — an unset GEO_BLOCK_COUNTRIES splits to
// [""], which is not a configuration.
func TestGeoBlockCountriesConfigured(t *testing.T) {
	if geoBlockCountriesConfigured(strings.Split("", ",")) {
		t.Error("unset variable must not count as configured")
	}
	if geoBlockCountriesConfigured([]string{"", " "}) {
		t.Error("blank entries must not count as configured")
	}
	if !geoBlockCountriesConfigured([]string{"", "DE"}) {
		t.Error("any non-blank entry counts as configured")
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

type captureHandler struct {
	records []slog.Record
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.records = append(h.records, r.Clone())
	return nil
}
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

func (h *captureHandler) messages() []string {
	out := make([]string, 0, len(h.records))
	for _, r := range h.records {
		out = append(out, r.Message)
	}
	return out
}

// flattenRecords renders every record's message and attributes — assertions
// on failure DETAIL (which rides in the error attribute) use this.
func flattenRecords(records []slog.Record) string {
	var b strings.Builder
	for _, r := range records {
		b.WriteString(r.Message)
		b.WriteString("\n")
		r.Attrs(func(a slog.Attr) bool {
			fmt.Fprintf(&b, "%s=%v\n", a.Key, a.Value)
			return true
		})
	}
	return b.String()
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// writeTestGeoIPDB persists a minimal well-formed country database (every
// IPv4 address resolves to {"country":{"iso_code":"DE"}}) and returns its
// path. See mailserver/internal/geoip/dbip_test.go for the encoding details.
func writeTestGeoIPDB(t *testing.T) string {
	t.Helper()

	var buf bytes.Buffer
	// Search tree: one 24-bit node; record value = node_count(1) + separator(16).
	rec := []byte{0x00, 0x00, 0x11}
	buf.Write(rec)
	buf.Write(rec)
	// Data section separator.
	buf.Write(make([]byte, 16))
	// {"country":{"iso_code":"DE"}}
	buf.WriteByte(0xE1)
	buf.WriteByte(0x47)
	buf.WriteString("country")
	buf.WriteByte(0xE1)
	buf.WriteByte(0x48)
	buf.WriteString("iso_code")
	buf.WriteByte(0x42)
	buf.WriteString("DE")
	// Metadata start marker + metadata map.
	buf.Write([]byte{0xAB, 0xCD, 0xEF})
	buf.WriteString("MaxMind.com")
	buf.WriteByte(0xE0 | 8)
	for _, kv := range []struct {
		key string
		val []byte
	}{
		{"binary_format_major_version", []byte{0xA1, 0x02}},
		{"binary_format_minor_version", []byte{0xA0}},
		{"database_type", []byte{0x51, 'D', 'B', 'I', 'P', '-', 'C', 'o', 'u', 'n', 't', 'r', 'y', '-', 'L', 'i', 't', 'e'}},
		{"description", []byte{0xE1, 0x42, 'e', 'n', 0x47, 's', 'e', 't', 'j', 'o', 'i', 'n'}},
		{"languages", []byte{0x01, 0x04, 0x42, 'e', 'n'}},
		{"ip_version", []byte{0xA1, 0x04}},
		{"node_count", []byte{0xA1, 0x01}},
		{"record_size", []byte{0xA1, 0x18}},
	} {
		buf.WriteByte(byte(0x40 | len(kv.key)))
		buf.WriteString(kv.key)
		buf.Write(kv.val)
	}

	path := t.TempDir() + "/geoip.mmdb"
	if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
		t.Fatalf("write test geoip db: %v", err)
	}
	return path
}
