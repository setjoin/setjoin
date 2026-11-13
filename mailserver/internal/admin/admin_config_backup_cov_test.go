package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"setjoin.com/shared/testsupport"
)

// covImportKey is an allowlisted, low-traffic key used by the ImportConfig
// coverage tests. Every write snapshots and restores the pre-test value so the
// shared test database keeps whatever other fixtures stored.
const covImportKey = "vacation_default_subject"

// TestConfigImport_BoundedStreamingWrites drives the rewritten ImportConfig
// (D-MAILSERVER-INTERNAL-ADMIN-F-010) end to end: the happy import path, both
// skip legs, the allowlist 403 short-circuit, the non-array and malformed-body
// 400s, the 4MB MaxBytesReader 413, the per-item count cap 413, the truncated
// body 400, and the per-item DB failure skip — each against the real DB.
func TestConfigImport_BoundedStreamingWrites(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewConfigBackupHandler(pool)

	// Snapshot + restore the raw jsonb of the row this test writes.
	var preVal []byte
	if err := pool.QueryRow(t.Context(),
		`SELECT value FROM system_config WHERE key = $1`, covImportKey).Scan(&preVal); err != nil {
		preVal = nil
	}
	t.Cleanup(func() {
		if preVal == nil {
			pool.Exec(context.Background(), `DELETE FROM system_config WHERE key = $1`, covImportKey) //nolint:errcheck
			return
		}
		pool.Exec(context.Background(),
			`INSERT INTO system_config (key, value) VALUES ($1, $2::jsonb)
			 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, covImportKey, preVal) //nolint:errcheck
	})

	importReq := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/admin/config/backup/import", strings.NewReader(body))
		rec := httptest.NewRecorder()
		h.ImportConfig(rec, req)
		return rec
	}

	t.Run("happy path imports and records descriptions", func(t *testing.T) {
		rec := importReq(`[{"key":"` + covImportKey + `","value":"\"brb\"","description":"cov happy"},
			{"key":"` + covImportKey + `","value":"\"away\""}]`)
		if rec.Code != http.StatusOK {
			t.Fatalf("import: want 200, got %d (%s)", rec.Code, rec.Body.String())
		}
		var out struct {
			Imported int `json:"imported"`
			Skipped  int `json:"skipped"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode import response: %v", err)
		}
		if out.Imported != 2 || out.Skipped != 0 {
			t.Fatalf("imported=%d skipped=%d, want 2/0", out.Imported, out.Skipped)
		}
		var val, desc string
		if err := pool.QueryRow(t.Context(),
			`SELECT value #>> '{}', COALESCE(description,'') FROM system_config WHERE key = $1`,
			covImportKey).Scan(&val, &desc); err != nil {
			t.Fatalf("read imported row: %v", err)
		}
		if val != "away" {
			t.Fatalf("last write wins: value=%q, want away", val)
		}
		if desc != "cov happy" {
			t.Fatalf("ON CONFLICT keep-first-description violated: description=%q", desc)
		}
	})

	t.Run("redacted and non-string values are skipped not written", func(t *testing.T) {
		rec := importReq(`[{"key":"` + covImportKey + `","value":"[ENCRYPTED]"},
			{"key":"` + covImportKey + `","value":42},
			{"key":"` + covImportKey + `","value":"\"kept\""}]`)
		if rec.Code != http.StatusOK {
			t.Fatalf("import: want 200, got %d (%s)", rec.Code, rec.Body.String())
		}
		var out struct {
			Imported int `json:"imported"`
			Skipped  int `json:"skipped"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode import response: %v", err)
		}
		if out.Imported != 1 || out.Skipped != 2 {
			t.Fatalf("imported=%d skipped=%d, want 1/2", out.Imported, out.Skipped)
		}
	})

	t.Run("empty key items are ignored without counting", func(t *testing.T) {
		rec := importReq(`[{"value":"x"},{"key":"","value":"y"},{"key":"` + covImportKey + `","value":"\"k\""}]`)
		if rec.Code != http.StatusOK {
			t.Fatalf("import: want 200, got %d (%s)", rec.Code, rec.Body.String())
		}
		var out struct {
			Imported int `json:"imported"`
			Skipped  int `json:"skipped"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode import response: %v", err)
		}
		if out.Imported != 1 || out.Skipped != 0 {
			t.Fatalf("imported=%d skipped=%d, want 1/0", out.Imported, out.Skipped)
		}
	})

	t.Run("disallowed key fails fast with 403 and writes nothing", func(t *testing.T) {
		rec := importReq(`[{"key":"migrations_owned_key","value":"\"x\""}]`)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("import: want 403, got %d (%s)", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "cannot be imported") {
			t.Fatalf("403 body missing the reason: %s", rec.Body.String())
		}
	})

	t.Run("non-array body is 400", func(t *testing.T) {
		if rec := importReq(`{"key":"` + covImportKey + `"}`); rec.Code != http.StatusBadRequest {
			t.Fatalf("object body: want 400, got %d (%s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("malformed body is 400", func(t *testing.T) {
		if rec := importReq(`{not json`); rec.Code != http.StatusBadRequest {
			t.Fatalf("malformed body: want 400, got %d (%s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("truncated array is 400", func(t *testing.T) {
		rec := importReq(`[{"key":"` + covImportKey + `","value":"\"partial\""}`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("truncated body: want 400, got %d (%s)", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "invalid JSON") {
			t.Fatalf("truncated body: unexpected message %s", rec.Body.String())
		}
	})

	t.Run("array closed with a brace is 400 at the closing bracket", func(t *testing.T) {
		rec := importReq(`[{"key":"` + covImportKey + `","value":"\"v\""}}`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("brace-closed array: want 400, got %d (%s)", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "invalid JSON") {
			t.Fatalf("brace-closed array: unexpected message %s", rec.Body.String())
		}
	})

	t.Run("oversized body hits the 4MB cap with 413", func(t *testing.T) {
		big := `[{"key":"` + covImportKey + `","value":"` + strings.Repeat("x", 5<<20) + `"}]`
		rec := importReq(big)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("oversized body: want 413, got %d (%s)", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "too large") {
			t.Fatalf("413 body missing the cap reason: %s", rec.Body.String())
		}
	})

	t.Run("oversized first token is 413 before any structure check", func(t *testing.T) {
		// A valid-JSON single string that trips the 4MB cap while the decoder
		// is still reading the FIRST token — the cap must fire before the
		// array-structure check.
		rec := importReq(`"` + strings.Repeat("x", 5<<20) + `"`)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("oversized first token: want 413, got %d (%s)", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "too large") {
			t.Fatalf("413 body missing the cap reason: %s", rec.Body.String())
		}
	})

	t.Run("more than 512 items is 413", func(t *testing.T) {
		var b strings.Builder
		b.WriteString(`[`)
		for i := 0; i < 513; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString(`{"key":"` + covImportKey + `","value":"\"n\"","description":"cap"}`)
		}
		b.WriteString(`]`)
		rec := importReq(b.String())
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("513 items: want 413, got %d (%s)", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "too many config items") {
			t.Fatalf("413 body missing the item-cap reason: %s", rec.Body.String())
		}
		var val string
		if err := pool.QueryRow(t.Context(),
			`SELECT value #>> '{}' FROM system_config WHERE key = $1`, covImportKey).Scan(&val); err != nil {
			t.Fatalf("read row after item-cap rejection: %v", err)
		}
		if val != "n" {
			t.Fatalf("item-cap value = %q, want the 512 streamed writes to have landed", val)
		}
	})

	t.Run("value that fails the jsonb cast is skipped not fatal", func(t *testing.T) {
		rec := importReq(`[{"key":"` + covImportKey + `","value":"\"ok\""},
			{"key":"` + covImportKey + `","value":"not json"},
			{"key":"` + covImportKey + `","value":"\"final\""}]`)
		if rec.Code != http.StatusOK {
			t.Fatalf("import with bad jsonb: want 200, got %d (%s)", rec.Code, rec.Body.String())
		}
		var out struct {
			Imported int `json:"imported"`
			Skipped  int `json:"skipped"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode import response: %v", err)
		}
		if out.Imported != 2 || out.Skipped != 1 {
			t.Fatalf("imported=%d skipped=%d, want 2/1", out.Imported, out.Skipped)
		}
		var val string
		if err := pool.QueryRow(t.Context(),
			`SELECT value #>> '{}' FROM system_config WHERE key = $1`, covImportKey).Scan(&val); err != nil {
			t.Fatal(err)
		}
		if val != "final" {
			t.Fatalf("value=%q, want final (the bad item must not abort the stream)", val)
		}
	})
}
