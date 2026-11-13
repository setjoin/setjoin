package smime

// Refresh: curl -fsS https://curl.se/ca/cacert.pem -o mailserver/internal/smime/cacert.pem

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestBundleNotStale fails when the embedded CA bundle is older than 183 days,
// forcing a deliberate refresh. The curl.se bundle embeds a header line like:
//
//	## Certificate data from Mozilla as of: Thu May 14 03:12:02 2026 GMT
//
// If that line is absent (e.g. host-store fallback), the test falls back to
// the file's mtime.
func TestBundleNotStale(t *testing.T) {
	const maxAge = 183 * 24 * time.Hour

	bundleDate := parseBundleDate(bundledCABytes)
	if bundleDate.IsZero() {
		// Fallback: use the file's mtime (host-store bundle won't have the header).
		_, thisFile, _, _ := runtime.Caller(0)
		pemPath := filepath.Join(filepath.Dir(thisFile), "cacert.pem")
		info, err := os.Stat(pemPath)
		if err != nil {
			t.Fatalf("cannot stat cacert.pem: %v", err)
		}
		bundleDate = info.ModTime()
		t.Logf("no 'as of' date in bundle header; using file mtime: %s", bundleDate.Format(time.RFC1123))
	} else {
		t.Logf("bundle date: %s", bundleDate.Format(time.RFC1123))
	}

	age := time.Since(bundleDate)
	if age > maxAge {
		t.Fatalf("CA bundle is %.0f days old (limit 183). Refresh with:\n  curl -fsS https://curl.se/ca/cacert.pem -o mailserver/internal/smime/cacert.pem", age.Hours()/24)
	}
}

// parseBundleDate extracts the date from the curl.se header comment, e.g.:
//
//	## Certificate data from Mozilla as of: Thu May 14 03:12:02 2026 GMT
func parseBundleDate(data []byte) time.Time {
	const prefix = "## Certificate data from Mozilla as of: "
	// The curl.se bundle format uses "as of:", but handle minor wording variants
	// by also checking the older "generated:" form.
	const altPrefix = "## Certificate data generated: "

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		var dateStr string
		if after, ok := strings.CutPrefix(line, prefix); ok {
			dateStr = strings.TrimSpace(after)
		} else if after, ok := strings.CutPrefix(line, altPrefix); ok {
			dateStr = strings.TrimSpace(after)
		}
		if dateStr == "" {
			continue
		}
		// Format: "Thu May 14 03:12:02 2026 GMT"
		// Note: single-digit days appear as " 2" (space-padded), handled by _2.
		formats := []string{
			"Mon Jan _2 15:04:05 2006 MST",
			"Mon Jan  2 15:04:05 2006 MST",
			"Mon Jan 2 15:04:05 2006 MST",
		}
		for _, fmt := range formats {
			if t, err := time.Parse(fmt, dateStr); err == nil {
				return t
			}
		}
	}
	return time.Time{}
}
