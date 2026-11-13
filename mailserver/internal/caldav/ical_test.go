package caldav

import (
	"fmt"
	"testing"
	"time"
)

// TestLoadLocation_DoesNotCacheUnresolvableTZIDs pins the attacker-keyed cache
// hygiene (D-MAILSERVER-INTERNAL-CALDAV-007): a crafted/unresolvable TZID (even
// parsed many times, as a hostile PUT body would do) must never plant an
// entry — every attempt just falls back to UTC, leaving the bounded cache to
// legitimate zones only.
func TestLoadLocation_DoesNotCacheUnresolvableTZIDs(t *testing.T) {
	junk := []string{"Not/AZone", "../../etc/passwd", "", "UTC", "Etc/Gmt+ infected"}
	before := len(tzLocationCache)
	for _, tz := range junk {
		for i := 0; i < 3; i++ {
			if got := loadLocation(tz); got != time.UTC {
				t.Errorf("loadLocation(%q) = %v, want the UTC fallback", tz, got)
			}
		}
	}
	if after := len(tzLocationCache); after != before {
		t.Errorf("unresolvable/UTC TZIDs must not be cached: before=%d after=%d", before, after)
	}
}

// TestLoadLocation_BoundedFIFOEviction pins the size cap: once tzLocationCap
// synthetic entries are planted, caching a new zone must evict the oldest
// instead of growing the cache without bound.
func TestLoadLocation_BoundedFIFOEviction(t *testing.T) {
	tzLocationMu.Lock()
	origCache := make(map[string]*time.Location, len(tzLocationCache))
	origFIFO := make([]string, len(tzLocationFIFO))
	for k, v := range tzLocationCache {
		origCache[k] = v
	}
	copy(origFIFO, tzLocationFIFO)
	tzLocationMu.Unlock()
	t.Cleanup(func() {
		tzLocationMu.Lock()
		tzLocationCache = origCache
		tzLocationFIFO = origFIFO
		tzLocationMu.Unlock()
	})

	tzLocationMu.Lock()
	tzLocationCache = make(map[string]*time.Location)
	tzLocationFIFO = tzLocationFIFO[:0]
	tzLocationMu.Unlock()

	first := "Test/FirstZone"
	cacheLocation(first, time.FixedZone(first, 0))
	for i := 0; i < tzLocationCap; i++ {
		cacheLocation(fmt.Sprintf("Test/Zone%d", i), time.FixedZone(fmt.Sprintf("Z%d", i), 0))
	}

	tzLocationMu.Lock()
	size := len(tzLocationCache)
	_, firstSurvives := tzLocationCache[first]
	tzLocationMu.Unlock()
	if size != tzLocationCap {
		t.Errorf("cache size = %d, want the cap %d", size, tzLocationCap)
	}
	if firstSurvives {
		t.Error("oldest entry must be evicted once the cap is reached")
	}

	if got := loadLocation("Europe/Berlin"); got == time.UTC {
		t.Error("loadLocation must still resolve and cache legitimate zones under the cap")
	}
	tzLocationMu.Lock()
	size = len(tzLocationCache)
	tzLocationMu.Unlock()
	if size != tzLocationCap {
		t.Errorf("cache size after new insertion = %d, want the cap %d", size, tzLocationCap)
	}
}
