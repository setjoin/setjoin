package discovery

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// testBase is an arbitrary fixed instant for fake-clock tests.
var testBase = time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)

// useFakeNow swaps the package clock for a controllable fake and restores the
// real clock plus a clean cache when the test finishes.
func useFakeNow(t *testing.T, start time.Time) func(time.Duration) {
	t.Helper()
	current := start
	nowFunc = func() time.Time { return current }
	t.Cleanup(func() {
		nowFunc = time.Now
		resetCache(t)
	})
	return func(d time.Duration) { current = current.Add(d) }
}

func resetCache(t *testing.T) {
	t.Helper()
	cacheMu.Lock()
	cache = make(map[string]*cacheEntry)
	cacheMu.Unlock()
}

func cacheSize() int {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	return len(cache)
}

func keyFor(i int) string {
	return fmt.Sprintf("%d.wild.example", i)
}

// TestDiscoveryCacheTTLExpiryEvicts proves that an expired entry stops being a
// hit AND is actually removed from the map on access, instead of lingering
// forever as before.
func TestDiscoveryCacheTTLExpiryEvicts(t *testing.T) {
	advance := useFakeNow(t, testBase)
	cfg := &ServerConfig{URL: "https://mail.company.com", LoginField: "email"}

	cachePut("company.com", cfg)
	if got, ok := cacheGet("company.com"); !ok || got != cfg {
		t.Fatal("expected hit before TTL expiry")
	}

	advance(discoveryCacheTTL + time.Second)
	if got, ok := cacheGet("company.com"); ok || got != nil {
		t.Fatalf("expected miss after TTL expiry, got ok=%v config=%v", ok, got)
	}
	cacheMu.Lock()
	_, stillCached := cache["company.com"]
	cacheMu.Unlock()
	if stillCached {
		t.Fatal("expired entry was not evicted from the map on access")
	}
	if n := cacheSize(); n != 0 {
		t.Fatalf("cache holds %d entries after expiry eviction, want 0", n)
	}
}

// TestDiscoveryCacheEntryCapBoundsWildcardFlood proves the entry cap bounds
// resident memory when an attacker mints more distinct wildcard-host keys than
// the cap, and that legitimate keys inserted after the flood still hit.
func TestDiscoveryCacheEntryCapBoundsWildcardFlood(t *testing.T) {
	useFakeNow(t, testBase)

	const extra = 500
	total := maxDiscoveryCacheEntries + extra
	for i := 0; i < total; i++ {
		cachePut(keyFor(i), &ServerConfig{URL: "https://mx" + keyFor(i)})
	}

	if n := cacheSize(); n != maxDiscoveryCacheEntries {
		t.Fatalf("cache holds %d entries after %d distinct keys, want cap %d", n, total, maxDiscoveryCacheEntries)
	}

	lastKey := keyFor(total - 1)
	cacheMu.Lock()
	_, lastCached := cache[lastKey]
	cacheMu.Unlock()
	if !lastCached {
		t.Fatalf("most recently inserted key %q missing from cache", lastKey)
	}

	// Legitimate traffic keeps working under cap pressure.
	legit := &ServerConfig{URL: "https://mail.company.com", LoginField: "email"}
	cachePut("company.com", legit)
	if got, ok := cacheGet("company.com"); !ok || got != legit {
		t.Fatal("legitimate entry missing/hitting incorrectly after wildcard flood")
	}
}

// TestDiscoveryCachePruneExpiredBeforeEvictingLive proves the insert path
// prunes expired entries first, so a fully-expired cache collapses instead of
// evicting live victims one by one.
func TestDiscoveryCachePruneExpiredBeforeEvictingLive(t *testing.T) {
	advance := useFakeNow(t, testBase)
	for i := 0; i < maxDiscoveryCacheEntries; i++ {
		cachePut(keyFor(i), &ServerConfig{URL: "https://" + keyFor(i)})
	}

	advance(discoveryCacheTTL + time.Second)
	legit := &ServerConfig{URL: "https://mail.company.com"}
	cachePut("company.com", legit)

	if n := cacheSize(); n != 1 {
		t.Fatalf("cache holds %d entries after full expiry + 1 put, want 1", n)
	}
	if got, ok := cacheGet("company.com"); !ok || got != legit {
		t.Fatal("legit entry missing after expired entries were pruned")
	}
}

// TestDiscoveryCacheEvictsEarliestExpiry proves the overflow victim is the
// entry closest to expiry (the oldest one), not an arbitrary live entry.
func TestDiscoveryCacheEvictsEarliestExpiry(t *testing.T) {
	advance := useFakeNow(t, testBase)
	for i := 0; i < maxDiscoveryCacheEntries; i++ {
		cachePut(keyFor(i), &ServerConfig{URL: "https://" + keyFor(i)})
		advance(time.Millisecond) // each successive entry expires later, total << TTL
	}

	fresh := &ServerConfig{URL: "https://fresh.example"}
	cachePut("fresh.example", fresh)

	if n := cacheSize(); n != maxDiscoveryCacheEntries {
		t.Fatalf("cache holds %d entries, want cap %d", n, maxDiscoveryCacheEntries)
	}
	cacheMu.Lock()
	_, oldestPresent := cache[keyFor(0)]
	cacheMu.Unlock()
	if oldestPresent {
		t.Fatal("earliest-expiring entry was not the eviction victim")
	}
	if got, ok := cacheGet("fresh.example"); !ok || got != fresh {
		t.Fatal("newest entry missing after earliest-expiry eviction")
	}
}

// TestDiscoveryCacheHitMissSemanticsUnchanged pins the hit/miss contract for
// legitimate traffic: miss when absent, hit only while unexpired, hits never
// slide the TTL, and re-discovery refreshes both TTL and config.
func TestDiscoveryCacheHitMissSemanticsUnchanged(t *testing.T) {
	advance := useFakeNow(t, testBase)

	if got, ok := cacheGet("absent.example"); ok || got != nil {
		t.Fatalf("expected miss for absent key, got ok=%v config=%v", ok, got)
	}

	v1 := &ServerConfig{URL: "https://mail1.company.com", LoginField: "email"}
	v2 := &ServerConfig{URL: "https://mail2.company.com", LoginField: "username"}
	cachePut("company.com", v1)

	if got, ok := cacheGet("company.com"); !ok || got != v1 {
		t.Fatalf("expected hit returning cached config, got ok=%v", ok)
	}

	// Hits must not extend the TTL: written at t0, the entry dies at
	// t0+TTL even though it was read at t0+4m.
	advance(4 * time.Minute)
	if _, ok := cacheGet("company.com"); !ok {
		t.Fatal("expected hit at t0+4m")
	}
	advance(1*time.Minute + time.Second)
	if _, ok := cacheGet("company.com"); ok {
		t.Fatal("hit slid the TTL; expiry must stay fixed at write time")
	}

	// A re-put (fresh discovery) refreshes the TTL and replaces the config.
	cachePut("company.com", v2)
	if got, ok := cacheGet("company.com"); !ok || got != v2 {
		t.Fatalf("expected refreshed hit with replaced config, got ok=%v", ok)
	}
	advance(4 * time.Minute)
	if _, ok := cacheGet("company.com"); !ok {
		t.Fatal("expected hit within refreshed TTL")
	}
	advance(1*time.Minute + time.Second)
	if _, ok := cacheGet("company.com"); ok {
		t.Fatal("expected miss past refreshed TTL")
	}
}

// TestDiscoveryCacheConcurrentAccess exercises mixed concurrent readers and
// writers on shared and distinct keys while the map sits at its cap; run under
// -race to prove the cache is safe for cross-request sharing.
func TestDiscoveryCacheConcurrentAccess(t *testing.T) {
	resetCache(t)
	t.Cleanup(func() { resetCache(t) })

	const workers = 8
	const ops = 1500
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < ops; i++ {
				shared := fmt.Sprintf("shared.%d.wild.example", i%16)
				unique := fmt.Sprintf("w%d-%d.flood.example", w, i)
				cfg := &ServerConfig{URL: "https://" + unique}
				if i%3 == 0 {
					cachePut(shared, cfg)
				} else {
					cacheGet(shared)
				}
				cachePut(unique, cfg)
				cacheGet(unique)
			}
		}(w)
	}
	wg.Wait()

	if n := cacheSize(); n > maxDiscoveryCacheEntries {
		t.Fatalf("cache size %d exceeds cap %d under concurrent flood", n, maxDiscoveryCacheEntries)
	}
}
