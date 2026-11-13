# Benchmarks

Run all: `go test -bench=. -benchmem ./...`

## Baselines — Apple M4, Go 1.26.3

| Benchmark | ops | ns/op | B/op | allocs/op | Hot Path |
|-----------|-----|-------|------|-----------|----------|
| `BenchmarkHashPassword` (bcrypt cost=10) | 26 | 45,885,521 | 5,265 | 10 | Every login |
| `BenchmarkBuildSearchClause` | 3,279,211 | 351 | 616 | 15 | Every IMAP SEARCH |
| `BenchmarkHashSlug` (SHA-256 cache key) | 13,126,822 | 91 | 72 | 3 | Every auth cache check |
| `BenchmarkAuthCacheHit` (sync.Map load) | 159,454,372 | 7 | 0 | 0 | Every repeat auth |

## How to Run

```bash
# All benchmarks
go test -bench=. -benchmem ./...

# Specific package
go test -bench=. -benchmem ./internal/auth/

# Compare against saved baseline
go test -bench=. -benchmem -count=10 ./... | tee baseline.txt
benchstat baseline.txt
```

## What Each Benchmark Covers

| Benchmark | Source File | Measures |
|-----------|------------|----------|
| `BenchmarkHashPassword` | `gateway/internal/auth/bcrypt_test.go` | bcrypt hashing at DefaultCost (10). CPU-bound. Regression here means config change or bcrypt library upgrade |
| `BenchmarkBuildSearchClause` | `gateway/internal/imap/imap_test.go` | IMAP SEARCH command parser. String concatenation + parameter building. Regression here means SEARCH logic got slower or more alloc-heavy |
| `BenchmarkHashSlug` | `shared/pwhash/pwhash_test.go` | SHA-256 hash of email+password for cache key. Runs per cache miss |
| `BenchmarkAuthCacheHit` | `shared/pwhash/pwhash_test.go` | sync.Map.Load on pre-populated auth cache. Runs per successful repeat login. Should stay < 10 ns/op |

## Future Benchmarks (E2E Test Infra)

| Benchmark | Needs |
|-----------|-------|
| `BenchmarkStoreAndDeliver` | Real PostgreSQL + SeaweedFS + SMTP server. Implemented as `//go:build e2e` in `internal/smtp/inbound_test.go`. Tests full inbound delivery pipeline including DB INSERT, rule engine, quota enforcement, and notification dispatch |
| `BenchmarkIMAPFetch` | Real PostgreSQL with 1000+ seeded messages. Tests SELECT + FETCH command flow |
| `BenchmarkLoginHandler` | Real PostgreSQL with `httptest.NewServer` — full HTTP handler through middleware stack |
