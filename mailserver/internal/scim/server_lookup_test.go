package scim

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/pwhash"
)

// Coverage for the med-shard3-015 resource controls on the SCIM surface:
//
//   1. the per-IP rate limiter engages on SCIM routes BEFORE token verification
//      (authenticateToken used to be an unauthenticated CPU amplifier);
//   2. bearer-token verification resolves one candidate row through the V238
//      token_lookup_hash index and runs exactly ONE bcrypt compare — modern
//      tokens are never re-scanned, unknown tokens scan nothing when no legacy
//      (lookup-hash-less) tokens exist;
//   3. legacy pre-V238 tokens still verify through the bounded scan;
//   4. oversized request bodies are rejected at the 1 MiB cap before decode.

// stubBcryptCompare counts credential-seam comparisons and delegates to the
// real (pwhash-backed) one. Restored via t.Cleanup.
func stubBcryptCompare(t *testing.T) *int {
	t.Helper()
	calls := 0
	orig := bcryptCompare
	bcryptCompare = func(hash, secret string) error {
		calls++
		return pwhash.VerifyCredentialHash(hash, secret)
	}
	t.Cleanup(func() { bcryptCompare = orig })
	return &calls
}

// scimLookupTokenFixture seeds an active SCIM identity source plus one token,
// cleaning up in dependency order (tokens first, then the source).
type scimLookupTokenFixture struct {
	sourceID   int64
	generation int64
	tokenID    int64
	rawToken   string
	lookupHash string
}

func seedLookupToken(t *testing.T, suffix string, withLookupHash bool) scimLookupTokenFixture {
	t.Helper()
	pool := scimTestPool(t)
	ctx := context.Background()

	rawToken := "scim-lookup-" + suffix
	hash, err := bcrypt.GenerateFromPassword([]byte(rawToken), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash SCIM token: %v", err)
	}
	sum := sha256.Sum256([]byte(rawToken))
	lookupHash := hex.EncodeToString(sum[:])

	var sourceID, generation int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO identity_sources(source_key,display_name,kind,capabilities,state)
		VALUES($1,$2,'scim','{"provision_lifecycle":true,"stable_immutable_subject":true}'::jsonb,'active')
		RETURNING id,generation`,
		"scim:lookup-"+suffix, "SCIM lookup "+suffix,
	).Scan(&sourceID, &generation); err != nil {
		t.Fatalf("create SCIM source: %v", err)
	}
	var tokenID int64
	if withLookupHash {
		if err := pool.QueryRow(ctx, `
			INSERT INTO scim_tokens(name,token_hash,token_lookup_hash,deletion_policy,attribute_mapping,source_id)
			VALUES($1,$2,$3,'soft','{"department":"department"}'::jsonb,$4)
			RETURNING id`,
			"SCIM lookup "+suffix, string(hash), lookupHash, sourceID,
		).Scan(&tokenID); err != nil {
			t.Fatalf("create indexed SCIM token: %v", err)
		}
	} else {
		// Legacy pre-V238 shape: no lookup hash, verifiable only via the scan.
		if err := pool.QueryRow(ctx, `
			INSERT INTO scim_tokens(name,token_hash,deletion_policy,attribute_mapping,source_id)
			VALUES($1,$2,'soft','{"department":"department"}'::jsonb,$3)
			RETURNING id`,
			"SCIM lookup "+suffix, string(hash), sourceID,
		).Scan(&tokenID); err != nil {
			t.Fatalf("create legacy SCIM token: %v", err)
		}
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM scim_tokens WHERE id=$1`, tokenID)
		_, _ = pool.Exec(c, `DELETE FROM identity_sources WHERE id=$1`, sourceID)
	})

	return scimLookupTokenFixture{
		sourceID: sourceID, generation: generation, tokenID: tokenID,
		rawToken: rawToken, lookupHash: lookupHash,
	}
}

func authenticatedRequest(t *testing.T, s *Server, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	s.Authenticate(next).ServeHTTP(rec, req)
	return rec
}

// countLegacyActiveTokens reports how many active tokens still lack a lookup
// hash — exactly the set scim_list_active_tokens() offers to the bcrypt-scan
// fallback. Residual rows from other tests' fixtures are part of that set, so
// assertions are written as deltas against it rather than absolute counts.
func countLegacyActiveTokens(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*) FROM scim_tokens st
		JOIN identity_sources src ON src.id=st.source_id
		WHERE st.revoked_at IS NULL
		  AND st.token_lookup_hash IS NULL
		  AND src.kind='scim' AND src.state='active'
		  AND (st.expires_at IS NULL OR st.expires_at > now())`,
	).Scan(&n); err != nil {
		t.Fatalf("count legacy active tokens: %v", err)
	}
	return n
}

// TestAuthenticateIndexedTokenLookupRunsOneBcryptCompare proves the V238 fast
// path: an indexed hit costs exactly ONE bcrypt compare no matter how many
// other tokens (modern OR residual legacy) exist — the scan never runs — and
// an unknown token costs exactly one compare per legacy token, i.e. the
// indexed (modern) tokens are never scanned.
func TestAuthenticateIndexedTokenLookupRunsOneBcryptCompare(t *testing.T) {
	pool := scimTestPool(t)
	calls := stubBcryptCompare(t)
	legacyBefore := countLegacyActiveTokens(t, pool)

	primary := seedLookupToken(t, scimRandomSuffix(t), true)
	// Additional modern tokens must never enter any scan.
	for i := 0; i < 3; i++ {
		seedLookupToken(t, scimRandomSuffix(t), true)
	}

	s := NewServer(pool, pgxutil.WorkerPool{Pool: pool}, scimTestLogger(), "", "")

	rec := authenticatedRequest(t, s, primary.rawToken)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("indexed-token auth status=%d body=%s", rec.Code, rec.Body.String())
	}
	if *calls != 1 {
		t.Fatalf("bcrypt compares for indexed hit=%d, want exactly 1 (indexed lookup, not a scan — even with %d legacy tokens present)", *calls, legacyBefore)
	}

	// Unknown token: indexed lookup misses; the fallback scans exactly the
	// legacy set — one compare per legacy token, zero for the modern ones.
	rec = authenticatedRequest(t, s, "scim-never-minted-"+scimRandomSuffix(t))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unknown-token auth status=%d, want 401", rec.Code)
	}
	if *calls != 1+legacyBefore {
		t.Fatalf("bcrypt compares after unknown token=%d, want 1+%d (scan covers only legacy rows)", *calls, legacyBefore)
	}
}

// TestAuthenticateIndexedTokenBindsSourceMetadata keeps the metadata-binding
// contract on the new path (symmetric with the legacy-path test in
// server_auth_test.go).
func TestAuthenticateIndexedTokenBindsSourceMetadata(t *testing.T) {
	pool := scimTestPool(t)
	fix := seedLookupToken(t, scimRandomSuffix(t), true)

	s := NewServer(pool, pgxutil.WorkerPool{Pool: pool}, scimTestLogger(), "", "")
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Context().Value(ctxTokenID) != fix.tokenID ||
			r.Context().Value(ctxSourceID) != fix.sourceID ||
			r.Context().Value(ctxSourceGeneration) != fix.generation {
			t.Fatalf("indexed-path auth did not bind token/source metadata")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	req.Header.Set("Authorization", "Bearer "+fix.rawToken)
	rec := httptest.NewRecorder()
	s.Authenticate(next).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("indexed-token metadata auth status=%d body=%s", rec.Code, rec.Body.String())
	}
}

// TestAuthenticateLegacyTokenScanIsBoundedToLegacyRows proves the rotation
// story: a pre-V238 token (no lookup hash) still authenticates via the scan,
// and the scan set is exactly the legacy set — no active indexed token is ever
// surfaced to it (asserted at the SQL boundary, which is hermetic against
// residual fixture rows in the shared test database).
func TestAuthenticateLegacyTokenScanIsBoundedToLegacyRows(t *testing.T) {
	pool := scimTestPool(t)
	stubBcryptCompare(t)

	legacy := seedLookupToken(t, scimRandomSuffix(t), false)
	indexed := make([]scimLookupTokenFixture, 0, 3)
	for i := 0; i < 3; i++ {
		indexed = append(indexed, seedLookupToken(t, scimRandomSuffix(t), true))
	}

	s := NewServer(pool, pgxutil.WorkerPool{Pool: pool}, scimTestLogger(), "", "")

	rec := authenticatedRequest(t, s, legacy.rawToken)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("legacy-token auth status=%d body=%s", rec.Code, rec.Body.String())
	}

	// SQL-boundary proof: every row the scan offers is lookup-hash-less, and
	// the active indexed tokens seeded next to it are absent from it.
	var legacyRows, indexedInScan int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*), count(*) FILTER (WHERE st.token_lookup_hash IS NOT NULL)
		  FROM scim_list_active_tokens() la
		  JOIN scim_tokens st ON st.id = la.token_id`,
	).Scan(&legacyRows, &indexedInScan); err != nil {
		t.Fatalf("inspect scan set: %v", err)
	}
	if indexedInScan != 0 {
		t.Fatalf("scan set contains %d indexed tokens, want 0 (bounded to legacy rows)", indexedInScan)
	}
	if legacyRows == 0 {
		t.Fatal("scan set is empty, want at least the seeded legacy token")
	}
	var present bool
	if err := pool.QueryRow(context.Background(), `
		SELECT EXISTS (SELECT 1 FROM scim_list_active_tokens() la WHERE la.token_id = $1)`,
		legacy.tokenID,
	).Scan(&present); err != nil {
		t.Fatalf("check legacy token in scan set: %v", err)
	}
	if !present {
		t.Fatal("seeded legacy token is not offered to the scan fallback")
	}
	for _, fix := range indexed {
		var inScan bool
		if err := pool.QueryRow(context.Background(), `
			SELECT EXISTS (SELECT 1 FROM scim_list_active_tokens() la WHERE la.token_id = $1)`,
			fix.tokenID,
		).Scan(&inScan); err != nil {
			t.Fatalf("check indexed token in scan set: %v", err)
		}
		if inScan {
			t.Fatalf("indexed token %d leaked into the legacy scan set", fix.tokenID)
		}
	}
}

// TestSCIMRoutesRateLimitBeforeAuthentication wires the real route table and
// proves the per-IP limiter engages on SCIM routes ahead of token
// verification: the first requests reach auth (401 for a missing bearer), and
// once the budget is spent the route answers 429 without running auth.
func TestSCIMRoutesRateLimitBeforeAuthentication(t *testing.T) {
	s := &Server{}
	s.SetRateLimiter(middleware.NewRateLimiter(2, time.Minute))

	mux := http.NewServeMux()
	s.registerRoutes(mux)

	codes := make([]int, 0, 3)
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		codes = append(codes, rec.Code)
	}
	if codes[0] != http.StatusUnauthorized || codes[1] != http.StatusUnauthorized {
		t.Fatalf("first in-budget requests must reach auth (401), got %v", codes)
	}
	if codes[2] != http.StatusTooManyRequests {
		t.Fatalf("third request over budget=%d, want 429", codes[2])
	}
	over := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	overRec := httptest.NewRecorder()
	mux.ServeHTTP(overRec, over)
	if !strings.Contains(overRec.Body.String(), "rate limit exceeded") {
		t.Fatalf("429 body=%q, want rate-limit problem detail", overRec.Body.String())
	}

	// Every SCIM route is wrapped: ServiceProviderConfig (the Okta validation
	// endpoint) rate-limits too.
	mux2 := http.NewServeMux()
	s.registerRoutes(mux2)
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/scim/v2/ServiceProviderConfig", nil)
		mux2.ServeHTTP(httptest.NewRecorder(), req)
	}
	req := httptest.NewRequest(http.MethodGet, "/scim/v2/ServiceProviderConfig", nil)
	rec := httptest.NewRecorder()
	mux2.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("ServiceProviderConfig over budget=%d, want 429", rec.Code)
	}
}

// TestSCIMDecodeRejectsOversizedBody proves the 1 MiB MaxBytesReader cap
// rejects attacker-sized bodies before any decode keeps their bytes: 413 at
// the cap, while normal-size bodies still decode.
func TestSCIMDecodeRejectsOversizedBody(t *testing.T) {
	s := &Server{} // decode rejects before any pool access

	oversized := `{"userName":"` + strings.Repeat("a", maxBodyBytes) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", strings.NewReader(oversized))
	rec := httptest.NewRecorder()
	s.CreateUser(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized create body status=%d, want 413", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "1 MiB") {
		t.Fatalf("413 body=%q, want the SCIM body-cap detail", rec.Body.String())
	}

	// PATCH bodies are capped through the same helper (PatchOperation.Value is
	// not retained wholesale for oversize payloads).
	oversizedPatch := `{"Operations":[{"op":"replace","path":"displayName","value":"` +
		strings.Repeat("a", maxBodyBytes) + `"}]}`
	req = httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/1", strings.NewReader(oversizedPatch))
	req.SetPathValue("id", "1")
	rec = httptest.NewRecorder()
	s.PatchUser(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized patch body status=%d, want 413", rec.Code)
	}

	// Normal-size bodies still decode (empty userName fails AFTER the decode,
	// with the field-level 400 — never the cap error).
	req = httptest.NewRequest(http.MethodPost, "/scim/v2/Users", strings.NewReader(`{"userName":""}`))
	rec = httptest.NewRecorder()
	s.CreateUser(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "userName is required") {
		t.Fatalf("normal-size body status=%d body=%s, want field-level 400 past the cap", rec.Code, rec.Body.String())
	}
}
