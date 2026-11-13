package federation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/cryptokey"
)

// testMasterKey is the raw deployment master secret used across the OIDC
// client-secret at-rest tests. Per the cryptokey contract it is passed RAW:
// EncryptColumn/DecryptColumn derive the column key internally.
var testMasterKey = []byte("oidc-rp-at-rest-test-master-secret")

func TestOIDCClientSecretRoundTripBothProfiles(t *testing.T) {
	t.Parallel()
	const secret = "idp-client-secret- Value!\x2f+"
	for _, profile := range []cryptokey.CryptoProfile{cryptokey.ProfileStandard, cryptokey.ProfileSMx} {
		t.Run(string(profile), func(t *testing.T) {
			sealed, err := SealOIDCClientSecret(secret, testMasterKey, profile)
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
			if sealed == secret || strings.Contains(sealed, secret) {
				t.Fatal("sealed value must not contain the plaintext secret")
			}
			envelope, err := base64.RawURLEncoding.DecodeString(sealed)
			if err != nil {
				t.Fatalf("sealed value is not base64: %v", err)
			}
			// The stored value must be algorithm-tagged cryptokey ciphertext —
			// not merely a flag beside plaintext.
			magic := cryptokey.EnvelopeMagic
			if len(envelope) < len(magic)+1 || string(envelope[:len(magic)]) != string(magic) {
				t.Fatalf("sealed value lacks %s envelope magic", magic)
			}
			if gotAlgo := cryptokey.AlgorithmTag(envelope[len(magic)]); gotAlgo != cryptokey.AlgorithmTagFromProfile(profile) {
				t.Fatalf("algorithm tag = %v, want the active profile's %v",
					gotAlgo, cryptokey.AlgorithmTagFromProfile(profile))
			}

			opened, err := OpenOIDCClientSecret(sealed, testMasterKey)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if opened != secret {
				t.Fatalf("round trip mismatch: got %q want %q", opened, secret)
			}

			wrongKey := append([]byte(nil), testMasterKey...)
			wrongKey[0] ^= 0xff
			if _, err := OpenOIDCClientSecret(sealed, wrongKey); err == nil {
				t.Fatal("opening under the wrong key must fail closed")
			}
		})
	}
}

func TestOIDCClientSecretFailClosedOnNonCiphertext(t *testing.T) {
	t.Parallel()
	for name, stored := range map[string]string{
		"plaintext":          "plain-secret",
		"base64-plaintext":   base64.StdEncoding.EncodeToString([]byte("plain-secret")),
		"truncated-envelope": string(cryptokey.EnvelopeMagic),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := OpenOIDCClientSecret(stored, testMasterKey); err == nil {
				t.Fatal("non-sealed secret must fail closed")
			}
		})
	}
	if got, err := OpenOIDCClientSecret("", testMasterKey); err != nil || got != "" {
		t.Fatalf("empty stored secret = (%q, %v), want pass-through", got, err)
	}
	if _, err := OpenOIDCClientSecret("plain-secret", nil); err == nil {
		t.Fatal("secret with no configured master key must fail closed")
	}
	if _, err := SealOIDCClientSecret("", testMasterKey, cryptokey.ProfileStandard); err == nil {
		t.Fatal("sealing an empty secret must be rejected")
	}
	if _, err := SealOIDCClientSecret("s", nil, cryptokey.ProfileStandard); err == nil {
		t.Fatal("sealing without a master key must be rejected")
	}
}

func newOIDCSecretTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set")
	}
	pool, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func insertOIDCConfig(t *testing.T, pool *pgxpool.Pool, key, value string, encrypted bool) {
	t.Helper()
	if _, err := pool.Exec(t.Context(),
		`INSERT INTO system_config (key, value, encrypted) VALUES ($1, $2, $3)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, encrypted = EXCLUDED.encrypted`,
		key, value, encrypted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM system_config WHERE key = $1`, key)
	})
}

func fetchOIDCConfig(t *testing.T, pool *pgxpool.Pool, key string) (json.RawMessage, bool) {
	t.Helper()
	var raw json.RawMessage
	var encrypted bool
	if err := pool.QueryRow(t.Context(),
		`SELECT value, encrypted FROM system_config WHERE key = $1`, key).Scan(&raw, &encrypted); err != nil {
		t.Fatalf("fetch %q: %v", key, err)
	}
	_ = encrypted
	return raw, encrypted
}

// TestOIDCLoaderFailsClosedOnPlaintextSecret proves a row whose client_secret
// is not cryptokey-sealed ciphertext is never admitted — the `encrypted`
// column flag alone is insufficient — so no plaintext secret reaches the RP
// client.
func TestOIDCLoaderFailsClosedOnPlaintextSecret(t *testing.T) {
	pool := newOIDCSecretTestPool(t)

	for _, tc := range []struct {
		label     string
		encrypted bool
		authority bool // true: construct with master key, false: no key configured
	}{
		{"flagged-encrypted", true, true},
		{"unflagged-plaintext", false, true},
		{"no-master-key", true, false},
	} {
		t.Run(tc.label, func(t *testing.T) {
			name := "plaintext-" + uuid.NewString()
			key := "oidc_provider_" + name + "_config"
			insertOIDCConfig(t, pool, key, `{
				"name": "`+name+`", "enabled": true,
				"provider_url": "https://idp.invalid.example",
				"client_id": "client", "client_secret": "plain-secret",
				"redirect_url": "https://setjoin.example/callback"
			}`, tc.encrypted)

			authority := testMasterKey
			if !tc.authority {
				authority = nil
			}
			p, err := NewOIDCRPProvider(t.Context(), pool, authority)
			if err == nil {
				t.Fatal("plaintext client_secret must fail the load")
			}
			if !strings.Contains(err.Error(), "not cryptokey-sealed ciphertext") &&
				!strings.Contains(err.Error(), "no DB encryption master key") {
				t.Fatalf("fail-closed reason not surfaced: %v", err)
			}
			if p == nil || p.Provider(name) != nil {
				t.Fatalf("provider with plaintext secret was admitted: %#v", p)
			}
		})
	}
}

// TestOIDCLoaderAcceptsSealedSecret proves a properly sealed secret decrypts
// and flows into RP construction: with an unreachable (TEST-NET) issuer the
// load fails at OIDC discovery, never at the secret stage.
func TestOIDCLoaderAcceptsSealedSecret(t *testing.T) {
	pool := newOIDCSecretTestPool(t)

	name := "sealed-" + uuid.NewString()
	key := "oidc_provider_" + name + "_config"
	sealed, err := SealOIDCClientSecret("secret", testMasterKey, cryptokey.ProfileSMx)
	if err != nil {
		t.Fatal(err)
	}
	insertOIDCConfig(t, pool, key, `{
		"name": "`+name+`", "enabled": true,
		"provider_url": "https://192.0.2.1",
		"client_id": "client", "client_secret": "`+sealed+`",
		"redirect_url": "https://setjoin.example/callback"
	}`, true)

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	p, err := NewOIDCRPProvider(ctx, pool, testMasterKey)
	if err == nil {
		t.Fatal("unreachable OIDC discovery unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), "client secret") {
		t.Fatalf("sealed secret did not decrypt for RP construction: %v", err)
	}
	if !strings.Contains(err.Error(), "discovery") {
		t.Fatalf("expected discovery failure, got: %v", err)
	}
	if p == nil || p.Provider(name) != nil {
		t.Fatalf("failed discovery did not fail closed: %#v", p)
	}
}

// assertReSealedRow proves one system_config row now stores wantSecret as
// cryptokey-sealed ciphertext under the authoritative encrypted flag.
func assertReSealedRow(t *testing.T, pool *pgxpool.Pool, key, wantSecret string) {
	t.Helper()
	raw, encrypted := fetchOIDCConfig(t, pool, key)
	if !encrypted {
		t.Fatal("authoritative encrypted column was not set")
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		t.Fatalf("stored config is not a JSON object: %v", err)
	}
	var storedSecret string
	if err := json.Unmarshal(members["client_secret"], &storedSecret); err != nil {
		t.Fatalf("client_secret is not a JSON string: %v", err)
	}
	if storedSecret == wantSecret {
		t.Fatal("client_secret is still stored as plaintext")
	}
	opened, err := OpenOIDCClientSecret(storedSecret, testMasterKey)
	if err != nil {
		t.Fatalf("re-sealed secret does not open: %v", err)
	}
	if opened != wantSecret {
		t.Fatalf("re-sealed secret = %q, want the original value", opened)
	}
}

// TestResealOIDCProviderClientSecrets covers the one-time migration: plaintext
// rows are re-sealed under the active profile, sealed rows and empty secrets
// are untouched, the write replaces only the client_secret member, the
// authoritative encrypted column flips true, the migration is idempotent, and
// a wrong master key aborts without writing.
func TestResealOIDCProviderClientSecrets(t *testing.T) {
	pool := newOIDCSecretTestPool(t)

	const plaintextSecret = "legacy-plaintext-secret"
	// Large int64 proves members other than client_secret survive byte-for-byte
	// (no float64 round-trip corruption).
	const configFmt = `{
		"name": %q, "enabled": %s,
		"provider_url": "https://idp.invalid.example",
		"client_id": "client", "client_secret": %q,
		"redirect_url": "https://setjoin.example/callback",
		"group_mappings": [{"idp_group": "eng", "distribution_group_id": 9007199254740993}]
	}`

	plainKey := "oidc_provider_plain-" + uuid.NewString() + "_config"
	plainValue := fmt.Sprintf(configFmt, "plain", "true", plaintextSecret)
	insertOIDCConfig(t, pool, plainKey, plainValue, false)
	beforeRaw, _ := fetchOIDCConfig(t, pool, plainKey)

	disabledKey := "oidc_provider_disabled-" + uuid.NewString() + "_config"
	insertOIDCConfig(t, pool, disabledKey,
		fmt.Sprintf(configFmt, "disabled", "false", plaintextSecret), false)

	emptyKey := "oidc_provider_empty-" + uuid.NewString() + "_config"
	insertOIDCConfig(t, pool, emptyKey,
		fmt.Sprintf(configFmt, "empty", "true", ""), false)

	sealedKey := "oidc_provider_sealed-" + uuid.NewString() + "_config"
	sealedValue, err := SealOIDCClientSecret(plaintextSecret, testMasterKey, cryptokey.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	sealedRow := fmt.Sprintf(configFmt, "sealed", "true", sealedValue)
	insertOIDCConfig(t, pool, sealedKey, sealedRow, true)
	sealedBefore, _ := fetchOIDCConfig(t, pool, sealedKey)

	upgraded, err := ResealOIDCProviderClientSecrets(t.Context(), pool, testMasterKey, cryptokey.ProfileStandard)
	if err != nil {
		t.Fatalf("re-seal: %v", err)
	}
	if upgraded != 2 {
		t.Fatalf("upgraded = %d, want 2 (plain + disabled rows)", upgraded)
	}

	assertReSealedRow(t, pool, plainKey, plaintextSecret)
	assertReSealedRow(t, pool, disabledKey, plaintextSecret)

	// Every non-secret member is preserved byte-for-byte across the migration.
	var before, after map[string]json.RawMessage
	if err := json.Unmarshal(beforeRaw, &before); err != nil {
		t.Fatal(err)
	}
	plainRaw, _ := fetchOIDCConfig(t, pool, plainKey)
	if err := json.Unmarshal(plainRaw, &after); err != nil {
		t.Fatal(err)
	}
	for member, want := range before {
		if member == "client_secret" {
			continue
		}
		if string(after[member]) != string(want) {
			t.Fatalf("member %q was mutated by the re-seal: %s != %s", member, after[member], want)
		}
	}

	// Already-sealed and empty-secret rows are untouched.
	sealedAfter, _ := fetchOIDCConfig(t, pool, sealedKey)
	if string(sealedAfter) != string(sealedBefore) {
		t.Fatal("already-sealed row was modified by the migration")
	}
	emptyRaw, _ := fetchOIDCConfig(t, pool, emptyKey)
	if !strings.Contains(string(emptyRaw), `"client_secret": ""`) &&
		!strings.Contains(string(emptyRaw), `"client_secret":""`) {
		t.Fatalf("empty-secret row was modified: %s", emptyRaw)
	}

	// Idempotent: a second run finds nothing to upgrade.
	upgraded, err = ResealOIDCProviderClientSecrets(t.Context(), pool, testMasterKey, cryptokey.ProfileStandard)
	if err != nil {
		t.Fatalf("second re-seal: %v", err)
	}
	if upgraded != 0 {
		t.Fatalf("second re-seal upgraded %d rows, want 0", upgraded)
	}

	// Wrong key material: validation aborts before any write.
	wrongKey := append([]byte(nil), testMasterKey...)
	wrongKey[0] ^= 0xff
	beforeWrong, _ := fetchOIDCConfig(t, pool, plainKey)
	if _, err := ResealOIDCProviderClientSecrets(t.Context(), pool, wrongKey, cryptokey.ProfileStandard); err == nil {
		t.Fatal("re-seal under wrong key material must fail")
	}
	afterWrong, _ := fetchOIDCConfig(t, pool, plainKey)
	if string(afterWrong) != string(beforeWrong) {
		t.Fatal("failed re-seal validation mutated stored rows")
	}
}

// TestResealStartupGateIndependentOfOIDCServiceEnabled pins the authserverd
// startup contract (med-shard3-002 r2): the at-rest re-seal migration runs
// whether or not the OIDC RP service is activated, because the migration
// concerns stored credentials, not provider construction. With the service
// disabled the gate alone must upgrade plaintext rows (no relying-party
// provider is ever constructed); when the service is later enabled the
// unchanged loader must admit the gate's output and must still fail closed on
// any plaintext row that bypassed the gate.
func TestResealStartupGateIndependentOfOIDCServiceEnabled(t *testing.T) {
	pool := newOIDCSecretTestPool(t)

	const plaintextSecret = "legacy-secret-seeded-while-service-off"
	const configFmt = `{
		"name": %q, "enabled": true,
		"provider_url": "https://192.0.2.1",
		"client_id": "client", "client_secret": %q,
		"redirect_url": "https://setjoin.example/callback"
	}`

	offKey := "oidc_provider_off-" + uuid.NewString() + "_config"
	insertOIDCConfig(t, pool, offKey,
		fmt.Sprintf(configFmt, "off", plaintextSecret), false)

	// Startup with the OIDC RP service disabled: authserverd runs ONLY the
	// storage gate — cfg.OIDCEnabled is false, so NewOIDCRPProvider is never
	// constructed. The plaintext row must still be re-sealed.
	upgraded, err := ResealOIDCProviderClientSecrets(t.Context(), pool, testMasterKey, cryptokey.ProfileStandard)
	if err != nil {
		t.Fatalf("disabled-service startup re-seal: %v", err)
	}
	if upgraded != 1 {
		t.Fatalf("disabled-service startup upgraded %d rows, want 1", upgraded)
	}
	assertReSealedRow(t, pool, offKey, plaintextSecret)

	// Idempotent: the next disabled-service startup finds nothing to do.
	upgraded, err = ResealOIDCProviderClientSecrets(t.Context(), pool, testMasterKey, cryptokey.ProfileStandard)
	if err != nil {
		t.Fatalf("second disabled-service startup re-seal: %v", err)
	}
	if upgraded != 0 {
		t.Fatalf("second disabled-service startup upgraded %d rows, want 0", upgraded)
	}

	// Enabled path regression: the service is switched on at a later startup.
	// The unchanged loader reads the gate's output; with an unreachable
	// (TEST-NET) issuer the load fails at discovery — never at the secret
	// stage — proving the re-sealed value decrypts for RP construction.
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	p, err := NewOIDCRPProvider(ctx, pool, testMasterKey)
	if err == nil {
		t.Fatal("unreachable OIDC discovery unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), "client secret") {
		t.Fatalf("re-sealed secret did not decrypt for the enabled loader: %v", err)
	}
	if !strings.Contains(err.Error(), "discovery") {
		t.Fatalf("expected discovery failure, got: %v", err)
	}
	if p == nil || p.Provider("off") != nil {
		t.Fatalf("failed discovery did not fail closed: %#v", p)
	}

	// Loader fail-closed is unchanged: a plaintext row written after the gate
	// ran (bypassing it, e.g. seeded between restarts) is still refused — the
	// migration never loosened the at-rest contract.
	lateKey := "oidc_provider_late-" + uuid.NewString() + "_config"
	insertOIDCConfig(t, pool, lateKey,
		fmt.Sprintf(configFmt, "late", plaintextSecret), false)
	lateCtx, lateCancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer lateCancel()
	p, err = NewOIDCRPProvider(lateCtx, pool, testMasterKey)
	if err == nil {
		t.Fatal("plaintext row bypassing the gate must fail the load")
	}
	if !strings.Contains(err.Error(), "not cryptokey-sealed ciphertext") {
		t.Fatalf("fail-closed reason not surfaced: %v", err)
	}
	if p == nil || p.Provider("late") != nil {
		t.Fatalf("provider with plaintext secret was admitted: %#v", p)
	}
}
