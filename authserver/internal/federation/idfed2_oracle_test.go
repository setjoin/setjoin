//go:build gofree_record

package federation

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/cryptokey"
)

// This calls the frozen public startup seam; only synthetic owned fixture rows
// and the immutable observation artifact are written.
func TestRecordIDFED2SecretReseal(t *testing.T) {
	out := os.Getenv("IDFED2_SECRET_ORACLE")
	if out == "" {
		t.Fatal("IDFED2_SECRET_ORACLE required")
	}
	if _, e := os.Stat(out); e == nil {
		t.Fatal("refuse overwrite")
	}
	raw, e := os.ReadFile(os.Getenv("IDFED2_KEYS"))
	if e != nil {
		t.Fatal(e)
	}
	var keys map[string]json.RawMessage
	if e = json.Unmarshal(raw, &keys); e != nil {
		t.Fatal(e)
	}
	var secret string
	if e = json.Unmarshal(keys["secret"], &secret); e != nil {
		t.Fatal(e)
	}
	master := []byte(secret)
	ctx := context.Background()
	db, e := pgxpool.New(ctx, os.Getenv("TEST_DB_DSN"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	lock, e := db.Acquire(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Release()
	if _, e = lock.Exec(ctx, "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))"); e != nil {
		t.Fatal(e)
	}
	defer lock.Exec(ctx, "SELECT pg_advisory_unlock(hashtextextended('gofree-idlogin1-oracle',0))")
	fixtureKeys := []string{"oidc_provider_idfed2_secret_a_config", "oidc_provider_idfed2_secret_b_config", "oidc_provider_idfed2_secret_c_config"}
	cleanup := func() {
		if _, e := db.Exec(ctx, "DELETE FROM system_config WHERE key=ANY($1::text[])", fixtureKeys); e != nil {
			t.Fatal(e)
		}
	}
	cleanup()
	defer cleanup()
	seed := func(key string, value any, encrypted bool) {
		body, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = db.Exec(ctx, "INSERT INTO system_config(key,value,encrypted) VALUES($1,$2::jsonb,$3) ON CONFLICT(key) DO UPDATE SET value=excluded.value,encrypted=excluded.encrypted", key, body, encrypted); e != nil {
			t.Fatal(e)
		}
	}
	snapshot := func() ([]any, []any) {
		rows, e := db.Query(ctx, "SELECT key,value,encrypted FROM system_config WHERE key=ANY($1::text[]) ORDER BY key", fixtureKeys)
		if e != nil {
			t.Fatal(e)
		}
		defer rows.Close()
		norm := []any{}
		exact := []any{}
		for rows.Next() {
			var k string
			var b []byte
			var encrypted bool
			if e = rows.Scan(&k, &b, &encrypted); e != nil {
				t.Fatal(e)
			}
			var v map[string]any
			if e = json.Unmarshal(b, &v); e != nil {
				t.Fatal(e)
			}
			exact = append(exact, []any{k, string(b), encrypted})
			if s, ok := v["client_secret"].(string); ok {
				if envelope, ok := decodeOIDCSecretEnvelope(s); ok {
					opened, err := OpenOIDCClientSecret(s, master)
					var plain any
					if err == nil {
						plain = opened
					}
					var algorithm any
					if len(envelope) > 4 {
						algorithm = int(envelope[4])
					}
					v["client_secret"] = map[string]any{"envelope": true, "opened": plain, "algorithm": algorithm}
				}
			}
			norm = append(norm, map[string]any{"key": k, "value": v, "encrypted": encrypted})
		}
		if e = rows.Err(); e != nil {
			t.Fatal(e)
		}
		return norm, exact
	}
	cases := []any{}
	for _, kind := range []string{"plain", "repeat", "wrong-key", "bad-type", "smx"} {
		if kind != "repeat" {
			cleanup()
			seed(fixtureKeys[0], map[string]any{"name": "idfed2-secret", "enabled": false, "client_secret": "synthetic-rp-secret", "extra": map[string]any{"keep": true}}, false)
			seed(fixtureKeys[2], map[string]any{"client_secret": "", "enabled": false}, false)
		}
		if kind == "wrong-key" {
			sealed, e := SealOIDCClientSecret("wrong-key-secret", []byte("another synthetic master key 340"), cryptokey.ProfileStandard)
			if e != nil {
				t.Fatal(e)
			}
			seed(fixtureKeys[1], map[string]any{"client_secret": sealed}, true)
		}
		if kind == "bad-type" {
			seed(fixtureKeys[1], map[string]any{"client_secret": 42}, false)
		}
		before, exactBefore := snapshot()
		profile := cryptokey.ProfileStandard
		if kind == "smx" {
			profile = cryptokey.ProfileSMx
		}
		count, err := ResealOIDCProviderClientSecrets(ctx, db, master, profile)
		after, exactAfter := snapshot()
		cases = append(cases, map[string]any{"case": kind, "count": count, "error": err != nil, "unchanged": reflect.DeepEqual(exactBefore, exactAfter), "before": before, "after": after})
	}
	doc := map[string]any{"format": 1, "go_source": "61e9cff379b4087b970c7637ab8af5c4c252af67", "seam": "ResealOIDCProviderClientSecrets", "cases": cases}
	body, e := json.MarshalIndent(doc, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	body = append(body, '\n')
	if e = os.WriteFile(out, body, 0600); e != nil {
		t.Fatal(e)
	}
}
