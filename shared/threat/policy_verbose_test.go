package threat

import (
	"math/rand"
	"testing"
	"time"
)

func TestMatchAllVerboseNamesFirstFailure(t *testing.T) {
	ctx := PolicyEvalContext{Country: "US", ClientType: "web", RequestTime: time.Now()}
	cond := map[string]interface{}{"country_in": []interface{}{"RU"}, "client_type": "imap"}
	ok, first := matchAllVerbose(cond, ctx, "unknown", "low", "low", "windows", nil)
	if ok {
		t.Fatal("expected non-match")
	}
	if first == "" {
		t.Fatal("expected a named first-failed condition")
	}
}

// Golden equality: matchAllVerbose's ok must equal matchAll over random inputs.
func TestMatchAllVerboseEqualsMatchAll(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	keys := []string{"country_in", "client_type", "device_platform", "device_trust", "geo_risk_tier"}
	for i := 0; i < 500; i++ {
		cond := map[string]interface{}{}
		for _, k := range keys {
			if rng.Intn(2) == 0 {
				continue
			}
			switch k {
			case "country_in":
				cond[k] = []interface{}{[]string{"US", "RU", "KP"}[rng.Intn(3)]}
			default:
				cond[k] = []string{"imap", "web", "ios", "managed", "high"}[rng.Intn(5)]
			}
		}
		ctx := PolicyEvalContext{Country: []string{"US", "RU"}[rng.Intn(2)], ClientType: []string{"imap", "web"}[rng.Intn(2)], RequestTime: time.Now()}
		platform := []string{"ios", "windows"}[rng.Intn(2)]
		want := matchAll(cond, ctx, "managed", "low", "low", platform, nil)
		got, _ := matchAllVerbose(cond, ctx, "managed", "low", "low", platform, nil)
		if got != want {
			t.Fatalf("divergence at cond=%v ctx=%+v: verbose=%v boolean=%v", cond, ctx, got, want)
		}
	}
}
