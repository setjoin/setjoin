package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/shared/testsupport"
)

func TestAllowedConfigKeys(t *testing.T) {
	tests := []string{
		"identity_source",
		"deleted_items_purge_days",
		"password_min_length",
		"mfa_enforcement_mode",
		"apps_caps_strict",
	}

	for _, key := range tests {
		if !allowedConfigKeys[key] {
			t.Errorf("expected %q to be in allowedConfigKeys", key)
		}
	}
}

func TestDisallowedConfigKey(t *testing.T) {
	if allowedConfigKeys["malicious_key"] {
		t.Error("unknown keys should not be allowed")
	}
}

// TestBooleanConfigValueValidation covers validConfigValue for the boolean
// config keys (TYPES-002): the admin API must admit the boolean-ish literals
// the consumers parse and reject everything else so a never-activating value
// cannot be persisted.
func TestBooleanConfigValueValidation(t *testing.T) {
	raw := func(v string) json.RawMessage { return json.RawMessage(v) }

	// Allowed: string literals (any case the readers' lower() folds) and real
	// JSON booleans.
	if !booleanConfigKeys["apps_caps_strict"] {
		t.Fatal("expected apps_caps_strict in booleanConfigKeys")
	}
	for _, v := range []string{`"1"`, `"true"`, `"TRUE"`, `"True"`, `"0"`, `"false"`, `"FALSE"`, `true`, `false`} {
		if !validConfigValue("apps_caps_strict", raw(v)) {
			t.Errorf("apps_caps_strict: expected %s to be accepted", v)
		}
	}
	// Rejected: non-boolean strings, numbers, and structured values.
	for _, v := range []string{`"yes"`, `"on"`, `"2"`, `""`, `1`, `0`, `null`, `["true"]`, `{"v":true}`} {
		if validConfigValue("apps_caps_strict", raw(v)) {
			t.Errorf("apps_caps_strict: expected %s to be rejected", v)
		}
	}
	// Unconstrained keys keep the historical any-value behavior.
	for _, v := range []string{`"30"`, `7`, `"true"`, `null`} {
		if !validConfigValue("deleted_items_purge_days", raw(v)) {
			t.Errorf("deleted_items_purge_days: expected %s to be accepted (unvalidated key)", v)
		}
	}
}

// TestConfigSetAppsCapsStrict exercises the admin API write path for the
// TYPES-002 activation toggle: a boolean-ish value is accepted and persisted,
// a non-boolean value is rejected 400, and an unknown key stays 403.
// DB-backed; skips without DB_DSN.
func TestConfigSetAppsCapsStrict(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewConfigHandler(pool, nil)
	ctx := context.Background()

	const setKey = "apps_caps_strict"
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM system_config WHERE key = $1`, setKey)
	})

	set := func(key, rawValue string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/admin/system/config/"+key,
			bytes.NewBufferString(`{"value":`+rawValue+`,"encrypted":false}`))
		req.SetPathValue("key", key)
		req = req.WithContext(ctxWithAdminUser(1, "admin@example.com"))
		w := httptest.NewRecorder()
		h.Set(w, req)
		return w
	}

	// Allowed: 'true' writes through (204) and lands as the scalar text the
	// JMAP session-doc lookup parses.
	if w := set(setKey, `"true"`); w.Code != http.StatusNoContent {
		t.Fatalf("Set(apps_caps_strict='true'): expected 204, got %d — %s", w.Code, w.Body.String())
	}
	var stored string
	if err := pool.QueryRow(ctx,
		`SELECT value #>> '{}' FROM system_config WHERE key = $1`, setKey).Scan(&stored); err != nil {
		t.Fatalf("read back apps_caps_strict: %v", err)
	}
	if stored != "true" {
		t.Errorf("expected stored scalar 'true', got %q", stored)
	}

	// Rejected: a value the consumer could never activate.
	if w := set(setKey, `"yes"`); w.Code != http.StatusBadRequest {
		t.Errorf("Set(apps_caps_strict='yes'): expected 400, got %d — %s", w.Code, w.Body.String())
	}

	// Unknown keys remain forbidden.
	if w := set("malicious_key", `"true"`); w.Code != http.StatusForbidden {
		t.Errorf("Set(malicious_key): expected 403, got %d — %s", w.Code, w.Body.String())
	}
}

// TestConfigReadRedactsEncrypted verifies that both List and Get redact the
// ciphertext of an encrypted system_config row (returning the [ENCRYPTED]
// sentinel) while passing through a non-encrypted row's plaintext value.
// DB-backed; skips without DB_DSN.
func TestConfigReadRedactsEncrypted(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewConfigHandler(pool, nil)
	ctx := context.Background()

	const (
		encKey    = "test_redact_enc_secret"
		plainKey  = "test_redact_plain_value"
		secretTxt = "super-secret-ciphertext"
		plainTxt  = "visible-plaintext"
	)

	// Seed: one encrypted row (ciphertext must never leak), one plain row.
	encVal, _ := json.Marshal(secretTxt)
	plainVal, _ := json.Marshal(plainTxt)
	t.Cleanup(func() {
		pool.Exec(context.Background(),
			`DELETE FROM system_config WHERE key = ANY($1)`,
			[]string{encKey, plainKey})
	})
	if _, err := pool.Exec(ctx,
		`INSERT INTO system_config (key, value, encrypted) VALUES ($1,$2,true),($3,$4,false)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, encrypted = EXCLUDED.encrypted`,
		encKey, encVal, plainKey, plainVal); err != nil {
		t.Fatalf("seed system_config: %v", err)
	}

	// ---- Get on the encrypted key: must redact ------------------------------
	reqGet := httptest.NewRequest(http.MethodGet, "/admin/system/config/"+encKey, nil)
	reqGet.SetPathValue("key", encKey)
	reqGet = reqGet.WithContext(ctxWithAdminUser(1, "admin@example.com"))
	wGet := httptest.NewRecorder()
	h.Get(wGet, reqGet)
	if wGet.Code != http.StatusOK {
		t.Fatalf("Get(enc): expected 200, got %d — %s", wGet.Code, wGet.Body.String())
	}
	var got struct {
		Value     any  `json:"value"`
		Encrypted bool `json:"encrypted"`
	}
	if err := json.Unmarshal(wGet.Body.Bytes(), &got); err != nil {
		t.Fatalf("Get(enc): decode: %v", err)
	}
	if got.Value != redactedConfigValue {
		t.Errorf("Get(enc): expected value %q, got %v", redactedConfigValue, got.Value)
	}
	if !got.Encrypted {
		t.Error("Get(enc): expected encrypted=true in response")
	}
	if got.Value == secretTxt {
		t.Fatal("Get(enc): LEAKED ciphertext over read API")
	}

	// ---- Get on the plain key: must pass through ----------------------------
	reqGetP := httptest.NewRequest(http.MethodGet, "/admin/system/config/"+plainKey, nil)
	reqGetP.SetPathValue("key", plainKey)
	reqGetP = reqGetP.WithContext(ctxWithAdminUser(1, "admin@example.com"))
	wGetP := httptest.NewRecorder()
	h.Get(wGetP, reqGetP)
	if wGetP.Code != http.StatusOK {
		t.Fatalf("Get(plain): expected 200, got %d — %s", wGetP.Code, wGetP.Body.String())
	}
	var gotP struct {
		Value     any  `json:"value"`
		Encrypted bool `json:"encrypted"`
	}
	if err := json.Unmarshal(wGetP.Body.Bytes(), &gotP); err != nil {
		t.Fatalf("Get(plain): decode: %v", err)
	}
	if gotP.Value != plainTxt {
		t.Errorf("Get(plain): expected value %q, got %v", plainTxt, gotP.Value)
	}
	if gotP.Encrypted {
		t.Error("Get(plain): expected encrypted=false")
	}

	// ---- List (prefix-filtered): redact enc, pass through plain -------------
	reqList := httptest.NewRequest(http.MethodGet, "/admin/system/config?prefix=test_redact_", nil)
	reqList = reqList.WithContext(ctxWithAdminUser(1, "admin@example.com"))
	wList := httptest.NewRecorder()
	h.List(wList, reqList)
	if wList.Code != http.StatusOK {
		t.Fatalf("List: expected 200, got %d — %s", wList.Code, wList.Body.String())
	}
	var rows []struct {
		Key       string `json:"key"`
		Value     any    `json:"value"`
		Encrypted bool   `json:"encrypted"`
	}
	if err := json.Unmarshal(wList.Body.Bytes(), &rows); err != nil {
		t.Fatalf("List: decode: %v", err)
	}
	var sawEnc, sawPlain bool
	for _, row := range rows {
		switch row.Key {
		case encKey:
			sawEnc = true
			if row.Value != redactedConfigValue {
				t.Errorf("List(enc): expected %q, got %v", redactedConfigValue, row.Value)
			}
			if row.Value == secretTxt {
				t.Fatal("List(enc): LEAKED ciphertext over read API")
			}
			if !row.Encrypted {
				t.Error("List(enc): expected encrypted=true")
			}
		case plainKey:
			sawPlain = true
			if row.Value != plainTxt {
				t.Errorf("List(plain): expected %q, got %v", plainTxt, row.Value)
			}
		}
	}
	if !sawEnc || !sawPlain {
		t.Fatalf("List: missing seeded rows (sawEnc=%v sawPlain=%v)", sawEnc, sawPlain)
	}
}
