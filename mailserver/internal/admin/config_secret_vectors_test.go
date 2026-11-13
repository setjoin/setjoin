package admin

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"setjoin.com/shared/cryptokey"
)

// Records frozen-Go EK01 config-secret vectors for the Rust codec (#379):
//
//	GOFREE_VECTOR_DIR=<empty dir> go test -count=1 -run TestRecordConfigSecretVectors ./internal/admin
//
// Keys, deployment IDs and nonces are public test fixtures. The recorder refuses
// to overwrite an existing file.
type secretVectorCase struct {
	Name   string `json:"name"`
	Input  any    `json:"input"`
	Output any    `json:"output"`
}

type secretKeyringInput struct {
	Deployment    string            `json:"deployment_id"`
	ActiveVersion uint32            `json:"active_version"`
	ActiveKey     string            `json:"active_key"`
	Profile       string            `json:"profile"`
	RetiringKeys  map[string]string `json:"retiring_keys"`
}

func (k secretKeyringInput) build() ConfigSecretKeyring {
	retiring := map[uint32][]byte{}
	for rawVersion, key := range k.RetiringKeys {
		var v uint32
		for _, c := range rawVersion {
			v = v*10 + uint32(c-'0')
		}
		retiring[v] = []byte(key)
	}
	return ConfigSecretKeyring{
		DeploymentID:  k.Deployment,
		ActiveVersion: k.ActiveVersion,
		ActiveKey:     []byte(k.ActiveKey),
		ActiveProfile: cryptokey.CryptoProfile(k.Profile),
		RetiringKeys:  retiring,
	}
}

func secretErrText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func writeSecretVectors(t *testing.T, cases []secretVectorCase) {
	t.Helper()
	dir := os.Getenv("GOFREE_VECTOR_DIR")
	if dir == "" {
		return
	}
	data, err := json.MarshalIndent(struct {
		Contract string `json:"contract"`
		Cases    any    `json:"cases"`
	}{"configsecret", cases}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(filepath.Join(dir, "configsecret.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

// sealFixed builds exactly what Encrypt stores, with a fixed nonce.
func sealFixed(t *testing.T, c *ConfigSecretCodec, configKey string, nonce, plaintext []byte) json.RawMessage {
	t.Helper()
	sourceKey := configSecretSourceKey(configKey)
	envelope, err := cryptokey.SealEnvelopeDeterministic(
		cryptokey.AlgorithmTagFromProfile(c.active.profile),
		cryptokey.DeriveDBEncryptionKey(c.active.key, c.active.profile),
		nonce, plaintext, c.aad(sourceKey, configKey, c.active.version))
	if err != nil {
		t.Fatal(err)
	}
	stored, err := json.Marshal(configSecretRecord{
		Format: configEnvelopeKind, Version: configSecretVersion, KeyVersion: c.active.version,
		SourceKey: sourceKey, Ciphertext: base64.RawURLEncoding.EncodeToString(envelope),
	})
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

func mutateRecord(t *testing.T, stored json.RawMessage, mutate func(map[string]any)) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(stored, &m); err != nil {
		t.Fatal(err)
	}
	mutate(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func mutateEnvelope(t *testing.T, stored json.RawMessage, mutate func([]byte) []byte) string {
	t.Helper()
	return mutateRecord(t, stored, func(m map[string]any) {
		raw, err := base64.RawURLEncoding.DecodeString(m["ciphertext"].(string))
		if err != nil {
			t.Fatal(err)
		}
		m["ciphertext"] = base64.RawURLEncoding.EncodeToString(mutate(raw))
	})
}

func TestRecordConfigSecretVectors(t *testing.T) {
	const (
		deployment = "dep-fixture-1"
		keyA       = "fixture-config-secret-key-0123456789"
		keyB       = "other-config-secret-key-0123456789ab"
		retiring   = "retiring-config-secret-key-v1-fixture"
	)
	nonce := []byte("fixed-nonce!")
	var cases []secretVectorCase

	ring := func(profile string, version uint32, key string, retiringKeys map[string]string) secretKeyringInput {
		return secretKeyringInput{Deployment: deployment, ActiveVersion: version, ActiveKey: key, Profile: profile, RetiringKeys: retiringKeys}
	}
	codecFor := func(k secretKeyringInput) *ConfigSecretCodec {
		c, err := NewConfigSecretCodec(k.build())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	decryptCase := func(name string, k secretKeyringInput, configKey, stored string) {
		c := codecFor(k)
		plain, err := c.Decrypt(configKey, json.RawMessage(stored))
		cases = append(cases, secretVectorCase{
			Name:   name,
			Input:  map[string]any{"op": "decrypt", "keyring": k, "config_key": configKey, "stored": stored},
			Output: map[string]any{"plaintext_hex": hex.EncodeToString(plain), "error": secretErrText(err)},
		})
	}

	// Sealed values: every profile, every source family, JSON escaping of the source key.
	sealed := map[string]json.RawMessage{}
	for _, profile := range []string{"standard", "smx", "hybrid"} {
		k := ring(profile, 3, keyA, nil)
		c := codecFor(k)
		for _, item := range []struct{ configKey, plaintext string }{
			{"ad_sync_bind_password_enc", `"ad-bind-pw"`},
			{"ldap_sync_bind_password_enc", `"ldap-bind-pw"`},
			{"tls_private_key", `{"pem":"line1\nline2"}`},
			{"identity_source.src-42", `{"clientSecret":"abc"}`},
			{"identity_source.a&b<c>", `["x",1,true,null]`},
			{"assist.api_key", `"sk-fixture"`},
		} {
			stored := sealFixed(t, c, item.configKey, nonce, []byte(item.plaintext))
			sealed[profile+"/"+item.configKey] = stored
			plain, err := c.Decrypt(item.configKey, stored)
			cases = append(cases, secretVectorCase{
				Name: "seal_" + profile + "_" + item.configKey,
				Input: map[string]any{
					"op": "seal", "keyring": k, "config_key": item.configKey,
					"nonce_hex": hex.EncodeToString(nonce), "plaintext_hex": hex.EncodeToString([]byte(item.plaintext)),
				},
				Output: map[string]any{"stored": string(stored), "plaintext_hex": hex.EncodeToString(plain), "error": secretErrText(err)},
			})
		}
	}

	std := sealed["standard/ad_sync_bind_password_enc"]
	smx := sealed["smx/ad_sync_bind_password_enc"]
	good := ring("standard", 3, keyA, nil)

	// Decrypt successes and the self-describing envelope across profiles.
	decryptCase("open_standard_codec_opens_smx_envelope", good, "ad_sync_bind_password_enc", string(smx))
	decryptCase("open_smx_codec_opens_standard_envelope", ring("smx", 3, keyA, nil), "ad_sync_bind_password_enc", string(std))

	// Retiring key: sealed at version 1, read by a version-2 keyring.
	old := codecFor(ring("standard", 1, retiring, nil))
	oldStored := sealFixed(t, old, "ldap_sync_bind_password_enc", nonce, []byte(`"old-secret"`))
	decryptCase("open_retiring_key", ring("standard", 2, keyA, map[string]string{"1": retiring}), "ldap_sync_bind_password_enc", string(oldStored))
	decryptCase("unknown_key_version_without_retiring", ring("standard", 2, keyA, nil), "ldap_sync_bind_password_enc", string(oldStored))
	decryptCase("unknown_key_version_other_retiring", ring("standard", 2, keyA, map[string]string{"5": retiring}), "ldap_sync_bind_password_enc", string(oldStored))
	decryptCase("wrong_retiring_key", ring("standard", 2, keyA, map[string]string{"1": keyB}), "ldap_sync_bind_password_enc", string(oldStored))

	// Fail-closed authentication.
	decryptCase("wrong_key_standard", ring("standard", 3, keyB, nil), "ad_sync_bind_password_enc", string(std))
	decryptCase("wrong_key_smx", ring("smx", 3, keyB, nil), "ad_sync_bind_password_enc", string(smx))
	other := good
	other.Deployment = "dep-fixture-2"
	decryptCase("wrong_deployment", other, "ad_sync_bind_password_enc", string(std))
	decryptCase("wrong_config_key_same_source", good, "ad_sync_other_enc", string(std))
	decryptCase("wrong_config_key_other_source", good, "tls_private_key", string(std))
	decryptCase("wrong_key_version_in_record", good, "ad_sync_bind_password_enc", mutateRecord(t, std, func(m map[string]any) { m["keyVersion"] = 9 }))
	decryptCase("source_key_rewritten", good, "ad_sync_bind_password_enc", mutateRecord(t, std, func(m map[string]any) { m["sourceKey"] = "legacy:ldap" }))

	// Truncation and tampering of the EK01 envelope.
	decryptCase("truncated_envelope_20_bytes", good, "ad_sync_bind_password_enc", mutateEnvelope(t, std, func(b []byte) []byte { return b[:20] }))
	decryptCase("truncated_envelope_below_header", good, "ad_sync_bind_password_enc", mutateEnvelope(t, std, func(b []byte) []byte { return b[:10] }))
	decryptCase("truncated_envelope_one_byte_short", good, "ad_sync_bind_password_enc", mutateEnvelope(t, std, func(b []byte) []byte { return b[:len(b)-1] }))
	decryptCase("truncated_envelope_empty", good, "ad_sync_bind_password_enc", mutateEnvelope(t, std, func(b []byte) []byte { return nil }))
	decryptCase("tampered_tag", good, "ad_sync_bind_password_enc", mutateEnvelope(t, std, func(b []byte) []byte { b[len(b)-1] ^= 1; return b }))
	decryptCase("tampered_ciphertext_smx", ring("smx", 3, keyA, nil), "ad_sync_bind_password_enc", mutateEnvelope(t, smx, func(b []byte) []byte { b[30] ^= 0x80; return b }))
	decryptCase("tampered_nonce", good, "ad_sync_bind_password_enc", mutateEnvelope(t, std, func(b []byte) []byte { b[13] ^= 1; return b }))
	decryptCase("bad_magic", good, "ad_sync_bind_password_enc", mutateEnvelope(t, std, func(b []byte) []byte { b[0] = 'X'; return b }))
	decryptCase("reserved_bytes_set", good, "ad_sync_bind_password_enc", mutateEnvelope(t, std, func(b []byte) []byte { b[10] = 1; return b }))
	decryptCase("unknown_algorithm_tag", good, "ad_sync_bind_password_enc", mutateEnvelope(t, std, func(b []byte) []byte { b[4] = 7; return b }))
	decryptCase("kyber_algorithm_tag", good, "ad_sync_bind_password_enc", mutateEnvelope(t, std, func(b []byte) []byte { b[4] = 2; return b }))
	decryptCase("nonce_length_16", good, "ad_sync_bind_password_enc", mutateEnvelope(t, std, func(b []byte) []byte { b[12] = 16; return b }))
	decryptCase("key_length_16_with_aes_tag", good, "ad_sync_bind_password_enc", mutateEnvelope(t, std, func(b []byte) []byte { b[8] = 16; return b }))
	decryptCase("key_length_24_with_aes_tag", good, "ad_sync_bind_password_enc", mutateEnvelope(t, std, func(b []byte) []byte { b[8] = 24; return b }))
	decryptCase("key_length_5_with_aes_tag", good, "ad_sync_bind_password_enc", mutateEnvelope(t, std, func(b []byte) []byte { b[8] = 5; return b }))
	decryptCase("key_length_32_with_sm4_tag", good, "ad_sync_bind_password_enc", mutateEnvelope(t, std, func(b []byte) []byte { b[4] = 1; return b }))
	decryptCase("key_length_too_large_for_hkdf", good, "ad_sync_bind_password_enc", mutateEnvelope(t, std, func(b []byte) []byte { b[7] = 0x20; return b }))

	// Malformed records.
	decryptCase("not_json", good, "ad_sync_bind_password_enc", "not json")
	decryptCase("json_string", good, "ad_sync_bind_password_enc", `"plain"`)
	decryptCase("json_null", good, "ad_sync_bind_password_enc", `null`)
	decryptCase("empty_object", good, "ad_sync_bind_password_enc", `{}`)
	decryptCase("wrong_format", good, "ad_sync_bind_password_enc", mutateRecord(t, std, func(m map[string]any) { m["format"] = "other" }))
	decryptCase("wrong_version", good, "ad_sync_bind_password_enc", mutateRecord(t, std, func(m map[string]any) { m["version"] = 2 }))
	decryptCase("ciphertext_not_base64", good, "ad_sync_bind_password_enc", mutateRecord(t, std, func(m map[string]any) { m["ciphertext"] = "!!!!" }))
	decryptCase("ciphertext_padded_base64", good, "ad_sync_bind_password_enc", mutateRecord(t, std, func(m map[string]any) { m["ciphertext"] = m["ciphertext"].(string) + "=" }))
	decryptCase("ciphertext_missing", good, "ad_sync_bind_password_enc", mutateRecord(t, std, func(m map[string]any) { delete(m, "ciphertext") }))
	decryptCase("key_version_negative", good, "ad_sync_bind_password_enc", mutateRecord(t, std, func(m map[string]any) { m["keyVersion"] = -1 }))
	decryptCase("version_is_string", good, "ad_sync_bind_password_enc", mutateRecord(t, std, func(m map[string]any) { m["version"] = "1" }))
	notJSON := sealFixed(t, codecFor(good), "ad_sync_plain_enc", nonce, []byte("not json"))
	decryptCase("plaintext_not_json", good, "ad_sync_plain_enc", string(notJSON))

	// Keyring validation.
	keyringCases := []struct {
		name string
		k    secretKeyringInput
	}{
		{"keyring_ok_standard", ring("standard", 1, keyA, nil)},
		{"keyring_ok_smx_16_byte_key", ring("smx", 1, "0123456789abcdef", nil)},
		{"keyring_standard_31_byte_key", ring("standard", 1, keyA[:31], nil)},
		{"keyring_smx_15_byte_key", ring("smx", 1, "0123456789abcde", nil)},
		{"keyring_hybrid_needs_32", ring("hybrid", 1, "0123456789abcdef", nil)},
		{"keyring_version_zero", ring("standard", 0, keyA, nil)},
		{"keyring_blank_deployment", secretKeyringInput{Deployment: " \t ", ActiveVersion: 1, ActiveKey: keyA, Profile: "standard"}},
		{"keyring_deployment_256_bytes", secretKeyringInput{Deployment: string(make([]byte, 0)) + repeatByte('d', 256), ActiveVersion: 1, ActiveKey: keyA, Profile: "standard"}},
		{"keyring_deployment_255_bytes", secretKeyringInput{Deployment: repeatByte('d', 255), ActiveVersion: 1, ActiveKey: keyA, Profile: "standard"}},
		{"keyring_retiring_same_as_active", ring("standard", 2, keyA, map[string]string{"2": retiring})},
		{"keyring_retiring_short_key", ring("standard", 2, keyA, map[string]string{"1": "short"})},
		{"keyring_retiring_16_byte_key", ring("standard", 2, keyA, map[string]string{"1": "0123456789abcdef"})},
	}
	for _, item := range keyringCases {
		_, err := NewConfigSecretCodec(item.k.build())
		cases = append(cases, secretVectorCase{
			Name:   item.name,
			Input:  map[string]any{"op": "keyring", "keyring": item.k},
			Output: map[string]any{"error": secretErrText(err)},
		})
	}

	// Retiring keyring parsing.
	for _, item := range []struct{ name, raw string }{
		{"retiring_blank", "  "},
		{"retiring_null", "null"},
		{"retiring_empty_object", "{}"},
		{"retiring_two_versions", `{"1":"` + retiring + `","7":"another-retiring-key-0123456789"}`},
		{"retiring_not_object", `["a"]`},
		{"retiring_garbage", `{`},
		{"retiring_value_not_string", `{"1":5}`},
		{"retiring_value_null", `{"1":null}`},
		{"retiring_version_zero", `{"0":"` + retiring + `"}`},
		{"retiring_version_text", `{"x":"` + retiring + `"}`},
		{"retiring_version_negative", `{"-1":"` + retiring + `"}`},
		{"retiring_version_plus", `{"+1":"` + retiring + `"}`},
		{"retiring_version_overflow", `{"4294967296":"` + retiring + `"}`},
		{"retiring_version_max", `{"4294967295":"` + retiring + `"}`},
		{"retiring_version_leading_zero", `{"007":"` + retiring + `"}`},
		{"retiring_trailing_data", `{"1":"` + retiring + `"} x`},
	} {
		parsed, err := ParseConfigSecretRetiringKeys(item.raw)
		out := map[string]string{}
		for v, key := range parsed {
			out[base10(v)] = string(key)
		}
		cases = append(cases, secretVectorCase{
			Name:   item.name,
			Input:  map[string]any{"op": "retiring_keys", "raw": item.raw},
			Output: map[string]any{"keys": out, "error": secretErrText(err)},
		})
	}

	writeSecretVectors(t, cases)
}

func repeatByte(b byte, n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return string(out)
}

func base10(v uint32) string {
	if v == 0 {
		return "0"
	}
	var out []byte
	for ; v > 0; v /= 10 {
		out = append([]byte{byte('0' + v%10)}, out...)
	}
	return string(out)
}

// Opens values sealed by the Rust codec (random nonces), written by the Rust
// test `rust_sealed_values_for_go` when SETJOIN_RUST_SEALED_FILE is set.
func TestOpenRustSealedConfigSecrets(t *testing.T) {
	path := os.Getenv("GOFREE_RUST_SEALED_FILE")
	if path == "" {
		t.Skip("GOFREE_RUST_SEALED_FILE not set")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var items []struct {
		Keyring      secretKeyringInput `json:"keyring"`
		ConfigKey    string             `json:"config_key"`
		Stored       string             `json:"stored"`
		PlaintextHex string             `json:"plaintext_hex"`
	}
	if err := json.Unmarshal(raw, &items); err != nil || len(items) == 0 {
		t.Fatalf("rust sealed file: %v (%d items)", err, len(items))
	}
	for _, item := range items {
		c, err := NewConfigSecretCodec(item.Keyring.build())
		if err != nil {
			t.Fatal(err)
		}
		plain, err := c.Decrypt(item.ConfigKey, json.RawMessage(item.Stored))
		if err != nil {
			t.Fatalf("%s/%s: %v", item.Keyring.Profile, item.ConfigKey, err)
		}
		if hex.EncodeToString(plain) != item.PlaintextHex {
			t.Fatalf("%s: plaintext mismatch", item.ConfigKey)
		}
	}
}
