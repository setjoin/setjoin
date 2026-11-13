package cryptokey

import (
	"encoding/json"
	"testing"
)

// TestIsConfigSecretEnvelope pins the shared detection contract for the
// system_config secret envelope: shape, format, and version must all match.
func TestIsConfigSecretEnvelope(t *testing.T) {
	valid := `{"format":"setjoin-config-secret","version":1,"keyVersion":3,` +
		`"sourceKey":"legacy:system","ciphertext":"QUJDREVGRw"}`
	if !IsConfigSecretEnvelope(json.RawMessage(valid)) {
		t.Fatal("valid envelope not detected")
	}

	for name, raw := range map[string]string{
		"plaintext string":  `"sk-plain-legacy-key"`,
		"other json object": `{"format":"http","version":1}`,
		"wrong format":      `{"format":"other-envelope","version":1,"keyVersion":1,"sourceKey":"s","ciphertext":"QUJD"}`,
		"wrong version": `{"format":"setjoin-config-secret","version":2,"keyVersion":1,"sourceKey":"s","ciphertext":"QUJD"}`,
		"not json":      `not-json-at-all`,
		"empty":         ``,
	} {
		if IsConfigSecretEnvelope(json.RawMessage(raw)) {
			t.Errorf("%s detected as envelope: %s", name, raw)
		}
	}
	if IsConfigSecretEnvelope(nil) {
		t.Error("nil detected as envelope")
	}

	// The detector is a shape check on format+version only (matching the
	// admin codec contract): a record missing ciphertext still parses as an
	// envelope and fails later at decrypt time, not here.
	missingCiphertext := `{"format":"setjoin-config-secret","version":1,"keyVersion":1,"sourceKey":"s"}`
	if !IsConfigSecretEnvelope(json.RawMessage(missingCiphertext)) {
		t.Error("format+version record not detected as envelope")
	}

	// The exported record shape round-trips into exactly the detected form.
	record := ConfigSecretEnvelopeRecord{
		Format:     ConfigSecretEnvelopeFormat,
		Version:    ConfigSecretEnvelopeVersion,
		KeyVersion: 7,
		SourceKey:  "identity_source.ldap",
		Ciphertext: "QUJDREVGRw",
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	if !IsConfigSecretEnvelope(encoded) {
		t.Fatalf("marshaled record not detected: %s", encoded)
	}
}
