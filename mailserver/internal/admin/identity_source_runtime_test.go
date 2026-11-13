package admin

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func runtimeSourceEnvelope(
	t *testing.T,
	codec *ConfigSecretCodec,
	key string,
	spec string,
	secrets map[string]string,
) []byte {
	t.Helper()
	document := json.RawMessage(`{"apiVersion":"setjoin.io/v1","kind":"IdentitySource","metadata":{"sourceKey":"` +
		key + `","displayName":"Runtime test"},"spec":` + spec + `}`)
	plain, err := json.Marshal(identityStoredSourceDocument{
		Document: document,
		Secrets:  secrets,
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := codec.Encrypt("identity_source."+key, plain)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func TestDecodeIdentitySourceRuntimeRevalidatesAndKeepsSecretPrivate(t *testing.T) {
	t.Parallel()
	codec := testConfigSecretCodec(t)
	envelope := runtimeSourceEnvelope(
		t,
		codec,
		"corp-ad",
		`{"type":"ad","endpoint":{"host":"dc.example.test","port":636,"tls":"ldaps"},`+
			`"subjectAttribute":"msDS-ConsistencyGuid","baseDN":"dc=example,dc=test",`+
			`"bindDN":"cn=sync,dc=example,dc=test","userFilter":"(objectClass=user)"}`,
		map[string]string{
			"bindPassword": base64.StdEncoding.EncodeToString([]byte("runtime-only-secret")),
		},
	)

	got, err := DecodeIdentitySourceRuntime(codec, "corp-ad", "ad", envelope)
	if err != nil {
		t.Fatalf("DecodeIdentitySourceRuntime: %v", err)
	}
	if got.SourceKey != "corp-ad" || got.Kind != "ad" ||
		got.Host != "dc.example.test" || got.Port != 636 ||
		got.Transport != "ldaps" || got.SubjectAttribute != "msDS-ConsistencyGuid" ||
		got.UserFilter != "(objectClass=user)" {
		t.Fatalf("unexpected runtime projection: %#v", got)
	}
	if got.BindPassword() != "runtime-only-secret" {
		t.Fatal("runtime bind password was not projected")
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("runtime-only-secret")) {
		t.Fatalf("generic runtime formatting exposed the bind password: %s", encoded)
	}
}

func TestDecodeIdentitySourceRuntimeFailsClosed(t *testing.T) {
	t.Parallel()
	codec := testConfigSecretCodec(t)
	spec := `{"type":"ldap","endpoint":{"host":"ldap.example.test","port":389,"tls":"starttls"},` +
		`"subjectAttribute":"entryUUID","baseDN":"dc=example,dc=test"}`

	t.Run("missing secret", func(t *testing.T) {
		envelope := runtimeSourceEnvelope(t, codec, "corp-ldap", spec, nil)
		if _, err := DecodeIdentitySourceRuntime(codec, "corp-ldap", "ldap", envelope); err == nil {
			t.Fatal("runtime accepted a connector without its bind password")
		}
	})
	t.Run("invalid secret encoding", func(t *testing.T) {
		envelope := runtimeSourceEnvelope(
			t, codec, "corp-ldap", spec, map[string]string{"bindPassword": "not-base64!"},
		)
		if _, err := DecodeIdentitySourceRuntime(codec, "corp-ldap", "ldap", envelope); err == nil {
			t.Fatal("runtime accepted a malformed stored bind password")
		}
	})
	t.Run("catalog kind mismatch", func(t *testing.T) {
		envelope := runtimeSourceEnvelope(
			t, codec, "corp-ldap", spec, map[string]string{
				"bindPassword": base64.StdEncoding.EncodeToString([]byte("secret")),
			},
		)
		if _, err := DecodeIdentitySourceRuntime(codec, "corp-ldap", "ad", envelope); err == nil {
			t.Fatal("runtime accepted a document/catalog kind mismatch")
		}
	})
	t.Run("catalog key mismatch", func(t *testing.T) {
		envelope := runtimeSourceEnvelope(
			t, codec, "corp-ldap", spec, map[string]string{
				"bindPassword": base64.StdEncoding.EncodeToString([]byte("secret")),
			},
		)
		if _, err := DecodeIdentitySourceRuntime(codec, "other", "ldap", envelope); err == nil {
			t.Fatal("runtime accepted a cross-source ciphertext")
		}
	})
}
