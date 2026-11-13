package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/ldapsync"
	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

func TestValidateIdentitySourceDocumentKindsAndBounds(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"local": `{"type":"local"}`,
		"ad":    `{"type":"ad","endpoint":{"host":"dc.example.test","port":636,"tls":"ldaps"},"subjectAttribute":"objectGUID","baseDN":"dc=example,dc=test"}`,
		"ldap":  `{"type":"ldap","endpoint":{"host":"ldap.example.test","port":636,"tls":"ldaps"},"subjectAttribute":"entryUUID","baseDN":"dc=example,dc=test"}`,
		"scim":  `{"type":"scim","deletionPolicy":"disable"}`,
		"saml":  `{"type":"saml","registrationKey":"corp-saml","idpEntityId":"https://idp.example.test"}`,
		"oidc":  `{"type":"oidc","providerKey":"corp-oidc","issuer":"https://idp.example.test","clientId":"setjoin","subjectClaim":"sub"}`,
	}
	for name, spec := range tests {
		name, spec := name, spec
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			raw := json.RawMessage(`{"apiVersion":"setjoin.io/v1","kind":"IdentitySource","metadata":{"sourceKey":"` +
				name + `:test","displayName":"` + strings.ToUpper(name) + ` test"},"spec":` + spec + `}`)
			document, canonical, err := validateIdentitySourceDocument(raw)
			if err != nil {
				t.Fatalf("valid %s document: %v", name, err)
			}
			if document.Metadata.SourceKey != name+":test" || !json.Valid(canonical) {
				t.Fatalf("invalid canonical result: %+v %s", document, canonical)
			}
		})
	}
}

func TestValidateIdentitySourceDocumentRejectsUnsafeShapes(t *testing.T) {
	t.Parallel()
	validPrefix := `{"apiVersion":"setjoin.io/v1","kind":"IdentitySource","metadata":{"sourceKey":"corp","displayName":"Corp"},"spec":`
	tests := map[string]string{
		"unknown top-level":      `{"apiVersion":"setjoin.io/v1","kind":"IdentitySource","metadata":{"sourceKey":"corp","displayName":"Corp"},"spec":{"type":"local"},"secret":"leak"}`,
		"secret in spec":         validPrefix + `{"type":"oidc","providerKey":"p","issuer":"https://idp.example.test","clientId":"c","subjectClaim":"sub","clientSecret":"leak"}}`,
		"AD soft subject":        validPrefix + `{"type":"ad","endpoint":{"host":"dc.example.test","port":636,"tls":"ldaps"},"subjectAttribute":"mail","baseDN":"dc=example,dc=test"}}`,
		"OIDC soft subject":      validPrefix + `{"type":"oidc","providerKey":"p","issuer":"https://idp.example.test","clientId":"c","subjectClaim":"email"}}`,
		"unknown endpoint field": validPrefix + `{"type":"ldap","endpoint":{"host":"ldap.example.test","port":636,"tls":"ldaps","password":"leak"},"subjectAttribute":"entryUUID","baseDN":"dc=example,dc=test"}}`,
	}
	for name, raw := range tests {
		name, raw := name, raw
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := validateIdentitySourceDocument(json.RawMessage(raw)); err == nil {
				t.Fatal("unsafe identity source document accepted")
			}
		})
	}
}

func TestValidateIdentitySourceDocumentRejectsEveryBoundedContractArm(t *testing.T) {
	t.Parallel()
	document := func(sourceKey, displayName, spec string) json.RawMessage {
		return json.RawMessage(`{"apiVersion":"setjoin.io/v1","kind":"IdentitySource",` +
			`"metadata":{"sourceKey":` + strconv.Quote(sourceKey) +
			`,"displayName":` + strconv.Quote(displayName) + `},"spec":` + spec + `}`)
	}
	tests := map[string]json.RawMessage{
		"empty":                  nil,
		"oversized":              json.RawMessage(strings.Repeat("x", identityBodyMaxBytes+1)),
		"invalid JSON":           json.RawMessage(`{`),
		"trailing JSON":          append(document("corp", "Corp", `{"type":"local"}`), []byte(` {}`)...),
		"wrong api version":      json.RawMessage(`{"apiVersion":"v0","kind":"IdentitySource","metadata":{"sourceKey":"corp","displayName":"Corp"},"spec":{"type":"local"}}`),
		"wrong kind":             json.RawMessage(`{"apiVersion":"setjoin.io/v1","kind":"Other","metadata":{"sourceKey":"corp","displayName":"Corp"},"spec":{"type":"local"}}`),
		"invalid key":            document("bad key", "Corp", `{"type":"local"}`),
		"blank display":          document("corp", "", `{"type":"local"}`),
		"trimmed display":        document("corp", " Corp", `{"type":"local"}`),
		"control display":        document("corp", "Corp\nName", `{"type":"local"}`),
		"long display":           document("corp", strings.Repeat("x", 129), `{"type":"local"}`),
		"spec null":              document("corp", "Corp", `null`),
		"spec array":             document("corp", "Corp", `[]`),
		"missing type":           document("corp", "Corp", `{}`),
		"non-string type":        document("corp", "Corp", `{"type":1}`),
		"unsupported type":       document("corp", "Corp", `{"type":"other"}`),
		"unknown spec field":     document("corp", "Corp", `{"type":"local","extra":true}`),
		"AD missing base":        document("corp", "Corp", `{"type":"ad","subjectAttribute":"objectGUID","endpoint":{"host":"dc.example.test","port":636,"tls":"ldaps"}}`),
		"AD missing subject":     document("corp", "Corp", `{"type":"ad","baseDN":"dc=example","endpoint":{"host":"dc.example.test","port":636,"tls":"ldaps"}}`),
		"AD soft subject":        document("corp", "Corp", `{"type":"ad","baseDN":"dc=example","subjectAttribute":"mail","endpoint":{"host":"dc.example.test","port":636,"tls":"ldaps"}}`),
		"AD invalid endpoint":    document("corp", "Corp", `{"type":"ad","baseDN":"dc=example","subjectAttribute":"objectGUID","endpoint":{"host":"","port":0,"tls":"none"}}`),
		"LDAP missing subject":   document("corp", "Corp", `{"type":"ldap","baseDN":"dc=example","endpoint":{"host":"ldap.example.test","port":636,"tls":"ldaps"}}`),
		"SAML missing key":       document("corp", "Corp", `{"type":"saml","idpEntityId":"https://idp.example.test"}`),
		"SAML missing entity":    document("corp", "Corp", `{"type":"saml","registrationKey":"corp"}`),
		"OIDC missing provider":  document("corp", "Corp", `{"type":"oidc","issuer":"https://idp.example.test","clientId":"setjoin","subjectClaim":"sub"}`),
		"OIDC missing issuer":    document("corp", "Corp", `{"type":"oidc","providerKey":"corp","clientId":"setjoin","subjectClaim":"sub"}`),
		"OIDC missing client":    document("corp", "Corp", `{"type":"oidc","providerKey":"corp","issuer":"https://idp.example.test","subjectClaim":"sub"}`),
		"OIDC wrong subject":     document("corp", "Corp", `{"type":"oidc","providerKey":"corp","issuer":"https://idp.example.test","clientId":"setjoin","subjectClaim":"email"}`),
		"capabilities null":      document("corp", "Corp", `{"type":"local","capabilities":null}`),
		"capabilities nonobject": document("corp", "Corp", `{"type":"local","capabilities":[]}`),
		"capabilities unknown":   document("corp", "Corp", `{"type":"local","capabilities":{"takeover":true}}`),
		"endpoint unknown field": document("corp", "Corp", `{"type":"ldap","baseDN":"dc=example","subjectAttribute":"entryUUID","endpoint":{"host":"ldap.example.test","port":636,"tls":"ldaps","secret":"x"}}`),
		"endpoint invalid port":  document("corp", "Corp", `{"type":"ldap","baseDN":"dc=example","subjectAttribute":"entryUUID","endpoint":{"host":"ldap.example.test","port":65536,"tls":"ldaps"}}`),
		"endpoint insecure tls":  document("corp", "Corp", `{"type":"ldap","baseDN":"dc=example","subjectAttribute":"entryUUID","endpoint":{"host":"ldap.example.test","port":636,"tls":"none"}}`),
		"endpoint control host":  document("corp", "Corp", `{"type":"ldap","baseDN":"dc=example","subjectAttribute":"entryUUID","endpoint":{"host":"ldap\n.example.test","port":636,"tls":"ldaps"}}`),
	}
	for name, raw := range tests {
		name, raw := name, raw
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := validateIdentitySourceDocument(raw); err == nil {
				t.Fatal("invalid identity source document accepted")
			}
		})
	}
	if _, _, err := validateIdentitySourceDocument(document(
		"corp-ad", "Corp AD",
		`{"type":"ad","baseDN":"dc=example","subjectAttribute":"msDS-ConsistencyGuid",`+
			`"endpoint":{"host":"dc.example.test","port":389,"tls":"starttls"},`+
			`"capabilities":{"authenticate":false,"provisionLifecycle":true,`+
			`"passwordWriteback":false,"profileFields":true,"entitlements":true,`+
			`"deltaCursor":true,"suspendDelete":true,"immutableSubject":true}}`,
	)); err != nil {
		t.Fatalf("complete bounded AD contract rejected: %v", err)
	}
}

func TestIdentitySourceEnvelopeBindsExactSourceKey(t *testing.T) {
	t.Parallel()
	codec, err := NewConfigSecretCodec(ConfigSecretKeyring{
		DeploymentID:  uuid.NewString(),
		ActiveVersion: 1,
		ActiveKey:     []byte("identity-source-test-master-key-32-bytes"),
		ActiveProfile: cryptokey.ProfileStandard,
	})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := codec.Encrypt("identity_source.corp-ad", json.RawMessage(`{"secret":"value"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := codec.Decrypt("identity_source.corp-ad", stored); err != nil {
		t.Fatalf("same-source decrypt: %v", err)
	}
	if _, err := codec.Decrypt("identity_source.other-ad", stored); err == nil {
		t.Fatal("cross-source envelope transplant was accepted")
	}
}

func TestIdentityStoredSourceCodecRejectsMissingCorruptAndCrossSourceEnvelopes(t *testing.T) {
	codec := testConfigSecretCodec(t)
	withoutCodec := NewIdentityHandler(nil, nil, testsupport.TestLogger())
	if _, err := withoutCodec.decodeStoredIdentitySource(identitySourceRow{
		SourceKey: "corp-oidc",
	}); err == nil {
		t.Fatal("stored source decoded without a codec")
	}
	if _, _, err := withoutCodec.encryptStoredIdentitySource(
		"corp-oidc", json.RawMessage(`{"type":"oidc"}`), nil,
	); err == nil {
		t.Fatal("stored source encrypted without a codec")
	}

	h := NewIdentityHandler(nil, nil, testsupport.TestLogger())
	h.SetSourceSecretCodec(codec)
	empty, err := h.decodeStoredIdentitySource(identitySourceRow{
		SourceKey: "corp-oidc",
	})
	if err != nil || empty.Secrets == nil {
		t.Fatalf("empty legacy envelope did not produce an empty secret map: %+v %v",
			empty, err)
	}
	if _, err := h.decodeStoredIdentitySource(identitySourceRow{
		SourceKey:      "corp-oidc",
		ConfigEnvelope: json.RawMessage(`{"not":"an envelope"}`),
	}); err == nil {
		t.Fatal("malformed stored source envelope accepted")
	}
	crossSource, err := codec.Encrypt("identity_source.other",
		json.RawMessage(`{"document":{"type":"oidc"},"secrets":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.decodeStoredIdentitySource(identitySourceRow{
		SourceKey: "corp-oidc", ConfigEnvelope: crossSource,
	}); err == nil {
		t.Fatal("cross-source stored envelope accepted")
	}
	envelope, _, err := h.encryptStoredIdentitySource(
		"corp-oidc", json.RawMessage(`{"type":"oidc"}`), nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := h.decodeStoredIdentitySource(identitySourceRow{
		SourceKey: "corp-oidc", ConfigEnvelope: envelope,
	})
	if err != nil || decoded.Secrets == nil {
		t.Fatalf("round-trip stored source failed: %+v %v", decoded, err)
	}
}

func TestIdentityMutationHeadersRequireExactStrongContracts(t *testing.T) {
	t.Parallel()
	key := uuid.NewString()
	request := httptest.NewRequest("POST", "/", nil)
	request.Header.Set("Idempotency-Key", key)
	recorder := httptest.NewRecorder()
	if got, ok := identityMutationHeaders(recorder, request, key); !ok || got.String() != key {
		t.Fatalf("exact idempotency key rejected: %v %v", got, ok)
	}
	recorder = httptest.NewRecorder()
	if _, ok := identityMutationHeaders(recorder, request, uuid.NewString()); ok {
		t.Fatal("mismatched body/header idempotency key accepted")
	}

	request.Header.Set("If-Match", `"7"`)
	recorder = httptest.NewRecorder()
	if generation, ok := identityExpectedGeneration(recorder, request, "7"); !ok || generation != 7 {
		t.Fatalf("strong generation ETag rejected: %d %v", generation, ok)
	}
	request.Header.Set("If-Match", `W/"7"`)
	recorder = httptest.NewRecorder()
	if _, ok := identityExpectedGeneration(recorder, request, "7"); ok {
		t.Fatal("weak If-Match accepted")
	}
}

func TestIdentitySourceSecretCatalogIsClosed(t *testing.T) {
	t.Parallel()
	if !identitySecretNameAllowed("oidc", "clientSecret") ||
		identitySecretNameAllowed("oidc", "bindPassword") ||
		identitySecretNameAllowed("local", "password") {
		t.Fatal("source secret catalog is not kind-confined")
	}
}

func TestIdentitySourceHandlersFailClosedAtEveryLocalContractBoundary(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewIdentityHandler(pool, pool, testsupport.TestLogger())
	h.SetSourceSecretCodec(testConfigSecretCodec(t))
	reason := "identity source contract boundary test"
	key := uuid.NewString()
	adminRequest := func(method, target, body string) *http.Request {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header.Set("X-Audit-Reason", reason)
		return req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
			UserID:            42,
			IsAdmin:           true,
			Permissions:       permissions.AllPermissions,
			GlobalPermissions: permissions.AllPermissions,
		}))
	}
	call := func(
		name string,
		handler func(http.ResponseWriter, *http.Request),
		req *http.Request,
		want int,
	) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler(rec, req)
			if rec.Code != want {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, want, rec.Body.String())
			}
		})
	}

	call("plan malformed JSON", h.IdentitySourcePlan,
		adminRequest(http.MethodPost, "/admin/identity/v2/sources:plan", `{`),
		http.StatusBadRequest)
	call("plan invalid document", h.IdentitySourcePlan,
		adminRequest(http.MethodPost, "/admin/identity/v2/sources:plan",
			`{"apiVersion":"setjoin.io/v1","kind":"IdentitySource",`+
				`"metadata":{"sourceKey":"bad key","displayName":"Bad"},`+
				`"spec":{"type":"local"}}`),
		http.StatusBadRequest)

	validDocument := `{"apiVersion":"setjoin.io/v1","kind":"IdentitySource",` +
		`"metadata":{"sourceKey":"boundary-source","displayName":"Boundary"},` +
		`"spec":{"type":"local"}}`
	call("apply malformed JSON", h.IdentitySourceApply,
		adminRequest(http.MethodPost, "/admin/identity/v2/sources:apply", `{`),
		http.StatusBadRequest)
	call("apply invalid document", h.IdentitySourceApply,
		adminRequest(http.MethodPost, "/admin/identity/v2/sources:apply",
			`{"document":{},"reason":"`+reason+`","idempotencyKey":"`+key+`"}`),
		http.StatusBadRequest)
	pathMismatch := adminRequest(http.MethodPost,
		"/admin/identity/v2/sources/other:apply",
		`{"document":`+validDocument+`,"reason":"`+reason+
			`","idempotencyKey":"`+key+`"}`)
	pathMismatch.SetPathValue("sourceKey", "other")
	call("apply path mismatch", h.IdentitySourceApply, pathMismatch, http.StatusBadRequest)
	missingHeader := adminRequest(http.MethodPost, "/admin/identity/v2/sources:apply",
		`{"document":`+validDocument+`,"reason":"`+reason+
			`","idempotencyKey":"`+key+`"}`)
	call("apply missing idempotency header", h.IdentitySourceApply,
		missingHeader, http.StatusBadRequest)

	newSourceKey := "boundary-" + strings.ToLower(uuid.NewString()[:8])
	newDocument := `{"apiVersion":"setjoin.io/v1","kind":"IdentitySource",` +
		`"metadata":{"sourceKey":"` + newSourceKey + `","displayName":"Boundary new"},` +
		`"spec":{"type":"local"}}`
	newBody := `{"document":` + newDocument + `,"reason":"` + reason +
		`","idempotencyKey":"` + key + `"}`
	newWithIfMatch := adminRequest(http.MethodPost,
		"/admin/identity/v2/sources:apply", newBody)
	newWithIfMatch.Header.Set("Idempotency-Key", key)
	newWithIfMatch.Header.Set("If-Match", `"1"`)
	call("new apply rejects If-Match", h.IdentitySourceApply,
		newWithIfMatch, http.StatusPreconditionFailed)

	withoutCodec := NewIdentityHandler(pool, pool, testsupport.TestLogger())
	newWithoutCodec := adminRequest(http.MethodPost,
		"/admin/identity/v2/sources:apply", newBody)
	newWithoutCodec.Header.Set("Idempotency-Key", key)
	call("new apply fails closed without source codec",
		withoutCodec.IdentitySourceApply, newWithoutCodec,
		http.StatusServiceUnavailable)

	detailBadKey := adminRequest(http.MethodGet,
		"/admin/identity/v2/sources/bad", "")
	detailBadKey.SetPathValue("sourceKey", "bad key")
	call("detail invalid source key", h.IdentitySourceDetail,
		detailBadKey, http.StatusBadRequest)
	detailMissing := adminRequest(http.MethodGet,
		"/admin/identity/v2/sources/missing-source", "")
	detailMissing.SetPathValue("sourceKey", "missing-source")
	call("detail missing source", h.IdentitySourceDetail,
		detailMissing, http.StatusNotFound)
	exportMissing := adminRequest(http.MethodGet,
		"/admin/identity/v2/sources/missing-source/export", "")
	exportMissing.SetPathValue("sourceKey", "missing-source")
	call("export missing source", h.IdentitySourceExport,
		exportMissing, http.StatusNotFound)

	secretRequest := func(contentType, sourceKey, name, body string) *http.Request {
		req := adminRequest(http.MethodPut,
			"/admin/identity/v2/sources/source/secrets/name", body)
		req.SetPathValue("sourceKey", sourceKey)
		req.SetPathValue("name", name)
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("Idempotency-Key", key)
		req.Header.Set("X-Identity-Reason", reason)
		req.Header.Set("If-Match", `"1"`)
		return req
	}
	call("secret wrong media type", h.IdentitySourceSetSecret,
		secretRequest("application/json", "missing-source", "clientSecret", `{}`),
		http.StatusUnsupportedMediaType)
	call("secret invalid path", h.IdentitySourceSetSecret,
		secretRequest("application/octet-stream", "bad key", "clientSecret", "secret"),
		http.StatusBadRequest)
	call("secret missing source", h.IdentitySourceSetSecret,
		secretRequest("application/octet-stream", "missing-source", "clientSecret", "secret"),
		http.StatusNotFound)

	unknownAction := adminRequest(http.MethodPost,
		"/admin/identity/v2/sources/missing-source/unknown", `{}`)
	unknownAction.SetPathValue("action", "unknown")
	call("lifecycle unknown action", h.IdentitySourceLifecycle,
		unknownAction, http.StatusNotFound)
	for name, body := range map[string]string{
		"malformed JSON": `{`,
		"invalid generation": `{"expectedGeneration":"0","reason":"` + reason +
			`","idempotencyKey":"` + key + `"}`,
		"missing idempotency header": `{"expectedGeneration":"1","reason":"` + reason +
			`","idempotencyKey":"` + key + `"}`,
	} {
		req := adminRequest(http.MethodPost,
			"/admin/identity/v2/sources/missing-source/activate", body)
		req.SetPathValue("sourceKey", "missing-source")
		if name != "missing idempotency header" {
			req.Header.Set("Idempotency-Key", key)
		}
		req.Header.Set("If-Match", `"1"`)
		call("lifecycle "+name, h.IdentitySourceActivate, req, http.StatusBadRequest)
	}
	invalidLifecycleKey := adminRequest(http.MethodPost,
		"/admin/identity/v2/sources/bad/activate",
		`{"expectedGeneration":"1","reason":"`+reason+`","idempotencyKey":"`+key+`"}`)
	invalidLifecycleKey.SetPathValue("sourceKey", "bad key")
	invalidLifecycleKey.Header.Set("Idempotency-Key", key)
	invalidLifecycleKey.Header.Set("If-Match", `"1"`)
	call("lifecycle invalid source key", h.IdentitySourceActivate,
		invalidLifecycleKey, http.StatusBadRequest)

	dryMalformed := adminRequest(http.MethodPost,
		"/admin/identity/v2/sources/missing-source/dry-run", `{`)
	dryMalformed.SetPathValue("sourceKey", "missing-source")
	call("dry run malformed JSON", h.IdentitySourceDryRun,
		dryMalformed, http.StatusBadRequest)
	dryMissing := adminRequest(http.MethodPost,
		"/admin/identity/v2/sources/missing-source/dry-run",
		`{"expectedGeneration":"1","reason":"`+reason+`","idempotencyKey":"`+key+`"}`)
	dryMissing.SetPathValue("sourceKey", "missing-source")
	dryMissing.Header.Set("Idempotency-Key", key)
	dryMissing.Header.Set("If-Match", `"1"`)
	call("dry run missing source", h.IdentitySourceDryRun,
		dryMissing, http.StatusNotFound)
}

func TestIdentitySourceHandlersRejectCorruptStoredConfiguration(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	sourceKey := "corrupt-" + strings.ToLower(uuid.NewString()[:8])
	if _, err := pool.Exec(ctx, `
		INSERT INTO identity_sources(
		    source_key,display_name,kind,capabilities,state,generation,
		    config_envelope,config_key_version,mapping_version
		) VALUES(
		    $1,'Corrupt source','oidc',
		    '{"authenticate":true,"provision_lifecycle":false,
		      "stable_immutable_subject":true}'::jsonb,
		    'draft',1,$2,1,1
		)
	`, sourceKey, []byte(`{"not":"an encrypted envelope"}`)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM identity_sources WHERE source_key=$1`, sourceKey)
	})

	codec := testConfigSecretCodec(t)
	h := NewIdentityHandler(pool, pool, testsupport.TestLogger())
	h.SetSourceSecretCodec(codec)
	reason := "corrupt stored source contract test"
	key := uuid.NewString()
	document := `{"apiVersion":"setjoin.io/v1","kind":"IdentitySource",` +
		`"metadata":{"sourceKey":"` + sourceKey + `","displayName":"Corrupt source"},` +
		`"spec":{"type":"oidc","providerKey":"` + sourceKey + `",` +
		`"issuer":"https://idp.example.test","clientId":"setjoin",` +
		`"subjectClaim":"sub"}}`
	adminRequest := func(method, target, body string) *http.Request {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header.Set("X-Audit-Reason", reason)
		return req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
			UserID:            42,
			IsAdmin:           true,
			Permissions:       permissions.AllPermissions,
			GlobalPermissions: permissions.AllPermissions,
		}))
	}
	call := func(
		name string,
		handler func(http.ResponseWriter, *http.Request),
		req *http.Request,
		want int,
	) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler(rec, req)
			if rec.Code != want {
				t.Fatalf("status=%d want=%d body=%s",
					rec.Code, want, rec.Body.String())
			}
		})
	}

	call("plan", h.IdentitySourcePlan,
		adminRequest(http.MethodPost, "/sources:plan", document),
		http.StatusInternalServerError)

	apply := adminRequest(http.MethodPost, "/sources/"+sourceKey+":apply",
		`{"document":`+document+`,"reason":"`+reason+
			`","idempotencyKey":"`+key+`"}`)
	apply.SetPathValue("sourceKey", sourceKey)
	apply.Header.Set("Idempotency-Key", key)
	apply.Header.Set("If-Match", `"1"`)
	call("apply", h.IdentitySourceApply, apply, http.StatusInternalServerError)

	detail := adminRequest(http.MethodGet, "/sources/"+sourceKey, "")
	detail.SetPathValue("sourceKey", sourceKey)
	call("detail", h.IdentitySourceDetail, detail, http.StatusInternalServerError)

	secret := adminRequest(http.MethodPut,
		"/sources/"+sourceKey+"/secrets/clientSecret", "secret")
	secret.SetPathValue("sourceKey", sourceKey)
	secret.SetPathValue("name", "clientSecret")
	secret.Header.Set("Content-Type", "application/octet-stream")
	secret.Header.Set("Idempotency-Key", key)
	secret.Header.Set("If-Match", `"1"`)
	secret.Header.Set("X-Identity-Reason", reason)
	call("secret", h.IdentitySourceSetSecret, secret,
		http.StatusInternalServerError)

	dryRun := adminRequest(http.MethodPost, "/sources/"+sourceKey+":dry-run",
		`{"expectedGeneration":"1","reason":"`+reason+
			`","idempotencyKey":"`+key+`"}`)
	dryRun.SetPathValue("sourceKey", sourceKey)
	dryRun.Header.Set("Idempotency-Key", key)
	dryRun.Header.Set("If-Match", `"1"`)
	call("dry run envelope", h.IdentitySourceDryRun, dryRun,
		http.StatusInternalServerError)

	invalidDocumentEnvelope, err := codec.Encrypt("identity_source."+sourceKey,
		json.RawMessage(`{"document":{"bad":true},"secrets":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE identity_sources SET config_envelope=$2 WHERE source_key=$1`,
		sourceKey, []byte(invalidDocumentEnvelope)); err != nil {
		t.Fatal(err)
	}
	invalidKey := uuid.NewString()
	invalidDryRun := adminRequest(http.MethodPost, "/sources/"+sourceKey+":dry-run",
		`{"expectedGeneration":"1","reason":"`+reason+
			`","idempotencyKey":"`+invalidKey+`"}`)
	invalidDryRun.SetPathValue("sourceKey", sourceKey)
	invalidDryRun.Header.Set("Idempotency-Key", invalidKey)
	invalidDryRun.Header.Set("If-Match", `"1"`)
	call("dry run document", h.IdentitySourceDryRun, invalidDryRun,
		http.StatusConflict)
}

func TestIdentitySourceDryRunReportsBoundedLDAPTransportPosture(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	suffix := strings.ToLower(uuid.NewString()[:8])
	var mailboxID, actorID int64
	if err := pool.QueryRow(ctx, `SELECT mk_account($1)`,
		"identity-source-transport-"+suffix).Scan(&mailboxID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT user_id FROM mailboxes WHERE id=$1`, mailboxID,
	).Scan(&actorID); err != nil {
		t.Fatal(err)
	}

	const unreachablePort = 46360
	const reachablePort = 46361

	codec := testConfigSecretCodec(t)
	h := NewIdentityHandler(pool, pool, testsupport.TestLogger())
	h.SetSourceSecretCodec(codec)
	h.sourceProbe = func(_ context.Context, cfg IdentitySourceRuntimeConfig) error {
		if strings.Contains(cfg.SourceKey, "down") {
			return errors.New("directory unavailable")
		}
		if strings.Contains(cfg.SourceKey, "reject") {
			return &ldap.Error{ResultCode: ldap.LDAPResultInvalidCredentials, Err: errors.New("bind rejected")}
		}
		return nil
	}
	sourceKeys := []string{
		"ldap-down-" + suffix,
		"ldap-up-" + suffix,
		"ldap-reject-" + suffix,
		"ldap-mismatch-" + suffix,
	}
	document := func(sourceKey string, port int) json.RawMessage {
		return json.RawMessage(`{"apiVersion":"setjoin.io/v1","kind":"IdentitySource",` +
			`"metadata":{"sourceKey":"` + sourceKey + `","displayName":"LDAP transport"},` +
			`"spec":{"type":"ldap","endpoint":{"host":"127.0.0.1","port":` +
			strconv.Itoa(port) + `,"tls":"starttls"},"subjectAttribute":"entryUUID",` +
			`"baseDN":"dc=example,dc=test"}}`)
	}
	for index, sourceKey := range sourceKeys {
		port := unreachablePort
		if index == 1 {
			port = reachablePort
		}
		rowKind := "ldap"
		if index == 3 {
			rowKind = "ad"
		}
		_, canonical, err := validateIdentitySourceDocument(document(sourceKey, port))
		if err != nil {
			t.Fatal(err)
		}
		envelope, keyVersion, err := h.encryptStoredIdentitySource(
			sourceKey, canonical, map[string]string{
				"bindPassword": base64.StdEncoding.EncodeToString([]byte("secret")),
			})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO identity_sources(
			    source_key,display_name,kind,capabilities,state,generation,
			    config_envelope,config_key_version,mapping_version
			) VALUES(
			    $1,'LDAP transport',$2,
			    '{"authenticate":false,"provision_lifecycle":true,
			      "stable_immutable_subject":true}'::jsonb,
			    'draft',1,$3,$4,1
			)
		`, sourceKey, rowKind, []byte(envelope), keyVersion); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, sourceKey := range sourceKeys {
			_, _ = pool.Exec(context.Background(), `
				DELETE FROM identity_source_operations
				 WHERE source_id IN (
				       SELECT id FROM identity_sources WHERE source_key=$1
				 )
			`, sourceKey)
			_, _ = pool.Exec(context.Background(),
				`DELETE FROM identity_sources WHERE source_key=$1`, sourceKey)
		}
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM mailboxes WHERE id=$1`, mailboxID)
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM users WHERE id=$1`, actorID)
	})

	reason := "bounded LDAP transport dry run"
	callDryRun := func(sourceKey string) *httptest.ResponseRecorder {
		t.Helper()
		key := uuid.NewString()
		req := httptest.NewRequest(http.MethodPost,
			"/sources/"+sourceKey+":dry-run",
			strings.NewReader(`{"expectedGeneration":"1","reason":"`+reason+
				`","idempotencyKey":"`+key+`"}`))
		req.SetPathValue("sourceKey", sourceKey)
		req.Header.Set("Idempotency-Key", key)
		req.Header.Set("If-Match", `"1"`)
		req.Header.Set("X-Audit-Reason", reason)
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
			UserID: actorID, IsAdmin: true,
			Permissions:       permissions.AllPermissions,
			GlobalPermissions: permissions.AllPermissions,
		}))
		rec := httptest.NewRecorder()
		h.IdentitySourceDryRun(rec, req)
		return rec
	}

	down := callDryRun(sourceKeys[0])
	if down.Code != http.StatusOK ||
		!strings.Contains(down.Body.String(), "directory_probe_failed") ||
		!strings.Contains(down.Body.String(), `"transport":"failed"`) {
		t.Fatalf("unreachable LDAP posture: status=%d body=%s",
			down.Code, down.Body.String())
	}
	up := callDryRun(sourceKeys[1])
	if up.Code != http.StatusAccepted ||
		!strings.Contains(up.Body.String(), `"valid":true`) ||
		!strings.Contains(up.Body.String(), `"transport":"reachable"`) {
		t.Fatalf("reachable LDAP posture: status=%d body=%s",
			up.Code, up.Body.String())
	}
	rejected := callDryRun(sourceKeys[2])
	if rejected.Code != http.StatusOK ||
		!strings.Contains(rejected.Body.String(), "credential_rejected") ||
		!strings.Contains(rejected.Body.String(), `"transport":"reachable"`) {
		t.Fatalf("credential-rejected LDAP posture: status=%d body=%s",
			rejected.Code, rejected.Body.String())
	}
	mismatch := callDryRun(sourceKeys[3])
	if mismatch.Code != http.StatusOK ||
		!strings.Contains(mismatch.Body.String(), "runtime_configuration_invalid") ||
		!strings.Contains(mismatch.Body.String(), `"transport":"failed"`) {
		t.Fatalf("runtime-mismatch LDAP posture: status=%d body=%s",
			mismatch.Code, mismatch.Body.String())
	}
}

func TestIdentitySourceProbeClassifiesRejectedCredentialWithoutLeakingIt(t *testing.T) {
	secret := "never-log-this"
	probeErr := &ldap.Error{
		ResultCode: ldap.LDAPResultInvalidCredentials,
		Err:        errors.New("bind rejected"),
	}
	blocker, reachable := identitySourceProbeBlocker(probeErr)
	if blocker != "credential_rejected" || !reachable {
		t.Fatalf("credential classification = %q/%t", blocker, reachable)
	}
	if strings.Contains(probeErr.Error(), secret) || strings.Contains(blocker, secret) {
		t.Fatal("credential probe classification exposed secret material")
	}
}

func TestIdentitySourceRuntimeProbeRejectsInvalidBoundariesBeforeNetworkIO(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	logger := testsupport.TestLogger()

	tests := []struct {
		name string
		cfg  IdentitySourceRuntimeConfig
		want string
	}{
		{
			name: "unsupported kind",
			cfg:  IdentitySourceRuntimeConfig{Kind: "oidc"},
			want: "does not support",
		},
		{
			name: "invalid AD endpoint",
			cfg: IdentitySourceRuntimeConfig{
				Kind: "ad", Transport: "ldaps", BaseDN: "dc=example,dc=test",
				SubjectAttribute: "objectGUID",
			},
			want: "endpoint",
		},
		{
			name: "invalid LDAP endpoint",
			cfg: IdentitySourceRuntimeConfig{
				Kind: "ldap", Transport: "ldaps", BaseDN: "dc=example,dc=test",
			},
			want: "endpoint",
		},
		{
			name: "invalid LDAP subject attribute",
			cfg: IdentitySourceRuntimeConfig{
				Kind: "ldap", Host: "127.0.0.1", Port: 636, Transport: "ldaps",
				BaseDN: "dc=example,dc=test", SubjectAttribute: "bad attribute",
			},
			want: "subject attribute",
		},
		{
			name: "invalid LDAP filter",
			cfg: IdentitySourceRuntimeConfig{
				Kind: "ldap", Host: "127.0.0.1", Port: 636, Transport: "ldaps",
				BaseDN: "dc=example,dc=test", SubjectAttribute: "entryUUID",
				UserFilter: ")bad(",
			},
			want: "user filter",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := probeIdentitySourceRuntime(ctx, test.cfg, logger)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("probe error = %v, want substring %q", err, test.want)
			}
		})
	}

	// The constructor must retain the production probe rather than leaving a
	// nil seam that would turn a dry run into a panic or false success.
	h := NewIdentityHandler(nil, nil, logger)
	if err := h.sourceProbe(ctx, IdentitySourceRuntimeConfig{Kind: "local"}); err == nil {
		t.Fatal("default source probe accepted an unsupported runtime kind")
	}
}

func TestIdentitySourceProbeClassifiesTypedBindAndNetworkFailures(t *testing.T) {
	t.Parallel()
	blocker, reachable := identitySourceProbeBlocker(&ldapsync.ConnError{
		Class: ldapsync.ConnClassBindAuth,
		Err:   errors.New("bind rejected"),
	})
	if blocker != "credential_rejected" || !reachable {
		t.Fatalf("typed bind classification = %q/%t", blocker, reachable)
	}

	blocker, reachable = identitySourceProbeBlocker(&ldapsync.ConnError{
		Class: ldapsync.ConnClassNetwork,
		Err:   errors.New("dial failed"),
	})
	if blocker != "directory_probe_failed" || reachable {
		t.Fatalf("typed network classification = %q/%t", blocker, reachable)
	}
}

func TestIdentitySourceOperatorLifecycleWithEncryptedSecret(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	suffix := strings.ToLower(uuid.NewString()[:8])
	sourceKey := "oidc-" + suffix
	username := "identity-source-" + suffix

	var mailboxID, actorID int64
	if err := pool.QueryRow(ctx, `SELECT mk_account($1)`, username).Scan(&mailboxID); err != nil {
		t.Fatalf("create identity source actor: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT user_id FROM mailboxes WHERE id=$1`, mailboxID,
	).Scan(&actorID); err != nil {
		t.Fatalf("read identity source actor: %v", err)
	}
	t.Cleanup(func() {
		cleanup := context.Background()
		var sourceID int64
		_ = pool.QueryRow(cleanup,
			`SELECT id FROM identity_sources WHERE source_key=$1`, sourceKey,
		).Scan(&sourceID)
		_, _ = pool.Exec(cleanup, `
			DELETE FROM identity_source_operations
			 WHERE source_id IN (SELECT id FROM identity_sources WHERE source_key=$1)
		`, sourceKey)
		if sourceID != 0 {
			cleanupIdentityLinkEventsForSource(t, pool, sourceID)
		}
		_, _ = pool.Exec(cleanup,
			`DELETE FROM identity_sources WHERE source_key=$1`, sourceKey)
		_, _ = pool.Exec(cleanup, `DELETE FROM mailboxes WHERE id=$1`, mailboxID)
		_, _ = pool.Exec(cleanup, `DELETE FROM users WHERE id=$1`, actorID)
	})

	h := NewIdentityHandler(pool, pool, testsupport.TestLogger())
	h.SetSourceSecretCodec(testConfigSecretCodec(t))
	actorRequest := func(method, target, body string) *http.Request {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		return req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
			UserID:            actorID,
			IsAdmin:           true,
			Permissions:       permissions.AllPermissions,
			GlobalPermissions: permissions.AllPermissions,
		}))
	}
	document := func(displayName string) string {
		return `{"apiVersion":"setjoin.io/v1","kind":"IdentitySource",` +
			`"metadata":{"sourceKey":"` + sourceKey + `","displayName":"` + displayName + `"},` +
			`"spec":{"type":"oidc","providerKey":"` + sourceKey + `",` +
			`"issuer":"https://idp.example.test","clientId":"setjoin",` +
			`"subjectClaim":"sub"}}`
	}
	call := func(
		handler func(http.ResponseWriter, *http.Request),
		req *http.Request,
		want int,
	) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Code != want {
			t.Fatalf("%s %s: status=%d want=%d body=%s",
				req.Method, req.URL.Path, rec.Code, want, rec.Body.String())
		}
		return rec
	}
	generation := func(rec *httptest.ResponseRecorder) string {
		t.Helper()
		var result struct {
			Generation string `json:"generation"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil ||
			result.Generation == "" {
			t.Fatalf("decode generation: %v body=%s", err, rec.Body.String())
		}
		return result.Generation
	}
	mutation := func(
		handler func(http.ResponseWriter, *http.Request),
		path, body, expected string,
	) string {
		t.Helper()
		key := uuid.NewString()
		body = strings.ReplaceAll(body, "$KEY", key)
		req := actorRequest(http.MethodPost, path, body)
		req.SetPathValue("sourceKey", sourceKey)
		req.Header.Set("Idempotency-Key", key)
		req.Header.Set("X-Audit-Reason", "identity source lifecycle test")
		if expected != "" {
			req.Header.Set("If-Match", `"`+expected+`"`)
		}
		return generation(call(handler, req, http.StatusAccepted))
	}

	call(h.IdentitySourcePlan,
		actorRequest(http.MethodPost, "/admin/identity/v2/sources:plan", document("OIDC source")),
		http.StatusOK)

	applyKey := uuid.NewString()
	applyBody := `{"document":` + document("OIDC source") +
		`,"reason":"identity source lifecycle test","idempotencyKey":"` + applyKey + `"}`
	applyReq := actorRequest(http.MethodPost, "/admin/identity/v2/sources:apply", applyBody)
	applyReq.Header.Set("Idempotency-Key", applyKey)
	applyReq.Header.Set("X-Audit-Reason", "identity source lifecycle test")
	current := generation(call(h.IdentitySourceApply, applyReq, http.StatusCreated))

	for _, handler := range []func(http.ResponseWriter, *http.Request){
		h.IdentitySourceDetail,
		h.IdentitySourceExport,
	} {
		req := actorRequest(http.MethodGet, "/admin/identity/v2/sources/"+sourceKey, "")
		req.SetPathValue("sourceKey", sourceKey)
		rec := call(handler, req, http.StatusOK)
		if strings.Contains(rec.Body.String(), "client-secret-value") {
			t.Fatal("source detail or export leaked plaintext secret")
		}
	}
	missingDetail := actorRequest(http.MethodGet,
		"/admin/identity/v2/sources/missing-"+suffix, "")
	missingDetail.SetPathValue("sourceKey", "missing-"+suffix)
	call(h.IdentitySourceDetail, missingDetail, http.StatusNotFound)

	unconfiguredDryRunKey := uuid.NewString()
	unconfiguredDryRun := actorRequest(http.MethodPost,
		"/admin/identity/v2/sources/"+sourceKey+":dry-run",
		`{"expectedGeneration":"`+current+`","idempotencyKey":"`+
			unconfiguredDryRunKey+
			`","reason":"identity source lifecycle test"}`)
	unconfiguredDryRun.SetPathValue("sourceKey", sourceKey)
	unconfiguredDryRun.Header.Set("Idempotency-Key", unconfiguredDryRunKey)
	unconfiguredDryRun.Header.Set("If-Match", `"`+current+`"`)
	unconfiguredDryRun.Header.Set("X-Audit-Reason",
		"identity source lifecycle test")
	unconfiguredDryRunRec := call(h.IdentitySourceDryRun,
		unconfiguredDryRun, http.StatusOK)
	if !strings.Contains(unconfiguredDryRunRec.Body.String(), `"valid":false`) ||
		!strings.Contains(unconfiguredDryRunRec.Body.String(), "secret_missing:clientSecret") {
		t.Fatalf("unconfigured dry-run did not expose bounded blocker: %s",
			unconfiguredDryRunRec.Body.String())
	}

	secretRequest := func(
		handler func(http.ResponseWriter, *http.Request),
		name, expected, key, reasonHeader, identityReason, secret string,
		want int,
	) {
		t.Helper()
		req := actorRequest(http.MethodPut,
			"/admin/identity/v2/sources/"+sourceKey+"/secrets/"+name, secret)
		req.SetPathValue("sourceKey", sourceKey)
		req.SetPathValue("name", name)
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Idempotency-Key", key)
		req.Header.Set("If-Match", `"`+expected+`"`)
		req.Header.Set("X-Audit-Reason", reasonHeader)
		req.Header.Set("X-Identity-Reason", identityReason)
		call(handler, req, want)
	}
	secretRequest(h.IdentitySourceRotateSecret, "clientSecret", current,
		uuid.NewString(), "identity source lifecycle test",
		"identity source lifecycle test", "not-configured", http.StatusConflict)
	secretRequest(h.IdentitySourceSetSecret, "unknownSecret", current,
		uuid.NewString(), "identity source lifecycle test",
		"identity source lifecycle test", "secret", http.StatusBadRequest)
	secretRequest(h.IdentitySourceSetSecret, "clientSecret", "999",
		uuid.NewString(), "identity source lifecycle test",
		"identity source lifecycle test", "secret", http.StatusPreconditionFailed)
	secretRequest(h.IdentitySourceSetSecret, "clientSecret", current,
		"bad", "identity source lifecycle test",
		"identity source lifecycle test", "secret", http.StatusBadRequest)
	secretRequest(h.IdentitySourceSetSecret, "clientSecret", current,
		uuid.NewString(), "different reason",
		"identity source lifecycle test", "secret", http.StatusBadRequest)
	secretRequest(h.IdentitySourceSetSecret, "clientSecret", current,
		uuid.NewString(), "identity source lifecycle test",
		"identity source lifecycle test", "", http.StatusBadRequest)
	secretRequest(h.IdentitySourceSetSecret, "clientSecret", current,
		uuid.NewString(), "identity source lifecycle test",
		"identity source lifecycle test",
		strings.Repeat("s", identitySecretMaxBytes+1), http.StatusRequestEntityTooLarge)

	setSecret := func(handler func(http.ResponseWriter, *http.Request), expected, secret string) string {
		t.Helper()
		req := actorRequest(http.MethodPut,
			"/admin/identity/v2/sources/"+sourceKey+"/secrets/clientSecret", secret)
		req.SetPathValue("sourceKey", sourceKey)
		req.SetPathValue("name", "clientSecret")
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Idempotency-Key", uuid.NewString())
		req.Header.Set("If-Match", `"`+expected+`"`)
		req.Header.Set("X-Audit-Reason", "identity source lifecycle test")
		req.Header.Set("X-Identity-Reason", "identity source lifecycle test")
		return generation(call(handler, req, http.StatusAccepted))
	}
	current = setSecret(h.IdentitySourceSetSecret, current, "client-secret-value")
	current = setSecret(h.IdentitySourceRotateSecret, current, "rotated-client-secret")

	call(h.IdentitySourcePlan,
		actorRequest(http.MethodPost, "/admin/identity/v2/sources:plan", document("OIDC source")),
		http.StatusOK)

	updateKey := uuid.NewString()
	updateBody := `{"document":` + document("OIDC source updated") +
		`,"reason":"identity source lifecycle test","idempotencyKey":"` + updateKey + `"}`
	updateReq := actorRequest(http.MethodPost,
		"/admin/identity/v2/sources/"+sourceKey+":apply", updateBody)
	updateReq.SetPathValue("sourceKey", sourceKey)
	updateReq.Header.Set("Idempotency-Key", updateKey)
	updateReq.Header.Set("If-Match", `"`+current+`"`)
	updateReq.Header.Set("X-Audit-Reason", "identity source lifecycle test")
	current = generation(call(h.IdentitySourceApply, updateReq, http.StatusOK))

	lifecycleBody := func(expected string) string {
		return `{"expectedGeneration":"` + expected +
			`","idempotencyKey":"$KEY","reason":"identity source lifecycle test"}`
	}
	missingDryRunKey := uuid.NewString()
	missingDryRun := actorRequest(http.MethodPost,
		"/admin/identity/v2/sources/missing-"+suffix+":dry-run",
		strings.ReplaceAll(lifecycleBody(current), "$KEY", missingDryRunKey))
	missingDryRun.SetPathValue("sourceKey", "missing-"+suffix)
	missingDryRun.Header.Set("Idempotency-Key", missingDryRunKey)
	missingDryRun.Header.Set("If-Match", `"`+current+`"`)
	missingDryRun.Header.Set("X-Audit-Reason", "identity source lifecycle test")
	call(h.IdentitySourceDryRun, missingDryRun, http.StatusNotFound)
	staleDryRunKey := uuid.NewString()
	staleDryRun := actorRequest(http.MethodPost,
		"/admin/identity/v2/sources/"+sourceKey+":dry-run",
		strings.ReplaceAll(lifecycleBody("999"), "$KEY", staleDryRunKey))
	staleDryRun.SetPathValue("sourceKey", sourceKey)
	staleDryRun.Header.Set("Idempotency-Key", staleDryRunKey)
	staleDryRun.Header.Set("If-Match", `"999"`)
	staleDryRun.Header.Set("X-Audit-Reason", "identity source lifecycle test")
	call(h.IdentitySourceDryRun, staleDryRun, http.StatusPreconditionFailed)
	current = mutation(h.IdentitySourceDryRun,
		"/admin/identity/v2/sources/"+sourceKey+":dry-run",
		lifecycleBody(current), current)
	current = mutation(h.IdentitySourceActivate,
		"/admin/identity/v2/sources/"+sourceKey+":activate",
		lifecycleBody(current), current)
	current = mutation(h.IdentitySourcePause,
		"/admin/identity/v2/sources/"+sourceKey+":pause",
		lifecycleBody(current), current)
	current = mutation(h.IdentitySourceResume,
		"/admin/identity/v2/sources/"+sourceKey+":resume",
		lifecycleBody(current), current)
	illegalKey := uuid.NewString()
	illegalRetire := actorRequest(http.MethodPost,
		"/admin/identity/v2/sources/"+sourceKey+":retire",
		strings.ReplaceAll(lifecycleBody(current), "$KEY", illegalKey))
	illegalRetire.SetPathValue("sourceKey", sourceKey)
	illegalRetire.Header.Set("Idempotency-Key", illegalKey)
	illegalRetire.Header.Set("If-Match", `"`+current+`"`)
	illegalRetire.Header.Set("X-Audit-Reason", "identity source lifecycle test")
	call(h.IdentitySourceRetire, illegalRetire, http.StatusConflict)
	current = mutation(h.IdentitySourcePause,
		"/admin/identity/v2/sources/"+sourceKey+":pause",
		lifecycleBody(current), current)
	_ = mutation(h.IdentitySourceRetire,
		"/admin/identity/v2/sources/"+sourceKey+":retire",
		lifecycleBody(current), current)

	actionReq := actorRequest(http.MethodPost,
		"/admin/identity/v2/sources/"+sourceKey+":unknown", `{}`)
	actionReq.SetPathValue("action", "unknown")
	call(h.IdentitySourceLifecycle, actionReq, http.StatusNotFound)
}
