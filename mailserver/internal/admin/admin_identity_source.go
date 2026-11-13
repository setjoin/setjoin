package admin

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/ad"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/ldapsync"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/reducererr"
)

const (
	identitySourceAPIVersion = "setjoin.io/v1"
	identitySourceKind       = "IdentitySource"
	identitySecretMaxBytes   = 64 << 10
)

type identitySourceDocument struct {
	APIVersion string                 `json:"apiVersion"`
	Kind       string                 `json:"kind"`
	Metadata   identitySourceMetadata `json:"metadata"`
	Spec       json.RawMessage        `json:"spec"`
}

type identitySourceMetadata struct {
	SourceKey   string `json:"sourceKey"`
	DisplayName string `json:"displayName"`
}

type identityStoredSourceDocument struct {
	Document json.RawMessage   `json:"document"`
	Secrets  map[string]string `json:"secrets"`
}

type identitySourceRow struct {
	ID               int64
	SourceKey        string
	DisplayName      string
	Kind             string
	State            string
	Generation       int64
	MappingVersion   int64
	ConfigKeyVersion int64
	ConfigEnvelope   []byte
	Capabilities     json.RawMessage
	LastSuccessAt    *time.Time
	LastFailureAt    *time.Time
	LastErrorCode    *string
}

type identitySourceApplyRequest struct {
	Document       json.RawMessage `json:"document"`
	Reason         string          `json:"reason"`
	IdempotencyKey string          `json:"idempotencyKey,omitempty"`
}

type identitySourceLifecycleRequest struct {
	ExpectedGeneration string `json:"expectedGeneration"`
	IdempotencyKey     string `json:"idempotencyKey"`
	Reason             string `json:"reason"`
}

type identitySourcePlan struct {
	SourceKey         string          `json:"sourceKey"`
	Create            bool            `json:"create"`
	Changed           bool            `json:"changed"`
	CurrentGeneration *string         `json:"currentGeneration,omitempty"`
	Desired           json.RawMessage `json:"desired"`
	Operations        []string        `json:"operations"`
}

var identitySourceSpecFields = map[string]map[string]struct{}{
	"local": stringSet("type", "capabilities", "passwordPolicy", "passkeyPolicy", "mfaPolicy"),
	"ad": stringSet("type", "capabilities", "endpoint", "subjectAttribute", "baseDN", "bindDN",
		"userFilter", "groupFilter", "mapping", "deletionPolicy"),
	"ldap": stringSet("type", "capabilities", "endpoint", "subjectAttribute", "baseDN", "bindDN",
		"userFilter", "groupFilter", "mapping", "deletionPolicy"),
	"scim": stringSet("type", "capabilities", "deletionPolicy", "mapping", "tokenLabel", "tokenExpiry"),
	"saml": stringSet("type", "capabilities", "registrationKey", "idpEntityId", "metadataUrl",
		"ssoUrl", "certificateRef", "spEntityId", "persistentNameId", "attributeMapping",
		"groupMapping", "jitPolicy"),
	"oidc": stringSet("type", "capabilities", "providerKey", "issuer", "clientId", "redirectUri",
		"scopes", "claimMapping", "subjectClaim", "jitPolicy"),
}

var identitySourceSecretCatalog = map[string][]string{
	"local": {},
	"ad":    {"bindPassword"},
	"ldap":  {"bindPassword"},
	"scim":  {"bearerToken"},
	"saml":  {"metadataClientSecret"},
	"oidc":  {"clientSecret"},
}

func stringSet(values ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}

func decodeStrictJSON(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON value")
	}
	return nil
}

func validateIdentitySourceDocument(raw json.RawMessage) (identitySourceDocument, json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > identityBodyMaxBytes {
		return identitySourceDocument{}, nil, errors.New("identity source document must be 1..65536 bytes")
	}
	var document identitySourceDocument
	if err := decodeStrictJSON(raw, &document); err != nil {
		return identitySourceDocument{}, nil, fmt.Errorf("invalid identity source document: %w", err)
	}
	if document.APIVersion != identitySourceAPIVersion || document.Kind != identitySourceKind {
		return identitySourceDocument{}, nil, errors.New("unsupported identity source apiVersion or kind")
	}
	if !validIdentitySourceKey(document.Metadata.SourceKey) ||
		!boundedIdentityText(document.Metadata.DisplayName, 128) {
		return identitySourceDocument{}, nil, errors.New("invalid identity source metadata")
	}
	var spec map[string]json.RawMessage
	if err := decodeStrictJSON(document.Spec, &spec); err != nil || spec == nil {
		return identitySourceDocument{}, nil, errors.New("identity source spec must be an object")
	}
	var sourceType string
	if err := json.Unmarshal(spec["type"], &sourceType); err != nil {
		return identitySourceDocument{}, nil, errors.New("identity source spec.type is required")
	}
	allowed, ok := identitySourceSpecFields[sourceType]
	if !ok {
		return identitySourceDocument{}, nil, errors.New("unsupported identity source type")
	}
	for key := range spec {
		if _, allowedField := allowed[key]; !allowedField {
			return identitySourceDocument{}, nil, fmt.Errorf("unsupported identity source spec field %q", key)
		}
	}
	if err := validateIdentitySourceKindSpec(sourceType, spec); err != nil {
		return identitySourceDocument{}, nil, err
	}
	canonical, err := json.Marshal(document)
	if err != nil {
		return identitySourceDocument{}, nil, errors.New("canonicalize identity source document")
	}
	return document, canonical, nil
}

func validateIdentitySourceKindSpec(sourceType string, spec map[string]json.RawMessage) error {
	requireText := func(name string, max int) (string, error) {
		var value string
		if err := json.Unmarshal(spec[name], &value); err != nil || !boundedIdentityText(value, max) {
			return "", fmt.Errorf("identity source spec.%s is required and must be bounded text", name)
		}
		return value, nil
	}
	switch sourceType {
	case "ad", "ldap":
		if _, err := requireText("baseDN", 2048); err != nil {
			return err
		}
		subject, err := requireText("subjectAttribute", 128)
		if err != nil {
			return err
		}
		if sourceType == "ad" && subject != "objectGUID" && subject != "msDS-ConsistencyGuid" {
			return errors.New("AD subjectAttribute must be objectGUID or msDS-ConsistencyGuid")
		}
		if err := validateIdentityEndpoint(spec["endpoint"]); err != nil {
			return err
		}
	case "scim":
		// The SCIM endpoint is server-generated. No remote endpoint is accepted.
	case "saml":
		if _, err := requireText("registrationKey", 255); err != nil {
			return err
		}
		if _, err := requireText("idpEntityId", 2048); err != nil {
			return err
		}
	case "oidc":
		if _, err := requireText("providerKey", 255); err != nil {
			return err
		}
		if _, err := requireText("issuer", 2048); err != nil {
			return err
		}
		if _, err := requireText("clientId", 1024); err != nil {
			return err
		}
		var subject string
		if err := json.Unmarshal(spec["subjectClaim"], &subject); err != nil || subject != "sub" {
			return errors.New("OIDC subjectClaim must be sub")
		}
	}
	if raw, present := spec["capabilities"]; present {
		var capabilities map[string]json.RawMessage
		if err := json.Unmarshal(raw, &capabilities); err != nil || capabilities == nil {
			return errors.New("identity source capabilities must be an object")
		}
		allowed := stringSet("authenticate", "provisionLifecycle", "passwordWriteback",
			"profileFields", "entitlements", "deltaCursor", "suspendDelete", "immutableSubject")
		for key := range capabilities {
			if _, ok := allowed[key]; !ok {
				return fmt.Errorf("unsupported identity source capability %q", key)
			}
		}
	}
	return nil
}

func validateIdentityEndpoint(raw json.RawMessage) error {
	var endpoint struct {
		Host string `json:"host"`
		Port int    `json:"port"`
		TLS  string `json:"tls"`
	}
	if err := decodeStrictJSON(raw, &endpoint); err != nil ||
		!boundedIdentityText(endpoint.Host, 253) || endpoint.Port < 1 || endpoint.Port > 65535 ||
		(endpoint.TLS != "ldaps" && endpoint.TLS != "starttls") {
		return errors.New("identity source endpoint requires bounded host, port, and tls")
	}
	return nil
}

func boundedIdentityText(value string, max int) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > max {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func identitySourceCapabilities(sourceType string) json.RawMessage {
	authn := sourceType == "local" || sourceType == "saml" || sourceType == "oidc"
	provision := sourceType == "local" || sourceType == "ad" ||
		sourceType == "ldap" || sourceType == "scim"
	raw, _ := json.Marshal(map[string]bool{
		"authenticate":             authn,
		"provision_lifecycle":      provision,
		"stable_immutable_subject": true,
	})
	return raw
}

func (h *IdentityHandler) loadIdentitySource(ctx context.Context, key string) (identitySourceRow, error) {
	var row identitySourceRow
	err := h.workerPool.QueryRow(ctx, `
		SELECT id,source_key,display_name,kind,state,generation,mapping_version,
		       config_key_version,config_envelope,capabilities,
		       last_success_at,last_failure_at,last_error_code
		  FROM identity_sources WHERE source_key=$1`,
		key).Scan(&row.ID, &row.SourceKey, &row.DisplayName, &row.Kind, &row.State,
		&row.Generation, &row.MappingVersion, &row.ConfigKeyVersion,
		&row.ConfigEnvelope, &row.Capabilities, &row.LastSuccessAt,
		&row.LastFailureAt, &row.LastErrorCode)
	return row, err
}

func (h *IdentityHandler) decodeStoredIdentitySource(row identitySourceRow) (identityStoredSourceDocument, error) {
	if h.sourceSecrets == nil {
		return identityStoredSourceDocument{}, errors.New("identity source secret codec is unavailable")
	}
	if len(row.ConfigEnvelope) == 0 {
		return identityStoredSourceDocument{Secrets: map[string]string{}}, nil
	}
	plain, err := h.sourceSecrets.Decrypt("identity_source."+row.SourceKey, row.ConfigEnvelope)
	if err != nil {
		return identityStoredSourceDocument{}, err
	}
	var stored identityStoredSourceDocument
	if err := decodeStrictJSON(plain, &stored); err != nil {
		return identityStoredSourceDocument{}, err
	}
	if stored.Secrets == nil {
		stored.Secrets = map[string]string{}
	}
	return stored, nil
}

func (h *IdentityHandler) encryptStoredIdentitySource(
	key string,
	document json.RawMessage,
	secrets map[string]string,
) ([]byte, int64, error) {
	if h.sourceSecrets == nil || h.sourceSecrets.ActiveVersion() == 0 {
		return nil, 0, errors.New("identity source secret codec is unavailable")
	}
	plain, err := json.Marshal(identityStoredSourceDocument{Document: document, Secrets: secrets})
	if err != nil {
		return nil, 0, err
	}
	envelope, err := h.sourceSecrets.Encrypt("identity_source."+key, plain)
	return envelope, int64(h.sourceSecrets.ActiveVersion()), err
}

func identitySourceSecretPosture(kind string, secrets map[string]string) map[string]bool {
	out := make(map[string]bool)
	for _, name := range identitySourceSecretCatalog[kind] {
		out[name] = secrets[name] != ""
	}
	return out
}

func identityMutationHeaders(w http.ResponseWriter, r *http.Request, bodyKey string) (uuid.UUID, bool) {
	headerKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if bodyKey == "" || headerKey == "" || bodyKey != headerKey {
		httputil.WriteProblemStatus(w, http.StatusBadRequest,
			"body idempotencyKey must exactly match Idempotency-Key")
		return uuid.Nil, false
	}
	key, err := uuid.Parse(bodyKey)
	if err != nil || key == uuid.Nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid Idempotency-Key")
		return uuid.Nil, false
	}
	return key, true
}

func identityExpectedGeneration(w http.ResponseWriter, r *http.Request, body string) (int64, bool) {
	value, err := strconv.ParseInt(body, 10, 64)
	if err != nil || value <= 0 {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid expectedGeneration")
		return 0, false
	}
	header := strings.TrimSpace(r.Header.Get("If-Match"))
	if header != `"`+body+`"` {
		httputil.WriteProblemStatus(w, http.StatusPreconditionFailed,
			"If-Match must be the strong current generation ETag")
		return 0, false
	}
	return value, true
}

// IdentitySourcePlan validates and canonicalizes a source document without
// network access or writes, then returns a server-computed diff.
func (h *IdentityHandler) IdentitySourcePlan(w http.ResponseWriter, r *http.Request) {
	var documentRaw json.RawMessage
	if !decodeIdentityJSON(w, r, &documentRaw, "invalid identity source document") {
		return
	}
	document, canonical, err := validateIdentitySourceDocument(documentRaw)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, err.Error())
		return
	}
	if !requireUnscopedIdentityAdmin(w, r) || !h.requireIdentityWorker(w) {
		return
	}
	row, err := h.loadIdentitySource(r.Context(), document.Metadata.SourceKey)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "identity source plan failed")
		return
	}
	plan := identitySourcePlan{
		SourceKey: document.Metadata.SourceKey, Create: errors.Is(err, pgx.ErrNoRows),
		Desired: canonical, Operations: []string{},
	}
	if plan.Create {
		plan.Changed = true
		plan.Operations = []string{"create_draft"}
	} else {
		generation := strconv.FormatInt(row.Generation, 10)
		plan.CurrentGeneration = &generation
		stored, decodeErr := h.decodeStoredIdentitySource(row)
		if decodeErr != nil {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError,
				"identity source stored document cannot be decrypted")
			return
		}
		plan.Changed = !bytes.Equal(stored.Document, canonical)
		if plan.Changed {
			plan.Operations = []string{"update_draft_config", "increment_generation"}
		}
	}
	writeIdentityJSON(w, r, http.StatusOK, plan)
}

// IdentitySourceApply creates or updates only a draft source. It preserves any
// configured secret values inside the newly encrypted envelope.
func (h *IdentityHandler) IdentitySourceApply(w http.ResponseWriter, r *http.Request) {
	var req identitySourceApplyRequest
	if !decodeIdentityJSON(w, r, &req, "invalid identity source apply request") {
		return
	}
	document, canonical, err := validateIdentitySourceDocument(req.Document)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, err.Error())
		return
	}
	if pathKey := r.PathValue("sourceKey"); pathKey != "" &&
		pathKey != document.Metadata.SourceKey {
		httputil.WriteProblemStatus(w, http.StatusBadRequest,
			"path sourceKey must match document metadata.sourceKey")
		return
	}
	idempotency, ok := identityMutationHeaders(w, r, req.IdempotencyKey)
	if !ok || !identityReasonMatches(w, r, req.Reason) ||
		!requireUnscopedIdentityAdmin(w, r) || !h.requireIdentityWorker(w) {
		return
	}
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	var expected *int64
	var secrets = map[string]string{}
	status := http.StatusCreated
	row, loadErr := h.loadIdentitySource(r.Context(), document.Metadata.SourceKey)
	if loadErr == nil {
		value, matched := identityExpectedGeneration(
			w, r, strconv.FormatInt(row.Generation, 10))
		if !matched {
			return
		}
		expected = &value
		stored, decodeErr := h.decodeStoredIdentitySource(row)
		if decodeErr != nil {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError,
				"identity source stored document cannot be decrypted")
			return
		}
		secrets = stored.Secrets
		status = http.StatusOK
	} else if !errors.Is(loadErr, pgx.ErrNoRows) {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "identity source lookup failed")
		return
	} else if strings.TrimSpace(r.Header.Get("If-Match")) != "" {
		httputil.WriteProblemStatus(w, http.StatusPreconditionFailed,
			"new identity source must not send If-Match")
		return
	}
	envelope, keyVersion, err := h.encryptStoredIdentitySource(
		document.Metadata.SourceKey, canonical, secrets)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusServiceUnavailable,
			"identity source encryption is unavailable")
		return
	}
	var raw json.RawMessage
	err = h.workerPool.QueryRow(r.Context(),
		`SELECT identity_source_config_apply($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		claims.UserID, document.Metadata.SourceKey, document.Metadata.DisplayName,
		identityDocumentType(document.Spec), identitySourceCapabilities(identityDocumentType(document.Spec)),
		envelope, keyVersion, int64(1), expected, idempotency, req.Reason).Scan(&raw)
	if err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "identity source apply failed")
		}
		return
	}
	var result struct {
		Generation string `json:"generation"`
	}
	if json.Unmarshal(raw, &result) != nil || result.Generation == "" {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"identity source apply returned invalid result")
		return
	}
	writeIdentityRawJSON(w, r, status, raw, result.Generation)
}

func identityDocumentType(spec json.RawMessage) string {
	var value struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(spec, &value)
	return value.Type
}

// IdentitySourceDetail returns the canonical secret-free source document and
// named configured posture. Ciphertext and secret values are never serialized.
func (h *IdentityHandler) IdentitySourceDetail(w http.ResponseWriter, r *http.Request) {
	if !requireUnscopedIdentityAdmin(w, r, permissions.PermUsersRead) ||
		!h.requireIdentityWorker(w) {
		return
	}
	key := r.PathValue("sourceKey")
	if !validIdentitySourceKey(key) {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid identity source key")
		return
	}
	row, err := h.loadIdentitySource(r.Context(), key)
	if errors.Is(err, pgx.ErrNoRows) {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "identity source not found")
		return
	}
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "identity source lookup failed")
		return
	}
	stored, err := h.decodeStoredIdentitySource(row)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"identity source stored document cannot be decrypted")
		return
	}
	response := map[string]any{
		"sourceKey": key, "displayName": row.DisplayName, "kind": row.Kind,
		"state": row.State, "generation": strconv.FormatInt(row.Generation, 10),
		"mappingVersion": strconv.FormatInt(row.MappingVersion, 10),
		"capabilities":   row.Capabilities, "document": stored.Document,
		"secretConfigured": identitySourceSecretPosture(row.Kind, stored.Secrets),
		"lastSuccessAt":    row.LastSuccessAt, "lastFailureAt": row.LastFailureAt,
		"lastErrorCode": row.LastErrorCode,
	}
	writeIdentityJSON(w, r, http.StatusOK, response)
}

// IdentitySourceExport is the round-trippable canonical document plus boolean
// secret posture; it shares the same non-secret representation as detail.
func (h *IdentityHandler) IdentitySourceExport(w http.ResponseWriter, r *http.Request) {
	h.IdentitySourceDetail(w, r)
}

func (h *IdentityHandler) identitySourceSecret(w http.ResponseWriter, r *http.Request, rotate bool) {
	if !requireUnscopedIdentityAdmin(w, r) || !h.requireIdentityWorker(w) {
		return
	}
	mediaType, _, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/octet-stream" {
		httputil.WriteProblemStatus(w, http.StatusUnsupportedMediaType,
			"identity source secrets require application/octet-stream")
		return
	}
	key, name := r.PathValue("sourceKey"), r.PathValue("name")
	if !validIdentitySourceKey(key) || !boundedIdentityText(name, 64) {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid identity source secret path")
		return
	}
	row, err := h.loadIdentitySource(r.Context(), key)
	if errors.Is(err, pgx.ErrNoRows) {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "identity source not found")
		return
	}
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "identity source lookup failed")
		return
	}
	if !identitySecretNameAllowed(row.Kind, name) {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "secret name is not valid for this source kind")
		return
	}
	expected, ok := identityExpectedGeneration(w, r, strconv.FormatInt(row.Generation, 10))
	if !ok {
		return
	}
	idempotencyRaw := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	idempotency, parseErr := uuid.Parse(idempotencyRaw)
	if parseErr != nil || idempotency == uuid.Nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid Idempotency-Key")
		return
	}
	reason := r.Header.Get("X-Identity-Reason")
	if !identityReasonMatches(w, r, reason) {
		return
	}
	secret, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, identitySecretMaxBytes))
	if readErr != nil {
		var maxErr *http.MaxBytesError
		if errors.As(readErr, &maxErr) {
			httputil.WriteProblemStatus(w, http.StatusRequestEntityTooLarge,
				"identity source secret exceeds 65536 bytes")
		} else {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "identity source secret could not be read")
		}
		return
	}
	defer clear(secret)
	if len(secret) == 0 {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "identity source secret must be non-empty")
		return
	}
	stored, err := h.decodeStoredIdentitySource(row)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"identity source stored document cannot be decrypted")
		return
	}
	if rotate && stored.Secrets[name] == "" {
		httputil.WriteProblemStatus(w, http.StatusConflict,
			"cannot rotate an identity source secret that is not configured")
		return
	}
	stored.Secrets[name] = base64.StdEncoding.EncodeToString(secret)
	envelope, keyVersion, err := h.encryptStoredIdentitySource(key, stored.Document, stored.Secrets)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusServiceUnavailable,
			"identity source encryption is unavailable")
		return
	}
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	graceSeconds := 0
	if rotate {
		graceSeconds = 3600
	}
	var raw json.RawMessage
	err = h.workerPool.QueryRow(r.Context(),
		`SELECT identity_source_secret_set($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		claims.UserID, key, name, envelope, keyVersion, expected, rotate,
		graceSeconds, idempotency, reason).Scan(&raw)
	if err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError,
				"identity source secret update failed")
		}
		return
	}
	var result struct {
		Generation string `json:"generation"`
	}
	if json.Unmarshal(raw, &result) != nil || result.Generation == "" {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"identity source secret update returned invalid result")
		return
	}
	writeIdentityRawJSON(w, r, http.StatusAccepted, raw, result.Generation)
}

func identitySecretNameAllowed(kind, name string) bool {
	for _, allowed := range identitySourceSecretCatalog[kind] {
		if name == allowed {
			return true
		}
	}
	return false
}

func (h *IdentityHandler) IdentitySourceSetSecret(w http.ResponseWriter, r *http.Request) {
	h.identitySourceSecret(w, r, false)
}

func (h *IdentityHandler) IdentitySourceRotateSecret(w http.ResponseWriter, r *http.Request) {
	h.identitySourceSecret(w, r, true)
}

func (h *IdentityHandler) IdentitySourceLifecycle(w http.ResponseWriter, r *http.Request) {
	action := r.PathValue("action")
	if action != "activate" && action != "pause" && action != "resume" && action != "retire" {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "identity source action not found")
		return
	}
	h.identitySourceLifecycle(w, r, action, nil)
}

func (h *IdentityHandler) IdentitySourceActivate(w http.ResponseWriter, r *http.Request) {
	h.identitySourceLifecycle(w, r, "activate", nil)
}

func (h *IdentityHandler) IdentitySourcePause(w http.ResponseWriter, r *http.Request) {
	h.identitySourceLifecycle(w, r, "pause", nil)
}

func (h *IdentityHandler) IdentitySourceResume(w http.ResponseWriter, r *http.Request) {
	h.identitySourceLifecycle(w, r, "resume", nil)
}

func (h *IdentityHandler) IdentitySourceRetire(w http.ResponseWriter, r *http.Request) {
	h.identitySourceLifecycle(w, r, "retire", nil)
}

func (h *IdentityHandler) identitySourceLifecycle(
	w http.ResponseWriter,
	r *http.Request,
	action string,
	extra map[string]any,
) {
	var req identitySourceLifecycleRequest
	if !decodeIdentityJSON(w, r, &req, "invalid identity source lifecycle request") {
		return
	}
	expected, ok := identityExpectedGeneration(w, r, req.ExpectedGeneration)
	if !ok {
		return
	}
	idempotency, ok := identityMutationHeaders(w, r, req.IdempotencyKey)
	if !ok || !identityReasonMatches(w, r, req.Reason) ||
		!requireUnscopedIdentityAdmin(w, r) || !h.requireIdentityWorker(w) {
		return
	}
	key := r.PathValue("sourceKey")
	if !validIdentitySourceKey(key) {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid identity source key")
		return
	}
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	var raw json.RawMessage
	err := h.workerPool.QueryRow(r.Context(),
		`SELECT identity_source_lifecycle($1,$2,$3,$4,$5,$6)`,
		claims.UserID, key, action, expected, idempotency, req.Reason).Scan(&raw)
	if err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError,
				"identity source lifecycle failed")
		}
		return
	}
	if extra != nil {
		var value map[string]any
		if json.Unmarshal(raw, &value) == nil {
			for key, item := range extra {
				value[key] = item
			}
			raw, _ = json.Marshal(value)
		}
	}
	var result struct {
		Generation string `json:"generation"`
	}
	if json.Unmarshal(raw, &result) != nil || result.Generation == "" {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"identity source lifecycle returned invalid result")
		return
	}
	w.Header().Set("Location", "/api/admin/identity/v2/sources/"+key)
	writeIdentityRawJSON(w, r, http.StatusAccepted, raw, result.Generation)
}

// IdentitySourceDryRun performs bounded schema, credential-posture, and AD/LDAP
// transport checks without any person write. On success it records the source
// as validated through the lifecycle reducer.
func (h *IdentityHandler) IdentitySourceDryRun(w http.ResponseWriter, r *http.Request) {
	if !requireUnscopedIdentityAdmin(w, r) || !h.requireIdentityWorker(w) {
		return
	}
	var req identitySourceLifecycleRequest
	if !decodeIdentityJSON(w, r, &req, "invalid identity source dry-run request") {
		return
	}
	expected, ok := identityExpectedGeneration(w, r, req.ExpectedGeneration)
	if !ok {
		return
	}
	if _, ok := identityMutationHeaders(w, r, req.IdempotencyKey); !ok ||
		!identityReasonMatches(w, r, req.Reason) {
		return
	}
	reqRaw, _ := json.Marshal(req)
	r.Body = io.NopCloser(bytes.NewReader(reqRaw))
	key := r.PathValue("sourceKey")
	row, err := h.loadIdentitySource(r.Context(), key)
	if errors.Is(err, pgx.ErrNoRows) {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "identity source not found")
		return
	}
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "identity source lookup failed")
		return
	}
	if expected != row.Generation {
		httputil.WriteProblemStatus(w, http.StatusPreconditionFailed,
			"identity source generation is stale")
		return
	}
	stored, err := h.decodeStoredIdentitySource(row)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"identity source stored document cannot be decrypted")
		return
	}
	_, _, err = validateIdentitySourceDocument(stored.Document)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusConflict,
			"stored identity source document is invalid")
		return
	}
	posture := identitySourceSecretPosture(row.Kind, stored.Secrets)
	blockers := make([]string, 0)
	for name, configured := range posture {
		if !configured && (row.Kind == "ad" || row.Kind == "ldap" ||
			row.Kind == "scim" || row.Kind == "oidc") {
			blockers = append(blockers, "secret_missing:"+name)
		}
	}
	transport := "not_required"
	if len(blockers) == 0 && (row.Kind == "ad" || row.Kind == "ldap") {
		runtimeConfig, decodeErr := DecodeIdentitySourceRuntime(
			h.sourceSecrets, key, row.Kind, row.ConfigEnvelope,
		)
		if decodeErr != nil {
			blockers = append(blockers, "runtime_configuration_invalid")
			transport = "failed"
		} else if probeErr := h.sourceProbe(r.Context(), runtimeConfig); probeErr != nil {
			blocker, reachable := identitySourceProbeBlocker(probeErr)
			blockers = append(blockers, blocker)
			if reachable {
				transport = "reachable"
			} else {
				transport = "failed"
			}
		} else {
			transport = "reachable"
		}
	}
	if len(blockers) != 0 {
		writeIdentityJSON(w, r, http.StatusOK, map[string]any{
			"sourceKey": key, "valid": false, "transport": transport,
			"personWrites": 0, "blockers": blockers, "secretConfigured": posture,
		})
		return
	}
	// The request body carries the same bounded mutation envelope as lifecycle.
	h.identitySourceLifecycle(w, r, "validate", map[string]any{
		"valid": true, "transport": transport, "personWrites": 0,
		"blockers": []string{}, "secretConfigured": posture,
	})
}

func probeIdentitySourceRuntime(
	ctx context.Context,
	cfg IdentitySourceRuntimeConfig,
	logger *slog.Logger,
) error {
	switch cfg.Kind {
	case "ad":
		client, err := ad.NewConfiguredClient(ad.ClientConfig{
			Host: cfg.Host, Port: cfg.Port, Transport: cfg.Transport,
			BaseDN: cfg.BaseDN, BindDN: cfg.BindDN, Password: cfg.BindPassword(),
			SubjectAttribute: cfg.SubjectAttribute, UserFilter: cfg.UserFilter,
		}, logger)
		if err != nil {
			return err
		}
		_, err = ad.NewSyncWorker(client, nil, logger, 15).DryRun(ctx)
		return err
	case "ldap":
		client, err := ldapsync.NewClientWithTransport(
			cfg.Host, cfg.Port, cfg.Transport, cfg.BindDN, cfg.BindPassword(), cfg.BaseDN,
		)
		if err != nil {
			return err
		}
		if err := client.SetSubjectAttribute(cfg.SubjectAttribute); err != nil {
			return err
		}
		worker := ldapsync.NewSyncWorker(client, nil, logger, 15)
		if err := worker.SetFilter(cfg.UserFilter); err != nil {
			return err
		}
		_, err = worker.DryRun(ctx, 5)
		return err
	default:
		return errors.New("identity source runtime probe does not support this kind")
	}
}

func identitySourceProbeBlocker(err error) (string, bool) {
	if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		return "credential_rejected", true
	}
	var connErr *ldapsync.ConnError
	if errors.As(err, &connErr) && connErr.Class == ldapsync.ConnClassBindAuth {
		return "credential_rejected", true
	}
	return "directory_probe_failed", false
}
