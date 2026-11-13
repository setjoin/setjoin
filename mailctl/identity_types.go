package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const identityListLimit = 200

type identitySourceList struct {
	Items []identitySource `json:"items"`
}

type identitySource struct {
	SourceKey      string          `json:"sourceKey"`
	DisplayName    string          `json:"displayName"`
	Kind           string          `json:"kind"`
	State          string          `json:"state"`
	Generation     string          `json:"generation"`
	MappingVersion string          `json:"mappingVersion,omitempty"`
	Capabilities   json.RawMessage `json:"capabilities"`
	LastSuccessAt  *string         `json:"lastSuccessAt,omitempty"`
	LastFailureAt  *string         `json:"lastFailureAt,omitempty"`
	LastErrorCode  *string         `json:"lastErrorCode,omitempty"`
	HasCursor      bool            `json:"hasCursor"`
	AttentionCount *int            `json:"attentionCount"`
}

type identitySourceDetail struct {
	SourceKey        string          `json:"sourceKey"`
	DisplayName      string          `json:"displayName"`
	Kind             string          `json:"kind"`
	State            string          `json:"state"`
	Generation       string          `json:"generation"`
	MappingVersion   string          `json:"mappingVersion"`
	Capabilities     json.RawMessage `json:"capabilities"`
	Document         json.RawMessage `json:"document"`
	SecretConfigured map[string]bool `json:"secretConfigured"`
	LastSuccessAt    *string         `json:"lastSuccessAt,omitempty"`
	LastFailureAt    *string         `json:"lastFailureAt,omitempty"`
	LastErrorCode    *string         `json:"lastErrorCode,omitempty"`
}

type identitySourcePlanResult struct {
	SourceKey         string          `json:"sourceKey"`
	Create            *bool           `json:"create"`
	Changed           *bool           `json:"changed"`
	CurrentGeneration *string         `json:"currentGeneration,omitempty"`
	Desired           json.RawMessage `json:"desired"`
	Operations        []string        `json:"operations"`
}

type identitySourceMutationResult struct {
	SourceID   string `json:"sourceId"`
	SourceKey  string `json:"sourceKey"`
	State      string `json:"state"`
	Generation string `json:"generation"`
	Replayed   *bool  `json:"replayed"`
	SecretName string `json:"secretName,omitempty"`
	// Secret mutation responses carry a boolean while dry-run responses carry
	// the closed, per-name posture map defined by OpenAPI. Keep the wire union
	// raw here and validate the exact arm from the other discriminator fields.
	SecretConfigured json.RawMessage `json:"secretConfigured,omitempty"`
	Valid            *bool           `json:"valid,omitempty"`
	Transport        string          `json:"transport,omitempty"`
	PersonWrites     *int            `json:"personWrites,omitempty"`
	Blockers         []string        `json:"blockers,omitempty"`
}

type identityPeopleList struct {
	Items []identityPerson `json:"items"`
}

type identityPerson struct {
	UserID             string  `json:"userId"`
	Email              string  `json:"email"`
	DisplayName        *string `json:"displayName,omitempty"`
	Enabled            *bool   `json:"enabled"`
	LifecycleAuthority string  `json:"lifecycleAuthority"`
	SourceKey          *string `json:"sourceKey,omitempty"`
	ActiveLinks        int     `json:"activeLinks"`
	DetachedLinks      int     `json:"detachedLinks"`
}

type identityPersonDetail struct {
	UserID             string  `json:"userId"`
	Email              string  `json:"email"`
	DisplayName        *string `json:"displayName"`
	Enabled            *bool   `json:"enabled"`
	Relationship       string  `json:"relationship"`
	Protected          *bool   `json:"protected"`
	LifecycleAuthority struct {
		Kind       string  `json:"kind"`
		Generation string  `json:"generation"`
		LinkID     *string `json:"linkId"`
		SourceKey  *string `json:"sourceKey"`
	} `json:"lifecycleAuthority"`
	Recovery struct {
		HasLocalPassword          *bool `json:"hasLocalPassword"`
		PasskeyCount              *int  `json:"passkeyCount"`
		ActiveAuthenticationLinks *int  `json:"activeAuthenticationLinks"`
	} `json:"recovery"`
	Links []struct {
		ID                 string   `json:"id"`
		SourceKey          string   `json:"sourceKey"`
		SourceKind         string   `json:"sourceKind"`
		Purposes           []string `json:"purposes"`
		State              string   `json:"state"`
		Generation         string   `json:"generation"`
		LinkMethod         string   `json:"linkMethod"`
		SubjectFingerprint string   `json:"subjectFingerprint"`
		FirstSeenAt        string   `json:"firstSeenAt"`
		LastSeenAt         string   `json:"lastSeenAt"`
		DetachedAt         *string  `json:"detachedAt"`
	} `json:"links"`
	FieldAuthority []struct {
		Field              string  `json:"field"`
		AuthorityKind      string  `json:"authorityKind"`
		SourceKey          *string `json:"sourceKey"`
		LinkID             *string `json:"linkId"`
		Generation         string  `json:"generation"`
		LocalOverrideState string  `json:"localOverrideState"`
	} `json:"fieldAuthority"`
	EntitlementProvenance []struct {
		ID               string  `json:"id"`
		TargetID         string  `json:"targetId"`
		EntitlementID    string  `json:"entitlementId"`
		SourceGeneration string  `json:"sourceGeneration"`
		SourceKey        *string `json:"sourceKey"`
		LinkID           *string `json:"linkId"`
		ValidUntil       *string `json:"validUntil"`
		RevokedAt        *string `json:"revokedAt"`
	} `json:"entitlementProvenance"`
	TransitionHistory []struct {
		ID          string  `json:"id"`
		Generation  string  `json:"generation"`
		CreatedAt   string  `json:"createdAt"`
		UpdatedAt   string  `json:"updatedAt"`
		CompletedAt *string `json:"completedAt"`
	} `json:"transitionHistory"`
	LinkHistory []struct {
		ID            string  `json:"id"`
		OccurredAt    string  `json:"occurredAt"`
		Reason        string  `json:"reason"`
		CorrelationID string  `json:"correlationId"`
		LinkID        *string `json:"linkId"`
	} `json:"linkHistory"`
}

type identityConflictList struct {
	Items []identityConflict `json:"items"`
}

type identityConflict struct {
	ID            string `json:"id"`
	SourceKey     string `json:"sourceKey"`
	EvidenceClass string `json:"evidenceClass"`
	State         string `json:"state"`
	Generation    string `json:"generation"`
	CreatedAt     string `json:"createdAt,omitempty"`
	ExpiresAt     string `json:"expiresAt,omitempty"`
	Explanation   string `json:"explanation"`
}

type identityConflictDetail struct {
	ID     string `json:"id"`
	Source struct {
		SourceKey   string `json:"sourceKey"`
		DisplayName string `json:"displayName"`
		Kind        string `json:"kind"`
		State       string `json:"state"`
		Generation  string `json:"generation"`
	} `json:"source"`
	SubjectFingerprint string  `json:"subjectFingerprint"`
	EvidenceClass      string  `json:"evidenceClass"`
	EvidenceDigest     string  `json:"evidenceDigest"`
	Explanation        string  `json:"explanation"`
	State              string  `json:"state"`
	Generation         string  `json:"generation"`
	CreatedAt          string  `json:"createdAt"`
	ExpiresAt          string  `json:"expiresAt"`
	DecidedAt          *string `json:"decidedAt"`
	CandidatePerson    *struct {
		UserID      string  `json:"userId"`
		Email       string  `json:"email"`
		DisplayName *string `json:"displayName"`
		Enabled     *bool   `json:"enabled"`
		Protected   *bool   `json:"protected"`
	} `json:"candidatePerson"`
	AllowedDecisions []string `json:"allowedDecisions"`
	DecisionHistory  []struct {
		ID         string  `json:"id"`
		Decision   string  `json:"decision"`
		Reason     string  `json:"reason"`
		PersonID   *string `json:"personId"`
		LinkID     *string `json:"linkId"`
		DecidedBy  string  `json:"decidedBy"`
		OccurredAt string  `json:"occurredAt"`
	} `json:"decisionHistory"`
}

type identityConflictDecisionResult struct {
	ID         string  `json:"id"`
	State      string  `json:"state"`
	Generation string  `json:"generation"`
	PersonID   *string `json:"personId"`
	LinkID     *string `json:"linkId"`
	Replayed   *bool   `json:"replayed"`
}

type identityTransitionList struct {
	Items []identityTransition `json:"items"`
}

type identityTransition struct {
	ID             string  `json:"id"`
	UserID         string  `json:"userId"`
	Kind           string  `json:"kind"`
	State          string  `json:"state"`
	SourceKey      string  `json:"sourceKey"`
	Protected      *bool   `json:"protected"`
	Reason         string  `json:"reason,omitempty"`
	FailureCode    *string `json:"failureCode,omitempty"`
	CreatedAt      string  `json:"createdAt,omitempty"`
	UpdatedAt      string  `json:"updatedAt,omitempty"`
	PendingEffects *int    `json:"pendingEffects"`
}

type identityEventList struct {
	Items []identityEvent `json:"items"`
}

type identityEvent struct {
	ID            string          `json:"id"`
	OccurredAt    string          `json:"occurredAt"`
	UserID        *string         `json:"userId,omitempty"`
	SourceKey     *string         `json:"sourceKey,omitempty"`
	LinkID        *string         `json:"linkId,omitempty"`
	TransitionID  *string         `json:"transitionId,omitempty"`
	Action        string          `json:"action"`
	Reason        string          `json:"reason"`
	CorrelationID string          `json:"correlationId"`
	Metadata      json.RawMessage `json:"metadata,omitempty"`
}

type identityTransitionPreview struct {
	TransitionID         string `json:"transitionId"`
	State                string `json:"state"`
	TransitionGeneration string `json:"transitionGeneration"`
	PreviewVersion       string `json:"previewVersion"`
	PreviewDigest        string `json:"previewDigest"`
	PreviewExpiresAt     string `json:"previewExpiresAt"`
	Protected            *bool  `json:"protected"`
	RecoveryReady        *bool  `json:"recoveryReady"`
	SourceGeneration     string `json:"sourceGeneration"`
	LinkGeneration       string `json:"linkGeneration"`
	LifecycleGeneration  string `json:"lifecycleGeneration"`
	Replayed             bool   `json:"replayed,omitempty"`
}

type identityTransitionDetail struct {
	TransitionID         string  `json:"transitionId"`
	CorrelationID        string  `json:"correlationId"`
	PersonID             string  `json:"personId"`
	Type                 string  `json:"type"`
	State                string  `json:"state"`
	TransitionGeneration string  `json:"transitionGeneration"`
	PreviewVersion       string  `json:"previewVersion"`
	PreviewDigest        string  `json:"previewDigest"`
	PreviewExpiresAt     string  `json:"previewExpiresAt"`
	Protected            *bool   `json:"protected"`
	ApprovalRequestID    *string `json:"approvalRequestId"`
	FailureCode          *string `json:"failureCode"`
	Rollback             struct {
		Boundary          string  `json:"boundary"`
		PreviewDigest     *string `json:"previewDigest"`
		PreviewExpiresAt  *string `json:"previewExpiresAt"`
		ApprovalRequestID *string `json:"approvalRequestId"`
	} `json:"rollback"`
	Steps   []json.RawMessage          `json:"steps"`
	Effects []identityTransitionEffect `json:"effects"`
}

type identityTransitionEffect struct {
	EffectID      string  `json:"effectId"`
	Kind          string  `json:"kind"`
	State         string  `json:"state"`
	AttemptCount  int     `json:"attemptCount"`
	NextAttemptAt string  `json:"nextAttemptAt"`
	LastErrorCode *string `json:"lastErrorCode"`
	CompletedAt   *string `json:"completedAt"`
}

type identityTransitionChallenge struct {
	ChallengeID          string `json:"challengeId"`
	TransitionID         string `json:"transitionId"`
	TransitionGeneration string `json:"transitionGeneration"`
	PreviewDigest        string `json:"previewDigest"`
	ExpiresAt            string `json:"expiresAt"`
	HandoffMethod        string `json:"handoffMethod"`
	DisplayCode          string `json:"displayCode"`
	Completed            *bool  `json:"completed"`
	Invalidated          *bool  `json:"invalidated"`
}

type identityTransitionElevation struct {
	ChallengeID          string `json:"challengeId"`
	ElevationID          string `json:"elevationId"`
	TransitionID         string `json:"transitionId"`
	TransitionGeneration string `json:"transitionGeneration"`
	ExpiresAt            string `json:"expiresAt"`
	Consumed             *bool  `json:"consumed"`
	Invalidated          *bool  `json:"invalidated"`
	Replayed             *bool  `json:"replayed"`
}

type identityUpgradeStatus struct {
	SchemaVersion          int   `json:"schemaVersion"`
	MasterEnabled          *bool `json:"masterEnabled"`
	NormalizedReadsEnabled *bool `json:"normalizedReadsEnabled"`
	TransitionsEnabled     *bool `json:"transitionsEnabled"`
	Sources                struct {
		Total         *int `json:"total"`
		Shadow        *int `json:"shadow"`
		Canary        *int `json:"canary"`
		Normalized    *int `json:"normalized"`
		CohortMembers *int `json:"cohortMembers"`
	} `json:"sources"`
	Blockers struct {
		CriticalDivergences *int `json:"criticalDivergences"`
		PendingCandidates   *int `json:"pendingCandidates"`
		PendingEffects      *int `json:"pendingEffects"`
	} `json:"blockers"`
}

type identityUpgradeCanaryResult struct {
	SourceKey  string `json:"sourceKey"`
	Generation string `json:"generation"`
	ReadMode   string `json:"readMode"`
	CohortSize *int   `json:"cohortSize"`
}

type identityUpgradeRollbackResult struct {
	RolledBack     *bool `json:"rolledBack"`
	PendingEffects *int  `json:"pendingEffects"`
}

type identityDoctorCheck struct {
	Name       string          `json:"name"`
	Severity   string          `json:"severity"`
	Passed     *bool           `json:"passed"`
	Facts      json.RawMessage `json:"facts"`
	NextAction string          `json:"nextAction"`
}

type identityDoctor struct {
	GeneratedAt   string                `json:"generatedAt"`
	SourceKey     *string               `json:"sourceKey"`
	Passed        *bool                 `json:"passed"`
	BlockingCount *int                  `json:"blockingCount"`
	Checks        []identityDoctorCheck `json:"checks"`
}

type identityInventorySource struct {
	SourceKey     string `json:"sourceKey"`
	Kind          string `json:"kind"`
	State         string `json:"state"`
	Generation    string `json:"generation"`
	ReadMode      string `json:"readMode"`
	ActiveLinks   *int   `json:"activeLinks"`
	OpenConflicts *int   `json:"openConflicts"`
}

type identityInventoryPerson struct {
	UserID             string  `json:"userId"`
	Enabled            *bool   `json:"enabled"`
	AccountClass       string  `json:"accountClass"`
	LifecycleAuthority *string `json:"lifecycleAuthority"`
	ActiveLinks        *int    `json:"activeLinks"`
	DetachedLinks      *int    `json:"detachedLinks"`
}

type identityInventoryConflict struct {
	ID            string `json:"id"`
	SourceKey     string `json:"sourceKey"`
	EvidenceClass string `json:"evidenceClass"`
	State         string `json:"state"`
	Generation    string `json:"generation"`
	CreatedAt     string `json:"createdAt"`
	ExpiresAt     string `json:"expiresAt"`
}

type identityInventoryExport struct {
	ManifestVersion string                      `json:"manifestVersion"`
	SchemaVersion   int                         `json:"schemaVersion"`
	GeneratedAt     string                      `json:"generatedAt"`
	RedactionPolicy string                      `json:"redactionPolicy"`
	SHA256          string                      `json:"sha256"`
	Sources         []identityInventorySource   `json:"sources"`
	People          []identityInventoryPerson   `json:"people"`
	Conflicts       []identityInventoryConflict `json:"conflicts"`
	RedactionCounts struct {
		EmailsOmitted            *int `json:"emailsOmitted"`
		ExternalSubjectsOmitted  *int `json:"externalSubjectsOmitted"`
		CandidateSubjectsOmitted *int `json:"candidateSubjectsOmitted"`
		SecretsOmitted           *int `json:"secretsOmitted"`
	} `json:"redactionCounts"`
}

type identityJob struct {
	JobID           string          `json:"jobId"`
	Kind            string          `json:"kind"`
	State           string          `json:"state"`
	SnapshotID      string          `json:"snapshotId"`
	SourceKey       *string         `json:"sourceKey"`
	TransitionID    *string         `json:"transitionId"`
	CreatedAt       string          `json:"createdAt"`
	ExpiresAt       string          `json:"expiresAt"`
	Progress        json.RawMessage `json:"progress"`
	NextAction      string          `json:"nextAction"`
	Terminal        *bool           `json:"terminal"`
	CancelRequested *bool           `json:"cancelRequested"`
	ManifestVersion string          `json:"manifestVersion"`
	ByteCount       *int            `json:"byteCount"`
	SHA256          string          `json:"sha256"`
	RedactionCounts map[string]int  `json:"redactionCounts"`
}

type identityJobResult struct {
	Sequence  string          `json:"sequence"`
	UserID    *string         `json:"userId"`
	State     string          `json:"state"`
	Result    json.RawMessage `json:"result"`
	CreatedAt string          `json:"createdAt"`
}

type identityJobResults struct {
	Items        []identityJobResult `json:"items"`
	NextSequence *string             `json:"nextSequence"`
}

type identityUpgradePreflight struct {
	ManifestVersion string                `json:"manifestVersion"`
	GeneratedAt     string                `json:"generatedAt"`
	Phase           string                `json:"phase"`
	Checks          []identityDoctorCheck `json:"checks"`
	Blockers        []string              `json:"blockers"`
	SafeToBackfill  *bool                 `json:"safeToBackfill"`
	FeatureFlags    struct {
		IdentityModelV2 *bool `json:"identityModelV2"`
		NormalizedReads *bool `json:"normalizedReads"`
		Transitions     *bool `json:"transitions"`
	} `json:"featureFlags"`
	Estimates struct {
		People                 *int `json:"people"`
		MaximumBatchSize       *int `json:"maximumBatchSize"`
		MaximumDurationSeconds *int `json:"maximumDurationSeconds"`
	} `json:"estimates"`
	SHA256 string `json:"sha256"`
}

type identityUpgradeShadow struct {
	SourceKey                  string   `json:"sourceKey"`
	Eligible                   *bool    `json:"eligible"`
	CompletedSyncs             *int     `json:"completedSyncs"`
	RequiredSyncs              *int     `json:"requiredSyncs"`
	WindowStartedAt            *string  `json:"windowStartedAt"`
	WindowHours                *float64 `json:"windowHours"`
	RequiredWindowHours        *int     `json:"requiredWindowHours"`
	CriticalDivergences        *int     `json:"criticalDivergences"`
	MissingProjections         *int     `json:"missingProjections"`
	UndispositionedAmbiguities *int     `json:"undispositionedAmbiguities"`
	NextAction                 string   `json:"nextAction"`
}

type identityRetirementCheck struct {
	Name       string `json:"name"`
	Passed     *bool  `json:"passed"`
	NextAction string `json:"nextAction"`
}

type identityUpgradeRetirementCheck struct {
	Ready                        *bool                     `json:"ready"`
	DestructiveMigrationIncluded *bool                     `json:"destructiveMigrationIncluded"`
	Checks                       []identityRetirementCheck `json:"checks"`
	NextAction                   string                    `json:"nextAction"`
}

type identityTransitionReport struct {
	SchemaVersion int               `json:"schemaVersion"`
	GeneratedAt   string            `json:"generatedAt"`
	Transition    json.RawMessage   `json:"transition"`
	Effects       []json.RawMessage `json:"effects"`
	Events        []json.RawMessage `json:"events"`
}

func validateIdentitySourceList(v *identitySourceList) error {
	if v.Items == nil {
		return missingIdentityField("items")
	}
	if len(v.Items) > identityListLimit {
		return fmt.Errorf("identity source response has %d items; maximum is %d", len(v.Items), identityListLimit)
	}
	for i, item := range v.Items {
		if item.SourceKey == "" || item.DisplayName == "" || item.Kind == "" ||
			len(item.SourceKey) > 64 || len(item.DisplayName) > 255 ||
			!oneOf(item.Kind, "local", "ad", "ldap", "scim", "saml", "oidc") ||
			!oneOf(item.State, "draft", "validated", "active", "paused", "error", "retired") ||
			!positiveDecimal(item.Generation) ||
			!isJSONObject(item.Capabilities) || item.AttentionCount == nil ||
			*item.AttentionCount < 0 || invalidOptionalTime(item.LastSuccessAt) ||
			invalidOptionalTime(item.LastFailureAt) {
			return fmt.Errorf("identity source response item %d is missing or has an invalid required field", i)
		}
	}
	return nil
}

func validateIdentitySourceDetail(v *identitySourceDetail) error {
	if v.SourceKey == "" || len(v.SourceKey) > 64 ||
		v.DisplayName == "" || len(v.DisplayName) > 128 ||
		!oneOf(v.Kind, "local", "ad", "ldap", "scim", "saml", "oidc") ||
		!oneOf(v.State, "draft", "validated", "active", "paused", "error", "retired") ||
		!positiveDecimal(v.Generation) || !positiveDecimal(v.MappingVersion) ||
		!isJSONObject(v.Capabilities) || !isJSONObject(v.Document) ||
		v.SecretConfigured == nil || invalidOptionalTime(v.LastSuccessAt) ||
		invalidOptionalTime(v.LastFailureAt) {
		return fmt.Errorf("identity source detail is missing or has an invalid required field")
	}
	for name := range v.SecretConfigured {
		if name == "" || len(name) > 64 {
			return fmt.Errorf("identity source detail has an invalid secret name")
		}
	}
	return nil
}

func validateIdentitySourcePlan(v *identitySourcePlanResult) error {
	if v.SourceKey == "" || len(v.SourceKey) > 64 || v.Create == nil ||
		v.Changed == nil || !isJSONObject(v.Desired) || v.Operations == nil ||
		(v.CurrentGeneration != nil && !positiveDecimal(*v.CurrentGeneration)) ||
		len(v.Operations) > 2 {
		return fmt.Errorf("identity source plan is missing or has an invalid required field")
	}
	for _, operation := range v.Operations {
		if !oneOf(operation, "create_draft", "update_draft_config", "increment_generation") {
			return fmt.Errorf("identity source plan contains an unknown operation")
		}
	}
	return nil
}

func validateIdentitySourceMutation(v *identitySourceMutationResult) error {
	if v.Valid != nil && !*v.Valid {
		if v.SourceKey == "" || len(v.SourceKey) > 64 ||
			!oneOf(v.Transport, "not_required", "reachable", "failed") ||
			v.PersonWrites == nil || *v.PersonWrites != 0 || v.Blockers == nil ||
			!validIdentitySecretPosture(v.SecretConfigured) {
			return fmt.Errorf("identity source dry-run blocker response is invalid")
		}
		return nil
	}
	if v.SourceID != "" && !positiveDecimal(v.SourceID) {
		return fmt.Errorf("identity source mutation has an invalid sourceId")
	}
	if v.SourceKey == "" || len(v.SourceKey) > 64 ||
		!oneOf(v.State, "draft", "validated", "active", "paused", "error", "retired") ||
		!positiveDecimal(v.Generation) || v.Replayed == nil {
		return fmt.Errorf("identity source mutation is missing or has an invalid required field")
	}
	if v.SecretName != "" && !identitySecretConfiguredTrue(v.SecretConfigured) {
		return fmt.Errorf("identity source secret mutation has invalid configured posture")
	}
	if v.Valid != nil && !validIdentitySecretPosture(v.SecretConfigured) {
		return fmt.Errorf("identity source dry-run has invalid secret posture")
	}
	if v.PersonWrites != nil && *v.PersonWrites != 0 {
		return fmt.Errorf("identity source dry-run reported person writes")
	}
	return nil
}

func identitySecretConfiguredTrue(raw json.RawMessage) bool {
	var configured bool
	return json.Unmarshal(raw, &configured) == nil && configured
}

func validIdentitySecretPosture(raw json.RawMessage) bool {
	var posture map[string]bool
	if json.Unmarshal(raw, &posture) != nil || posture == nil || len(posture) > 1 {
		return false
	}
	for name := range posture {
		if name == "" || len(name) > 64 {
			return false
		}
	}
	return true
}

type identitySourceFileDocument struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		SourceKey   string `json:"sourceKey"`
		DisplayName string `json:"displayName"`
	} `json:"metadata"`
	Spec json.RawMessage `json:"spec"`
}

func validateIdentitySourceDocumentOffline(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || len(raw) > 64<<10 {
		return "", fmt.Errorf("identity source file must be 1..65536 bytes")
	}
	var document identitySourceFileDocument
	if err := strictIdentityJSON(raw, &document); err != nil {
		return "", fmt.Errorf("invalid identity source file: %w", err)
	}
	if document.APIVersion != "setjoin.io/v1" || document.Kind != "IdentitySource" ||
		document.Metadata.SourceKey == "" || len(document.Metadata.SourceKey) > 64 ||
		!boundedIdentitySourceTextCLI(document.Metadata.DisplayName, 128) {
		return "", fmt.Errorf("identity source file has invalid apiVersion, kind, or metadata")
	}
	for index, r := range document.Metadata.SourceKey {
		if index == 0 && !((r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return "", fmt.Errorf("identity source metadata.sourceKey is invalid")
		}
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || strings.ContainsRune("._:-", r)) {
			return "", fmt.Errorf("identity source metadata.sourceKey is invalid")
		}
	}
	var spec map[string]json.RawMessage
	if err := json.Unmarshal(document.Spec, &spec); err != nil || spec == nil {
		return "", fmt.Errorf("identity source spec must be an object")
	}
	var sourceType string
	if err := json.Unmarshal(spec["type"], &sourceType); err != nil ||
		!oneOf(sourceType, "local", "ad", "ldap", "scim", "saml", "oidc") {
		return "", fmt.Errorf("identity source spec.type is unsupported")
	}
	allowed := map[string]map[string]bool{
		"local": identityFieldSet("type", "capabilities", "passwordPolicy", "passkeyPolicy", "mfaPolicy"),
		"ad":    identityFieldSet("type", "capabilities", "endpoint", "subjectAttribute", "baseDN", "bindDN", "userFilter", "groupFilter", "mapping", "deletionPolicy"),
		"ldap":  identityFieldSet("type", "capabilities", "endpoint", "subjectAttribute", "baseDN", "bindDN", "userFilter", "groupFilter", "mapping", "deletionPolicy"),
		"scim":  identityFieldSet("type", "capabilities", "deletionPolicy", "mapping", "tokenLabel", "tokenExpiry"),
		"saml":  identityFieldSet("type", "capabilities", "registrationKey", "idpEntityId", "metadataUrl", "ssoUrl", "certificateRef", "spEntityId", "persistentNameId", "attributeMapping", "groupMapping", "jitPolicy"),
		"oidc":  identityFieldSet("type", "capabilities", "providerKey", "issuer", "clientId", "redirectUri", "scopes", "claimMapping", "subjectClaim", "jitPolicy"),
	}[sourceType]
	for key := range spec {
		if !allowed[key] {
			return "", fmt.Errorf("identity source spec contains unsupported field %q", key)
		}
	}
	requireText := func(name string, max int) (string, error) {
		var value string
		if json.Unmarshal(spec[name], &value) != nil ||
			!boundedIdentitySourceTextCLI(value, max) {
			return "", fmt.Errorf("identity source spec.%s is required and must be bounded text", name)
		}
		return value, nil
	}
	switch sourceType {
	case "ad", "ldap":
		if _, err := requireText("baseDN", 2048); err != nil {
			return "", err
		}
		subject, err := requireText("subjectAttribute", 128)
		if err != nil {
			return "", err
		}
		if sourceType == "ad" && subject != "objectGUID" && subject != "msDS-ConsistencyGuid" {
			return "", fmt.Errorf("AD subjectAttribute must be objectGUID or msDS-ConsistencyGuid")
		}
		var endpoint struct {
			Host string `json:"host"`
			Port int    `json:"port"`
			TLS  string `json:"tls"`
		}
		if strictIdentityJSON(spec["endpoint"], &endpoint) != nil ||
			!boundedIdentitySourceTextCLI(endpoint.Host, 253) ||
			endpoint.Port < 1 || endpoint.Port > 65535 ||
			!oneOf(endpoint.TLS, "ldaps", "starttls") {
			return "", fmt.Errorf("identity source endpoint requires bounded host, port, and tls")
		}
	case "saml":
		if _, err := requireText("registrationKey", 255); err != nil {
			return "", err
		}
		if _, err := requireText("idpEntityId", 2048); err != nil {
			return "", err
		}
	case "oidc":
		if _, err := requireText("providerKey", 255); err != nil {
			return "", err
		}
		if _, err := requireText("issuer", 2048); err != nil {
			return "", err
		}
		if _, err := requireText("clientId", 1024); err != nil {
			return "", err
		}
		subject, err := requireText("subjectClaim", 128)
		if err != nil || subject != "sub" {
			return "", fmt.Errorf("OIDC subjectClaim must be sub")
		}
	}
	if rawCapabilities, present := spec["capabilities"]; present {
		var capabilities map[string]json.RawMessage
		if json.Unmarshal(rawCapabilities, &capabilities) != nil || capabilities == nil {
			return "", fmt.Errorf("identity source capabilities must be an object")
		}
		allowedCapabilities := identityFieldSet(
			"authenticate", "provisionLifecycle", "passwordWriteback",
			"profileFields", "entitlements", "deltaCursor", "suspendDelete",
			"immutableSubject",
		)
		for key := range capabilities {
			if !allowedCapabilities[key] {
				return "", fmt.Errorf("identity source capabilities contain unsupported field %q", key)
			}
		}
	}
	return document.Metadata.SourceKey, nil
}

func boundedIdentitySourceTextCLI(value string, max int) bool {
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

func identityFieldSet(values ...string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		out[value] = true
	}
	return out
}

func strictIdentityJSON(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err == nil {
		return fmt.Errorf("trailing JSON value")
	} else if !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func validateIdentityPeopleList(v *identityPeopleList) error {
	if v.Items == nil {
		return missingIdentityField("items")
	}
	if len(v.Items) > identityListLimit {
		return fmt.Errorf("identity people response has %d items; maximum is %d", len(v.Items), identityListLimit)
	}
	for i, item := range v.Items {
		if !positiveDecimal(item.UserID) || !validEmail(item.Email) || item.Enabled == nil ||
			(item.LifecycleAuthority != "local" && item.LifecycleAuthority != "source") ||
			item.ActiveLinks < 0 || item.ActiveLinks > 8 || item.DetachedLinks < 0 {
			return fmt.Errorf("identity people response item %d is missing or has an invalid required field", i)
		}
	}
	return nil
}

func validateIdentityPersonDetail(v *identityPersonDetail) error {
	if !positiveDecimal(v.UserID) || !validEmail(v.Email) ||
		v.Enabled == nil || v.Protected == nil || v.Relationship != "member" ||
		!oneOf(v.LifecycleAuthority.Kind, "local", "source") ||
		!positiveDecimal(v.LifecycleAuthority.Generation) ||
		v.Recovery.HasLocalPassword == nil ||
		negativeOrMissing(v.Recovery.PasskeyCount) ||
		negativeOrMissing(v.Recovery.ActiveAuthenticationLinks) ||
		*v.Recovery.ActiveAuthenticationLinks > 8 ||
		v.Links == nil || len(v.Links) > 100 ||
		v.FieldAuthority == nil || len(v.FieldAuthority) > 64 ||
		v.EntitlementProvenance == nil || len(v.EntitlementProvenance) > 500 ||
		v.TransitionHistory == nil || len(v.TransitionHistory) > 50 ||
		v.LinkHistory == nil || len(v.LinkHistory) > 100 {
		return fmt.Errorf("identity person detail is missing or has an invalid required field")
	}
	if v.LifecycleAuthority.Kind == "local" {
		if v.LifecycleAuthority.LinkID != nil || v.LifecycleAuthority.SourceKey != nil {
			return fmt.Errorf("identity person detail has an invalid local lifecycle authority")
		}
	} else if v.LifecycleAuthority.LinkID == nil ||
		!positiveDecimal(*v.LifecycleAuthority.LinkID) ||
		v.LifecycleAuthority.SourceKey == nil ||
		*v.LifecycleAuthority.SourceKey == "" ||
		len(*v.LifecycleAuthority.SourceKey) > 64 {
		return fmt.Errorf("identity person detail has an invalid source lifecycle authority")
	}
	for _, link := range v.Links {
		seen := map[string]bool{}
		if !positiveDecimal(link.ID) || link.SourceKey == "" ||
			len(link.SourceKey) > 64 ||
			!oneOf(link.SourceKind, "local", "ad", "ldap", "scim", "saml", "oidc") ||
			len(link.Purposes) == 0 || len(link.Purposes) > 2 ||
			!oneOf(link.State, "candidate", "active", "suspended", "detaching", "detached", "conflict") ||
			!positiveDecimal(link.Generation) ||
			!oneOf(link.LinkMethod, "backfill", "jit", "connector", "operator", "transition") ||
			!validLowerHex(link.SubjectFingerprint, 16) ||
			!validRFC3339(link.FirstSeenAt) || !validRFC3339(link.LastSeenAt) ||
			invalidOptionalTime(link.DetachedAt) {
			return fmt.Errorf("identity person detail contains an invalid link")
		}
		for _, purpose := range link.Purposes {
			if seen[purpose] || !oneOf(purpose, "authenticate", "provision") {
				return fmt.Errorf("identity person detail contains invalid link purposes")
			}
			seen[purpose] = true
		}
	}
	for _, authority := range v.FieldAuthority {
		if authority.Field == "" || len(authority.Field) > 64 ||
			!oneOf(authority.AuthorityKind, "local", "source") ||
			!positiveDecimal(authority.Generation) ||
			(authority.LinkID != nil && !positiveDecimal(*authority.LinkID)) ||
			(authority.SourceKey != nil &&
				(*authority.SourceKey == "" || len(*authority.SourceKey) > 64)) ||
			!oneOf(authority.LocalOverrideState,
				"none", "override", "writeback_pending", "conflict") {
			return fmt.Errorf("identity person detail contains invalid field authority")
		}
	}
	for _, grant := range v.EntitlementProvenance {
		if !positiveDecimal(grant.ID) || !positiveDecimal(grant.TargetID) ||
			!positiveDecimal(grant.EntitlementID) ||
			!positiveDecimal(grant.SourceGeneration) ||
			(grant.LinkID != nil && !positiveDecimal(*grant.LinkID)) ||
			invalidOptionalTime(grant.ValidUntil) ||
			invalidOptionalTime(grant.RevokedAt) {
			return fmt.Errorf("identity person detail contains invalid entitlement provenance")
		}
	}
	for _, transition := range v.TransitionHistory {
		if !validUUID(transition.ID) || !positiveDecimal(transition.Generation) ||
			!validRFC3339(transition.CreatedAt) ||
			!validRFC3339(transition.UpdatedAt) ||
			invalidOptionalTime(transition.CompletedAt) {
			return fmt.Errorf("identity person detail contains invalid transition history")
		}
	}
	for _, event := range v.LinkHistory {
		if !positiveDecimal(event.ID) || !validRFC3339(event.OccurredAt) ||
			event.Reason == "" || len(event.Reason) > 1024 ||
			!validUUID(event.CorrelationID) ||
			(event.LinkID != nil && !positiveDecimal(*event.LinkID)) {
			return fmt.Errorf("identity person detail contains invalid link history")
		}
	}
	return nil
}

func validateIdentityConflictList(v *identityConflictList) error {
	if v.Items == nil {
		return missingIdentityField("items")
	}
	if len(v.Items) > identityListLimit {
		return fmt.Errorf("identity conflict response has %d items; maximum is %d", len(v.Items), identityListLimit)
	}
	for i, item := range v.Items {
		if !validUUID(item.ID) || item.SourceKey == "" || item.EvidenceClass == "" ||
			len(item.SourceKey) > 64 ||
			!oneOf(item.EvidenceClass, "hard", "composite", "soft", "conflict") ||
			!oneOf(item.State, "pending", "linked", "new", "rejected", "deferred", "expired") ||
			!positiveDecimal(item.Generation) || item.Explanation == "" ||
			len(item.Explanation) > 1024 ||
			(item.CreatedAt != "" && !validRFC3339(item.CreatedAt)) ||
			(item.ExpiresAt != "" && !validRFC3339(item.ExpiresAt)) {
			return fmt.Errorf("identity conflict response item %d is missing or has an invalid required field", i)
		}
	}
	return nil
}

func validateIdentityConflictDetail(v *identityConflictDetail) error {
	if !validUUID(v.ID) || v.Source.SourceKey == "" ||
		len(v.Source.SourceKey) > 64 || v.Source.DisplayName == "" ||
		len(v.Source.DisplayName) > 128 ||
		!oneOf(v.Source.Kind, "local", "ad", "ldap", "scim", "saml", "oidc") ||
		!oneOf(v.Source.State, "draft", "validated", "active", "paused", "error", "retired") ||
		!positiveDecimal(v.Source.Generation) ||
		!validLowerHex(v.SubjectFingerprint, 16) ||
		!oneOf(v.EvidenceClass, "hard", "composite", "soft", "conflict") ||
		!validDigest(v.EvidenceDigest) ||
		v.Explanation == "" || len(v.Explanation) > 512 ||
		!oneOf(v.State, "pending", "linked", "new", "rejected", "deferred", "expired") ||
		!positiveDecimal(v.Generation) || !validRFC3339(v.CreatedAt) ||
		!validRFC3339(v.ExpiresAt) || invalidOptionalTime(v.DecidedAt) ||
		v.AllowedDecisions == nil || len(v.AllowedDecisions) > 3 ||
		v.DecisionHistory == nil || len(v.DecisionHistory) > 50 {
		return fmt.Errorf("identity conflict detail is missing or has an invalid required field")
	}
	if v.CandidatePerson != nil &&
		(!positiveDecimal(v.CandidatePerson.UserID) ||
			!validEmail(v.CandidatePerson.Email) ||
			v.CandidatePerson.Enabled == nil ||
			v.CandidatePerson.Protected == nil) {
		return fmt.Errorf("identity conflict detail has an invalid candidate person")
	}
	seen := map[string]bool{}
	for _, decision := range v.AllowedDecisions {
		if seen[decision] || !oneOf(decision, "link", "create", "reject", "defer") {
			return fmt.Errorf("identity conflict detail has invalid allowed decisions")
		}
		seen[decision] = true
	}
	for _, decision := range v.DecisionHistory {
		if !positiveDecimal(decision.ID) ||
			!oneOf(decision.Decision, "link", "create", "reject", "defer") ||
			decision.Reason == "" || len(decision.Reason) > 1024 ||
			(decision.PersonID != nil && !positiveDecimal(*decision.PersonID)) ||
			(decision.LinkID != nil && !positiveDecimal(*decision.LinkID)) ||
			!positiveDecimal(decision.DecidedBy) ||
			!validRFC3339(decision.OccurredAt) {
			return fmt.Errorf("identity conflict detail contains invalid decision history")
		}
	}
	return nil
}

func validateIdentityConflictDecisionResult(v *identityConflictDecisionResult) error {
	if !validUUID(v.ID) ||
		!oneOf(v.State, "linked", "new", "rejected", "deferred") ||
		!positiveDecimal(v.Generation) || v.Replayed == nil ||
		(v.PersonID != nil && !positiveDecimal(*v.PersonID)) ||
		(v.LinkID != nil && !positiveDecimal(*v.LinkID)) {
		return fmt.Errorf("identity conflict decision response is missing or invalid")
	}
	if oneOf(v.State, "linked", "new") &&
		(v.PersonID == nil || v.LinkID == nil) {
		return fmt.Errorf("identity conflict decision response is missing its resulting link")
	}
	return nil
}

func validateIdentityTransitionList(v *identityTransitionList) error {
	if v.Items == nil {
		return missingIdentityField("items")
	}
	if len(v.Items) > identityListLimit {
		return fmt.Errorf("identity transition response has %d items; maximum is %d", len(v.Items), identityListLimit)
	}
	for i, item := range v.Items {
		if !validUUID(item.ID) || !positiveDecimal(item.UserID) ||
			item.Kind != "directory_to_local" ||
			item.State == "" || item.SourceKey == "" || item.Protected == nil ||
			len(item.SourceKey) > 64 || item.PendingEffects == nil ||
			*item.PendingEffects < 0 || *item.PendingEffects > 3 ||
			(item.CreatedAt != "" && !validRFC3339(item.CreatedAt)) ||
			(item.UpdatedAt != "" && !validRFC3339(item.UpdatedAt)) {
			return fmt.Errorf("identity transition response item %d is missing or has an invalid required field", i)
		}
	}
	return nil
}

func validateIdentityEventList(v *identityEventList) error {
	if v.Items == nil {
		return missingIdentityField("items")
	}
	if len(v.Items) > identityListLimit {
		return fmt.Errorf("identity event response has %d items; maximum is %d", len(v.Items), identityListLimit)
	}
	for i, item := range v.Items {
		if !positiveDecimal(item.ID) || !validRFC3339(item.OccurredAt) || item.Action == "" ||
			item.Reason == "" || len(item.Reason) > 1024 ||
			!validUUID(item.CorrelationID) ||
			(item.UserID != nil && !positiveDecimal(*item.UserID)) ||
			(item.LinkID != nil && !positiveDecimal(*item.LinkID)) ||
			(item.TransitionID != nil && !validUUID(*item.TransitionID)) ||
			(item.SourceKey != nil && (len(*item.SourceKey) == 0 || len(*item.SourceKey) > 64)) {
			return fmt.Errorf("identity event response item %d is missing or has an invalid required field", i)
		}
	}
	return nil
}

func (v *identityTransitionPreview) validate() error {
	if !validUUID(v.TransitionID) || !identityTransitionState(v.State) ||
		!validDigest(v.PreviewDigest) ||
		!positiveDecimal(v.TransitionGeneration) || !positiveDecimal(v.PreviewVersion) ||
		!validRFC3339(v.PreviewExpiresAt) ||
		v.Protected == nil || v.RecoveryReady == nil || !positiveDecimal(v.SourceGeneration) ||
		!positiveDecimal(v.LinkGeneration) ||
		!positiveDecimal(v.LifecycleGeneration) {
		return fmt.Errorf("identity transition preview response is missing or has an invalid required field")
	}
	return nil
}

func (v *identityTransitionDetail) validate() error {
	if !validUUID(v.TransitionID) || !validUUID(v.CorrelationID) ||
		!positiveDecimal(v.PersonID) || v.Type != "directory_to_local" ||
		!identityTransitionState(v.State) ||
		!positiveDecimal(v.TransitionGeneration) ||
		!positiveDecimal(v.PreviewVersion) || !validDigest(v.PreviewDigest) ||
		!validRFC3339(v.PreviewExpiresAt) || v.Protected == nil ||
		(v.ApprovalRequestID != nil && !positiveDecimal(*v.ApprovalRequestID)) ||
		v.Rollback.Boundary == "" || len(v.Steps) > 15 || len(v.Effects) > 6 {
		return fmt.Errorf("identity transition detail response is missing or has an invalid required field")
	}
	if !oneOf(v.Rollback.Boundary, "not_committed", "reversible",
		"new_login_observed", "irreversible_effect", "window_expired", "rolled_back") ||
		(v.Rollback.PreviewDigest != nil && !validDigest(*v.Rollback.PreviewDigest)) ||
		(v.Rollback.PreviewExpiresAt != nil && !validRFC3339(*v.Rollback.PreviewExpiresAt)) ||
		(v.Rollback.ApprovalRequestID != nil &&
			!positiveDecimal(*v.Rollback.ApprovalRequestID)) {
		return fmt.Errorf("identity transition detail has an invalid rollback state")
	}
	for _, step := range v.Steps {
		if !isJSONObject(step) {
			return fmt.Errorf("identity transition detail steps must be objects")
		}
	}
	for _, effect := range v.Effects {
		if !validUUID(effect.EffectID) ||
			!oneOf(effect.Kind, "auth_sessions", "livekit_sessions",
				"subscriber_notice", "rollback_auth_sessions",
				"rollback_livekit_sessions", "rollback_subscriber_notice") ||
			!oneOf(effect.State, "pending", "running", "completed", "failed", "disposed") ||
			effect.AttemptCount < 0 || effect.AttemptCount > 20 ||
			!validRFC3339(effect.NextAttemptAt) ||
			(effect.CompletedAt != nil && !validRFC3339(*effect.CompletedAt)) {
			return fmt.Errorf("identity transition detail contains an invalid effect")
		}
	}
	return nil
}

func (v *identityTransitionChallenge) validate() error {
	if !validUUID(v.ChallengeID) || !validUUID(v.TransitionID) ||
		!positiveDecimal(v.TransitionGeneration) || !validDigest(v.PreviewDigest) ||
		!validRFC3339(v.ExpiresAt) || v.HandoffMethod != "browser" ||
		len(v.DisplayCode) != 8 || v.Completed == nil || v.Invalidated == nil {
		return fmt.Errorf("identity transition challenge response is missing or invalid")
	}
	return nil
}

func (v *identityTransitionElevation) validate() error {
	if !validUUID(v.ChallengeID) || !validUUID(v.ElevationID) ||
		!validUUID(v.TransitionID) || !positiveDecimal(v.TransitionGeneration) ||
		!validRFC3339(v.ExpiresAt) || v.Consumed == nil ||
		v.Invalidated == nil || v.Replayed == nil {
		return fmt.Errorf("identity transition elevation response is missing or invalid")
	}
	return nil
}

func identityTransitionState(state string) bool {
	return oneOf(state,
		"draft", "previewed", "awaiting_approval", "authorized", "executing",
		"authority_committed", "effects_pending", "completed",
		"failed_precommit", "failed_recoverable", "rollback_previewed",
		"rolling_back", "rolled_back", "cancelled", "expired")
}

func (v *identityUpgradeStatus) validate() error {
	if v.SchemaVersion < 164 || v.MasterEnabled == nil || v.NormalizedReadsEnabled == nil ||
		v.TransitionsEnabled == nil || negativeOrMissing(v.Sources.Total) ||
		negativeOrMissing(v.Sources.Shadow) || negativeOrMissing(v.Sources.Canary) ||
		negativeOrMissing(v.Sources.Normalized) || negativeOrMissing(v.Sources.CohortMembers) ||
		negativeOrMissing(v.Blockers.CriticalDivergences) ||
		negativeOrMissing(v.Blockers.PendingCandidates) ||
		negativeOrMissing(v.Blockers.PendingEffects) {
		return fmt.Errorf("identity upgrade status response is missing or has an invalid required field")
	}
	return nil
}

func (v *identityUpgradeCanaryResult) validate() error {
	if v.SourceKey == "" || len(v.SourceKey) > 64 || !positiveDecimal(v.Generation) ||
		(v.ReadMode != "shadow" && v.ReadMode != "canary") ||
		v.CohortSize == nil || *v.CohortSize < 0 || *v.CohortSize > 500 {
		return fmt.Errorf("identity canary response is missing or has an invalid required field")
	}
	return nil
}

func (v *identityUpgradeRollbackResult) validate() error {
	if v.RolledBack == nil || !*v.RolledBack || v.PendingEffects == nil || *v.PendingEffects < 0 {
		return fmt.Errorf("identity rollback response is missing or has an invalid required field")
	}
	return nil
}

func (v *identityDoctorCheck) validate() error {
	if v.Name == "" || len(v.Name) > 128 ||
		!oneOf(v.Severity, "info", "warning", "blocker") ||
		v.Passed == nil || !isJSONObject(v.Facts) ||
		v.NextAction == "" || len(v.NextAction) > 256 {
		return fmt.Errorf("identity doctor check is missing or has an invalid required field")
	}
	return nil
}

func (v *identityDoctor) validate() error {
	if !validRFC3339(v.GeneratedAt) || v.Passed == nil ||
		v.BlockingCount == nil || *v.BlockingCount < 0 ||
		len(v.Checks) == 0 || len(v.Checks) > 32 ||
		(v.SourceKey != nil && (*v.SourceKey == "" || len(*v.SourceKey) > 64)) {
		return fmt.Errorf("identity doctor response is missing or has an invalid required field")
	}
	blockers := 0
	for i := range v.Checks {
		if err := v.Checks[i].validate(); err != nil {
			return fmt.Errorf("identity doctor check %d: %w", i, err)
		}
		if v.Checks[i].Severity == "blocker" && !*v.Checks[i].Passed {
			blockers++
		}
	}
	if blockers != *v.BlockingCount || *v.Passed != (blockers == 0) {
		return fmt.Errorf("identity doctor response has inconsistent blocker totals")
	}
	return nil
}

func (v *identityInventoryExport) validate() error {
	if v.ManifestVersion != "1" || v.SchemaVersion < 167 ||
		!validRFC3339(v.GeneratedAt) ||
		v.RedactionPolicy != "identity-inventory-v1" ||
		!validDigest(v.SHA256) || v.Sources == nil || v.People == nil ||
		v.Conflicts == nil || len(v.Sources) > 10000 ||
		len(v.People) > 10000 || len(v.Conflicts) > 10000 ||
		negativeOrMissing(v.RedactionCounts.EmailsOmitted) ||
		negativeOrMissing(v.RedactionCounts.ExternalSubjectsOmitted) ||
		negativeOrMissing(v.RedactionCounts.CandidateSubjectsOmitted) ||
		negativeOrMissing(v.RedactionCounts.SecretsOmitted) {
		return fmt.Errorf("identity inventory export is missing or has an invalid required field")
	}
	for i, source := range v.Sources {
		if source.SourceKey == "" || len(source.SourceKey) > 64 ||
			!oneOf(source.Kind, "local", "ad", "ldap", "scim", "saml", "oidc") ||
			source.State == "" || !positiveDecimal(source.Generation) ||
			!oneOf(source.ReadMode, "legacy", "shadow", "canary", "normalized") ||
			negativeOrMissing(source.ActiveLinks) ||
			negativeOrMissing(source.OpenConflicts) {
			return fmt.Errorf("identity inventory source %d is invalid", i)
		}
	}
	for i, person := range v.People {
		if !positiveDecimal(person.UserID) || person.Enabled == nil ||
			!oneOf(person.AccountClass, "member", "guest", "unclassified") ||
			(person.LifecycleAuthority != nil &&
				!oneOf(*person.LifecycleAuthority, "local", "source")) ||
			negativeOrMissing(person.ActiveLinks) ||
			negativeOrMissing(person.DetachedLinks) {
			return fmt.Errorf("identity inventory person %d is invalid", i)
		}
	}
	for i, conflict := range v.Conflicts {
		if !validUUID(conflict.ID) || conflict.SourceKey == "" ||
			!oneOf(conflict.EvidenceClass, "hard", "composite", "soft", "conflict") ||
			conflict.State == "" || !positiveDecimal(conflict.Generation) ||
			!validRFC3339(conflict.CreatedAt) || !validRFC3339(conflict.ExpiresAt) {
			return fmt.Errorf("identity inventory conflict %d is invalid", i)
		}
	}
	return nil
}

func (v *identityJob) validate() error {
	if !validUUID(v.JobID) || !validUUID(v.SnapshotID) ||
		!oneOf(v.Kind, "upgrade_backfill", "diagnostics", "cohort_preview") ||
		!oneOf(v.State, "queued", "running", "completed",
			"completed_with_failures", "failed", "cancelled", "expired") ||
		!validRFC3339(v.CreatedAt) || !validRFC3339(v.ExpiresAt) ||
		!isJSONObject(v.Progress) || v.NextAction == "" ||
		len(v.NextAction) > 256 || v.Terminal == nil ||
		v.CancelRequested == nil ||
		(v.SourceKey != nil && (*v.SourceKey == "" || len(*v.SourceKey) > 64)) ||
		(v.TransitionID != nil && !validUUID(*v.TransitionID)) {
		return fmt.Errorf("identity job response is missing or has an invalid required field")
	}
	terminal := oneOf(v.State, "completed", "completed_with_failures",
		"failed", "cancelled", "expired")
	if *v.Terminal != terminal {
		return fmt.Errorf("identity job response has an inconsistent terminal state")
	}
	if v.ByteCount != nil && (*v.ByteCount < 0 ||
		int64(*v.ByteCount) > maxIdentityArtifactBytes) {
		return fmt.Errorf("identity job response has an invalid byte count")
	}
	if v.SHA256 != "" && !validDigest(v.SHA256) {
		return fmt.Errorf("identity job response has an invalid checksum")
	}
	if v.ManifestVersion != "" && v.ManifestVersion != "1" {
		return fmt.Errorf("identity job response has an unsupported manifest version")
	}
	if len(v.RedactionCounts) > 16 {
		return fmt.Errorf("identity job response exceeds the redaction-count bound")
	}
	for _, count := range v.RedactionCounts {
		if count < 0 {
			return fmt.Errorf("identity job response has a negative redaction count")
		}
	}
	if v.Kind == "diagnostics" && v.State == "completed" &&
		(v.ManifestVersion != "1" || v.ByteCount == nil || v.SHA256 == "") {
		return fmt.Errorf("completed identity diagnostic job is missing artifact facts")
	}
	return nil
}

func (v *identityJobResults) validate() error {
	if v.Items == nil || len(v.Items) > 500 ||
		(v.NextSequence != nil && !positiveDecimal(*v.NextSequence)) {
		return fmt.Errorf("identity job results response is missing or invalid")
	}
	var last uint64
	for i, item := range v.Items {
		sequence, err := strconv.ParseUint(item.Sequence, 10, 64)
		if err != nil || sequence == 0 || sequence <= last ||
			(item.UserID != nil && !positiveDecimal(*item.UserID)) ||
			!oneOf(item.State, "completed", "failed", "skipped", "blocked") ||
			!isJSONObject(item.Result) || !validRFC3339(item.CreatedAt) {
			return fmt.Errorf("identity job result %d is invalid", i)
		}
		last = sequence
	}
	if len(v.Items) > 0 && (v.NextSequence == nil ||
		*v.NextSequence != v.Items[len(v.Items)-1].Sequence) {
		return fmt.Errorf("identity job results response has an invalid next sequence")
	}
	return nil
}

func (v *identityUpgradePreflight) validate() error {
	if v.ManifestVersion != "1" || !validRFC3339(v.GeneratedAt) ||
		v.Phase != "preflight" || len(v.Checks) == 0 || len(v.Checks) > 32 ||
		v.Blockers == nil || len(v.Blockers) > 32 || v.SafeToBackfill == nil ||
		v.FeatureFlags.IdentityModelV2 == nil ||
		v.FeatureFlags.NormalizedReads == nil ||
		v.FeatureFlags.Transitions == nil ||
		negativeOrMissing(v.Estimates.People) ||
		v.Estimates.MaximumBatchSize == nil ||
		*v.Estimates.MaximumBatchSize != 500 ||
		v.Estimates.MaximumDurationSeconds == nil ||
		*v.Estimates.MaximumDurationSeconds != 900 ||
		!validDigest(v.SHA256) {
		return fmt.Errorf("identity upgrade preflight response is missing or invalid")
	}
	failed := make(map[string]struct{})
	for i := range v.Checks {
		if err := v.Checks[i].validate(); err != nil {
			return fmt.Errorf("identity upgrade preflight check %d: %w", i, err)
		}
		if v.Checks[i].Severity == "blocker" && !*v.Checks[i].Passed {
			failed[v.Checks[i].Name] = struct{}{}
		}
	}
	if *v.SafeToBackfill != (len(v.Blockers) == 0) ||
		len(failed) != len(v.Blockers) {
		return fmt.Errorf("identity upgrade preflight has inconsistent blocker totals")
	}
	for _, blocker := range v.Blockers {
		if _, ok := failed[blocker]; !ok {
			return fmt.Errorf("identity upgrade preflight names an unknown blocker")
		}
	}
	return nil
}

func (v *identityUpgradeShadow) validate() error {
	if v.SourceKey == "" || len(v.SourceKey) > 64 || v.Eligible == nil ||
		negativeOrMissing(v.CompletedSyncs) || v.RequiredSyncs == nil ||
		*v.RequiredSyncs != 7 || *v.CompletedSyncs > *v.RequiredSyncs ||
		v.WindowHours == nil || *v.WindowHours < 0 ||
		v.RequiredWindowHours == nil || *v.RequiredWindowHours != 24 ||
		negativeOrMissing(v.CriticalDivergences) ||
		negativeOrMissing(v.MissingProjections) ||
		negativeOrMissing(v.UndispositionedAmbiguities) ||
		(v.WindowStartedAt != nil && !validRFC3339(*v.WindowStartedAt)) ||
		v.NextAction == "" || len(v.NextAction) > 256 {
		return fmt.Errorf("identity upgrade shadow response is missing or invalid")
	}
	return nil
}

func (v *identityUpgradeRetirementCheck) validate() error {
	if v.Ready == nil || v.DestructiveMigrationIncluded == nil ||
		*v.DestructiveMigrationIncluded || len(v.Checks) == 0 ||
		len(v.Checks) > 16 || v.NextAction == "" ||
		len(v.NextAction) > 256 {
		return fmt.Errorf("identity upgrade retirement response is missing or invalid")
	}
	passed := true
	for i, check := range v.Checks {
		if check.Name == "" || len(check.Name) > 128 || check.Passed == nil ||
			check.NextAction == "" || len(check.NextAction) > 256 {
			return fmt.Errorf("identity retirement check %d is invalid", i)
		}
		passed = passed && *check.Passed
	}
	if *v.Ready != passed {
		return fmt.Errorf("identity upgrade retirement response has inconsistent readiness")
	}
	return nil
}

func (v *identityTransitionReport) validate() error {
	if v.SchemaVersion != 1 || !validRFC3339(v.GeneratedAt) ||
		len(bytes.TrimSpace(v.Transition)) == 0 || v.Effects == nil || v.Events == nil {
		return fmt.Errorf("identity transition report response is missing or has an invalid required field")
	}
	if len(v.Effects) > 6 || len(v.Events) > 100 {
		return fmt.Errorf("identity transition report exceeds the documented response bounds")
	}
	if !isJSONObject(v.Transition) {
		return fmt.Errorf("identity transition report transition must be an object")
	}
	for _, effect := range v.Effects {
		if !isJSONObject(effect) {
			return fmt.Errorf("identity transition report effects must be objects")
		}
	}
	for _, event := range v.Events {
		if !isJSONObject(event) {
			return fmt.Errorf("identity transition report events must be objects")
		}
	}
	return nil
}

func missingIdentityField(field string) error {
	return fmt.Errorf("identity response is missing required field %q", field)
}

func positiveDecimal(s string) bool {
	if s == "" || strings.HasPrefix(s, "0") || strings.HasPrefix(s, "+") || strings.HasPrefix(s, "-") {
		return false
	}
	n, err := strconv.ParseUint(s, 10, 64)
	return err == nil && n > 0
}

func validUUID(s string) bool {
	id, err := uuid.Parse(s)
	return err == nil && id != uuid.Nil
}

func validDigest(s string) bool {
	return validLowerHex(s, 64)
}

func validLowerHex(s string, length int) bool {
	if len(s) != length {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func validRFC3339(s string) bool {
	_, err := time.Parse(time.RFC3339Nano, s)
	return err == nil
}

func isJSONObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) >= 2 && trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}'
}

func negativeOrMissing(v *int) bool {
	return v == nil || *v < 0
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func invalidOptionalTime(value *string) bool {
	return value != nil && !validRFC3339(*value)
}

func validEmail(value string) bool {
	address, err := mail.ParseAddress(value)
	return err == nil && address.Address == value
}
