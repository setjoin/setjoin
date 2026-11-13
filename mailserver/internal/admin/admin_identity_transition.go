package admin

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/reducererr"
)

func identityTransitionPathID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil || id == uuid.Nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid transition id")
		return uuid.Nil, false
	}
	return id, true
}

func identityTransitionMutationKey(
	w http.ResponseWriter,
	r *http.Request,
	bodyKey string,
) (uuid.UUID, bool) {
	headerKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if headerKey == "" || bodyKey == "" || headerKey != bodyKey {
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

func identityTransitionDigestFence(
	w http.ResponseWriter,
	r *http.Request,
	digest string,
) bool {
	if !validIdentityDigest(digest) {
		httputil.WriteProblemStatus(w, http.StatusBadRequest,
			"invalid transition preview digest")
		return false
	}
	if strings.TrimSpace(r.Header.Get("If-Match")) != `"`+strings.ToLower(digest)+`"` {
		httputil.WriteProblemStatus(w, http.StatusPreconditionFailed,
			"If-Match must be the strong transition preview digest ETag")
		return false
	}
	return true
}

func (h *IdentityHandler) identityTransitionReachable(
	w http.ResponseWriter,
	r *http.Request,
	actorID int64,
	transitionID uuid.UUID,
) bool {
	var reachable bool
	if err := h.workerPool.QueryRow(r.Context(), `
		SELECT COALESCE((
		  SELECT admin_can_reach($1,t.user_id)
		    FROM identity_transitions t
		   WHERE t.id=$2
		),false)
	`, actorID, transitionID).Scan(&reachable); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"identity transition scope check failed")
		return false
	}
	if !reachable {
		httputil.WriteProblemStatus(w, http.StatusNotFound,
			"identity transition not found")
		return false
	}
	return true
}

// IdentityTransition returns the authoritative transition read model. The
// generation is the strong resource version for non-preview-bound commands.
func (h *IdentityHandler) IdentityTransition(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	id, ok := identityTransitionPathID(w, r)
	if !ok || !h.requireIdentityWorker(w) ||
		!h.identityTransitionReachable(w, r, claims.UserID, id) {
		return
	}
	var raw json.RawMessage
	if err := h.workerPool.QueryRow(r.Context(),
		`SELECT identity_transition_read($1,$2)`,
		claims.UserID, id,
	).Scan(&raw); err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError,
				"identity transition read failed")
		}
		return
	}
	var version struct {
		TransitionGeneration string `json:"transitionGeneration"`
	}
	if err := json.Unmarshal(raw, &version); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"identity transition returned an invalid response")
		return
	}
	generation, err := strconv.ParseInt(version.TransitionGeneration, 10, 64)
	if err != nil || generation <= 0 {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"identity transition returned an invalid generation")
		return
	}
	writeIdentityRawJSON(w, r, http.StatusOK, raw, version.TransitionGeneration)
}

// TransitionChallengeIssue creates a five-minute, preview- and
// generation-bound challenge. It does not itself assert or accept AAL2.
func (h *IdentityHandler) TransitionChallengeIssue(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	id, ok := identityTransitionPathID(w, r)
	if !ok {
		return
	}
	var req struct {
		PreviewDigest  string `json:"previewDigest"`
		IdempotencyKey string `json:"idempotencyKey"`
	}
	if !decodeIdentityJSON(w, r, &req, "invalid transition challenge request") ||
		!identityTransitionDigestFence(w, r, req.PreviewDigest) {
		return
	}
	key, ok := identityTransitionMutationKey(w, r, req.IdempotencyKey)
	if !ok || !h.requireIdentityWorker(w) ||
		!h.identityTransitionReachable(w, r, claims.UserID, id) {
		return
	}
	var raw json.RawMessage
	if err := h.workerPool.QueryRow(r.Context(),
		`SELECT identity_transition_challenge_issue($1,$2,$3,$4)`,
		claims.UserID, id, strings.ToLower(req.PreviewDigest), key,
	).Scan(&raw); err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError,
				"identity transition challenge failed")
		}
		return
	}
	writeIdentityRawJSON(w, r, http.StatusOK, raw, strings.ToLower(req.PreviewDigest))
}

// TransitionChallengeComplete converts a verified, fresh AAL2 session into a
// one-use transition elevation. No bearer token or reusable factor material is
// persisted: reducers receive only deterministic SHA-256 bindings.
func (h *IdentityHandler) TransitionChallengeComplete(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	id, ok := identityTransitionPathID(w, r)
	if !ok {
		return
	}
	var req struct {
		ChallengeID    string `json:"challengeId"`
		PreviewDigest  string `json:"previewDigest"`
		IdempotencyKey string `json:"idempotencyKey"`
	}
	if !decodeIdentityJSON(w, r, &req, "invalid transition challenge completion") ||
		!identityTransitionDigestFence(w, r, req.PreviewDigest) {
		return
	}
	challengeID, err := uuid.Parse(req.ChallengeID)
	if err != nil || challengeID == uuid.Nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest,
			"invalid transition challenge id")
		return
	}
	key, ok := identityTransitionMutationKey(w, r, req.IdempotencyKey)
	if !ok {
		return
	}
	sessionDigest, factorDigest, amr, ok := identityTransitionStepUpBindings(
		claims, id, challengeID, strings.ToLower(req.PreviewDigest), time.Now(),
	)
	if !ok {
		httputil.WriteProblemStatus(w, http.StatusForbidden,
			"fresh AAL2 step-up with two verified factors is required")
		return
	}
	if !h.requireIdentityWorker(w) ||
		!h.identityTransitionReachable(w, r, claims.UserID, id) {
		return
	}
	var raw json.RawMessage
	if err := h.workerPool.QueryRow(r.Context(), `
		SELECT identity_transition_challenge_complete(
		  $1,$2,$3,$4,$5,$6,$7,$8,$9
		)
	`, claims.UserID, id, challengeID, strings.ToLower(req.PreviewDigest),
		sessionDigest[:], factorDigest[:], amr, claims.ACR, key,
	).Scan(&raw); err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError,
				"identity transition challenge completion failed")
		}
		return
	}
	writeIdentityRawJSON(w, r, http.StatusOK, raw, strings.ToLower(req.PreviewDigest))
}

type identityTransitionAuthorizedRequest struct {
	PreviewDigest   string  `json:"previewDigest"`
	ElevationID     string  `json:"elevationId"`
	ApprovalRequest *string `json:"approvalRequestId,omitempty"`
	Reason          string  `json:"reason"`
	IdempotencyKey  string  `json:"idempotencyKey"`
}

func identityTransitionApprovalID(raw *string) (*int64, bool) {
	if raw == nil {
		return nil, true
	}
	if *raw == "" || (*raw)[0] < '1' || (*raw)[0] > '9' {
		return nil, false
	}
	for _, ch := range *raw {
		if ch < '0' || ch > '9' {
			return nil, false
		}
	}
	value, err := strconv.ParseInt(*raw, 10, 64)
	if err != nil || value <= 0 {
		return nil, false
	}
	return &value, true
}

func (h *IdentityHandler) transitionAuthorizedMutation(
	w http.ResponseWriter,
	r *http.Request,
	operation string,
) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	id, ok := identityTransitionPathID(w, r)
	if !ok {
		return
	}
	var req identityTransitionAuthorizedRequest
	if !decodeIdentityJSON(w, r, &req, "invalid identity transition command") ||
		!identityReasonMatches(w, r, req.Reason) ||
		!identityTransitionDigestFence(w, r, req.PreviewDigest) {
		return
	}
	elevationID, err := uuid.Parse(req.ElevationID)
	approvalRequestID, approvalOK := identityTransitionApprovalID(req.ApprovalRequest)
	if err != nil || elevationID == uuid.Nil || !approvalOK {
		httputil.WriteProblemStatus(w, http.StatusBadRequest,
			"invalid identity transition authorization")
		return
	}
	if operation == "rollback" && approvalRequestID == nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest,
			"rollback requires an approvalRequestId")
		return
	}
	key, ok := identityTransitionMutationKey(w, r, req.IdempotencyKey)
	if !ok || !h.requireIdentityWorker(w) ||
		!h.identityTransitionReachable(w, r, claims.UserID, id) {
		return
	}
	var raw json.RawMessage
	switch operation {
	case "request":
		err = h.workerPool.QueryRow(r.Context(),
			`SELECT identity_transition_request($1,$2,$3,$4,$5,$6)`,
			claims.UserID, id, strings.ToLower(req.PreviewDigest),
			elevationID, req.Reason, key,
		).Scan(&raw)
	case "approve":
		err = h.workerPool.QueryRow(r.Context(),
			`SELECT identity_transition_approve($1,$2,$3,$4,$5,$6)`,
			claims.UserID, id, strings.ToLower(req.PreviewDigest),
			elevationID, req.Reason, key,
		).Scan(&raw)
	case "deny":
		err = h.workerPool.QueryRow(r.Context(),
			`SELECT identity_transition_deny($1,$2,$3,$4,$5,$6)`,
			claims.UserID, id, strings.ToLower(req.PreviewDigest),
			elevationID, req.Reason, key,
		).Scan(&raw)
	case "execute":
		err = h.workerPool.QueryRow(r.Context(),
			`SELECT identity_transition_execute($1,$2,$3,$4,$5,$6,$7)`,
			claims.UserID, id, strings.ToLower(req.PreviewDigest),
			elevationID, approvalRequestID, req.Reason, key,
		).Scan(&raw)
	case "rollback":
		err = h.workerPool.QueryRow(r.Context(),
			`SELECT identity_transition_rollback($1,$2,$3,$4,$5,$6,$7)`,
			claims.UserID, id, strings.ToLower(req.PreviewDigest),
			elevationID, approvalRequestID, req.Reason, key,
		).Scan(&raw)
	default:
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"unsupported identity transition command")
		return
	}
	if err != nil {
		writeIdentityTransitionReducerError(w, r, err,
			"identity transition "+operation+" failed")
		return
	}
	status := http.StatusOK
	if operation == "request" || operation == "execute" || operation == "rollback" {
		status = http.StatusAccepted
	}
	writeIdentityTransitionResult(w, r, status, raw)
}

func (h *IdentityHandler) TransitionRequest(w http.ResponseWriter, r *http.Request) {
	h.transitionAuthorizedMutation(w, r, "request")
}

func (h *IdentityHandler) TransitionApprove(w http.ResponseWriter, r *http.Request) {
	h.transitionAuthorizedMutation(w, r, "approve")
}

func (h *IdentityHandler) TransitionDeny(w http.ResponseWriter, r *http.Request) {
	h.transitionAuthorizedMutation(w, r, "deny")
}

func (h *IdentityHandler) TransitionExecuteAuthorized(w http.ResponseWriter, r *http.Request) {
	h.transitionAuthorizedMutation(w, r, "execute")
}

func (h *IdentityHandler) TransitionRollback(w http.ResponseWriter, r *http.Request) {
	h.transitionAuthorizedMutation(w, r, "rollback")
}

type identityTransitionGenerationRequest struct {
	ExpectedGeneration string `json:"expectedGeneration"`
	Reason             string `json:"reason"`
	IdempotencyKey     string `json:"idempotencyKey"`
}

func identityTransitionGenerationFence(
	w http.ResponseWriter,
	r *http.Request,
	expected string,
) (int64, bool) {
	generation, err := strconv.ParseInt(expected, 10, 64)
	if err != nil || generation <= 0 {
		httputil.WriteProblemStatus(w, http.StatusBadRequest,
			"invalid expected transition generation")
		return 0, false
	}
	if strings.TrimSpace(r.Header.Get("If-Match")) != `"`+expected+`"` {
		httputil.WriteProblemStatus(w, http.StatusPreconditionFailed,
			"If-Match must be the strong transition generation ETag")
		return 0, false
	}
	return generation, true
}

func (h *IdentityHandler) transitionGenerationMutation(
	w http.ResponseWriter,
	r *http.Request,
	operation string,
) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	id, ok := identityTransitionPathID(w, r)
	if !ok {
		return
	}
	var req identityTransitionGenerationRequest
	if !decodeIdentityJSON(w, r, &req, "invalid identity transition command") ||
		!identityReasonMatches(w, r, req.Reason) {
		return
	}
	expected, ok := identityTransitionGenerationFence(
		w, r, req.ExpectedGeneration,
	)
	if !ok {
		return
	}
	key, ok := identityTransitionMutationKey(w, r, req.IdempotencyKey)
	if !ok || !h.requireIdentityWorker(w) ||
		!h.identityTransitionReachable(w, r, claims.UserID, id) {
		return
	}
	var raw json.RawMessage
	var err error
	switch operation {
	case "cancel":
		err = h.workerPool.QueryRow(r.Context(),
			`SELECT identity_transition_cancel($1,$2,$3,$4,$5)`,
			claims.UserID, id, expected, req.Reason, key,
		).Scan(&raw)
	case "rollback-preview":
		err = h.workerPool.QueryRow(r.Context(),
			`SELECT identity_transition_rollback_preview($1,$2,$3,$4,$5)`,
			claims.UserID, id, expected, req.Reason, key,
		).Scan(&raw)
	default:
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"unsupported identity transition command")
		return
	}
	if err != nil {
		writeIdentityTransitionReducerError(w, r, err,
			"identity transition "+operation+" failed")
		return
	}
	writeIdentityTransitionResult(w, r, http.StatusOK, raw)
}

func (h *IdentityHandler) TransitionCancel(w http.ResponseWriter, r *http.Request) {
	h.transitionGenerationMutation(w, r, "cancel")
}

func (h *IdentityHandler) TransitionRollbackPreview(w http.ResponseWriter, r *http.Request) {
	h.transitionGenerationMutation(w, r, "rollback-preview")
}

func (h *IdentityHandler) TransitionRetry(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	id, ok := identityTransitionPathID(w, r)
	if !ok {
		return
	}
	effectID, err := uuid.Parse(r.PathValue("effectId"))
	if err != nil || effectID == uuid.Nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest,
			"invalid identity transition effect id")
		return
	}
	var req identityTransitionGenerationRequest
	if !decodeIdentityJSON(w, r, &req, "invalid identity transition retry") ||
		!identityReasonMatches(w, r, req.Reason) {
		return
	}
	expected, ok := identityTransitionGenerationFence(
		w, r, req.ExpectedGeneration,
	)
	if !ok {
		return
	}
	key, ok := identityTransitionMutationKey(w, r, req.IdempotencyKey)
	if !ok || !h.requireIdentityWorker(w) ||
		!h.identityTransitionReachable(w, r, claims.UserID, id) {
		return
	}
	var raw json.RawMessage
	if err := h.workerPool.QueryRow(r.Context(),
		`SELECT identity_transition_retry($1,$2,$3,$4,$5,$6)`,
		claims.UserID, id, expected, effectID, req.Reason, key,
	).Scan(&raw); err != nil {
		writeIdentityTransitionReducerError(w, r, err,
			"identity transition retry failed")
		return
	}
	writeIdentityTransitionResult(w, r, http.StatusAccepted, raw)
}

func writeIdentityTransitionResult(
	w http.ResponseWriter,
	r *http.Request,
	status int,
	raw json.RawMessage,
) {
	var result struct {
		TransitionGeneration string `json:"transitionGeneration"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"identity transition returned an invalid response")
		return
	}
	generation, err := strconv.ParseInt(result.TransitionGeneration, 10, 64)
	if err != nil || generation <= 0 {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"identity transition returned an invalid generation")
		return
	}
	writeIdentityRawJSON(w, r, status, raw, result.TransitionGeneration)
}

func identityTransitionStepUpBindings(
	claims *jwtutil.Claims,
	transitionID, challengeID uuid.UUID,
	previewDigest string,
	now time.Time,
) ([sha256.Size]byte, [sha256.Size]byte, []string, bool) {
	var empty [sha256.Size]byte
	if !validIdentityDigest(previewDigest) {
		return empty, empty, nil, false
	}
	evidence, err := jwtutil.VerifyFreshAAL2(claims, now, jwtutil.CurrentFreshAAL2Policy())
	if err != nil {
		return empty, empty, nil, false
	}
	issuedAt := evidence.IssuedAt.UTC().Format(time.RFC3339Nano)
	session := sha256.Sum256([]byte(fmt.Sprintf(
		"setjoin-identity-transition-session-v1\n%d\n%s\n%s",
		evidence.UserID, evidence.JTI, issuedAt,
	)))
	factor := sha256.Sum256([]byte(fmt.Sprintf(
		"setjoin-identity-transition-factor-v1\n%d\n%s\n%s\n%s\n%s\n%s\n%s",
		evidence.UserID, transitionID, challengeID, previewDigest,
		evidence.ACR, strings.Join(evidence.AMR, ","), evidence.JTI,
	)))
	return session, factor, evidence.AMR, true
}

func writeIdentityTransitionReducerError(
	w http.ResponseWriter,
	r *http.Request,
	err error,
	detail string,
) {
	if errors.Is(err, pgx.ErrNoRows) {
		httputil.WriteProblemStatus(w, http.StatusNotFound,
			"identity transition not found")
		return
	}
	if !reducererr.WriteClassified(w, r, err) {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, detail)
	}
}
