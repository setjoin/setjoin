package user

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/reducererr"
)

type SenderControlHandler struct{ pool pgxutil.WorkerPool }

func NewSenderControlHandler(pool pgxutil.WorkerPool) *SenderControlHandler {
	return &SenderControlHandler{pool: pool}
}

type senderControlTarget struct {
	MailboxID  int64
	MessageID  int64
	ReceivedAt time.Time
}

func parseSenderControlTarget(values func(string) string) (senderControlTarget, error) {
	mailboxID, err := strconv.ParseInt(values("mailboxId"), 10, 64)
	if err != nil || mailboxID <= 0 {
		return senderControlTarget{}, errors.New("invalid mailboxId")
	}
	messageID, err := strconv.ParseInt(values("messageId"), 10, 64)
	if err != nil || messageID <= 0 {
		return senderControlTarget{}, errors.New("invalid messageId")
	}
	receivedAt, err := time.Parse(time.RFC3339Nano, values("receivedAt"))
	if err != nil {
		return senderControlTarget{}, errors.New("invalid receivedAt")
	}
	return senderControlTarget{MailboxID: mailboxID, MessageID: messageID, ReceivedAt: receivedAt}, nil
}

func senderControlWrite(w http.ResponseWriter, raw json.RawMessage) {
	var meta struct {
		Generation string `json:"generation"`
	}
	if json.Unmarshal(raw, &meta) == nil && meta.Generation != "" {
		w.Header().Set("ETag", `"`+meta.Generation+`"`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (h *SenderControlHandler) Get(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "authentication required")
		return
	}
	target, err := parseSenderControlTarget(r.URL.Query().Get)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, err.Error())
		return
	}
	var raw json.RawMessage
	if err := h.pool.QueryRow(r.Context(), `SELECT sender_control_read($1,$2,$3,$4)`,
		claims.UserID, target.MailboxID, target.MessageID, target.ReceivedAt).Scan(&raw); err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "sender control read failed")
		}
		return
	}
	senderControlWrite(w, raw)
}

func (h *SenderControlHandler) Action(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "authentication required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var req struct {
		MailboxID          string `json:"mailboxId"`
		MessageID          string `json:"messageId"`
		ReceivedAt         string `json:"receivedAt"`
		OperationID        string `json:"operationId"`
		Action             string `json:"action"`
		ExpectedGeneration string `json:"expectedGeneration"`
		TargetOperationID  string `json:"targetOperationId,omitempty"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid sender control request")
		return
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "sender control request must contain one JSON object")
		return
	}
	target, err := parseSenderControlTarget(func(key string) string {
		switch key {
		case "mailboxId":
			return req.MailboxID
		case "messageId":
			return req.MessageID
		default:
			return req.ReceivedAt
		}
	})
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, err.Error())
		return
	}
	operationID, err := uuid.Parse(req.OperationID)
	if err != nil || operationID == uuid.Nil || strings.TrimSpace(r.Header.Get("Idempotency-Key")) != req.OperationID {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "operationId must exactly match Idempotency-Key")
		return
	}
	generation, err := strconv.ParseInt(req.ExpectedGeneration, 10, 64)
	if err != nil || generation <= 0 || r.Header.Get("If-Match") != `"`+req.ExpectedGeneration+`"` {
		httputil.WriteProblemStatus(w, http.StatusPreconditionRequired, "expectedGeneration must exactly match If-Match")
		return
	}
	var targetOperation any
	if req.TargetOperationID != "" {
		parsed, parseErr := uuid.Parse(req.TargetOperationID)
		if parseErr != nil || parsed == uuid.Nil {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid targetOperationId")
			return
		}
		targetOperation = parsed
	}
	digestInput := struct{ MailboxID, MessageID, ReceivedAt, OperationID, Action, ExpectedGeneration, TargetOperationID string }{req.MailboxID, req.MessageID, req.ReceivedAt, req.OperationID, req.Action, req.ExpectedGeneration, req.TargetOperationID}
	encoded, _ := json.Marshal(digestInput)
	sum := sha256.Sum256(encoded)
	digest := hex.EncodeToString(sum[:])
	var raw json.RawMessage
	if err := h.pool.QueryRow(r.Context(), `SELECT sender_control_action($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		claims.UserID, target.MailboxID, target.MessageID, target.ReceivedAt, operationID, req.Action, generation, digest, targetOperation).Scan(&raw); err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "sender control action failed")
		}
		return
	}
	senderControlWrite(w, raw)
}
