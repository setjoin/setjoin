package approval

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/minio/minio-go/v7"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/identity"
	"setjoin.com/shared/reducererr"
	"setjoin.com/shared/toggle"
)

const approvalGuestInvite = "approval.guest_invite"

// SetGuestInviteDelivery wires the same blob-backed system-mail transport used
// by direct admin invitations. Sender and public auth URL remain authoritative
// system_config values read transactionally by guestinvite.Prepare.
func (h *Handler) SetGuestInviteDelivery(mc *minio.Client, bucket string) {
	h.guestInviteMC = mc
	h.guestInviteBucket = bucket
}

// SubmitGuestInvite implements POST /me/guest-invites.
func (h *Handler) SubmitGuestInvite(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblem(w, r, httputil.NewUnauthorizedProblem("authentication required"))
		return
	}
	if claims.IsGuest() || h.toggles == nil ||
		!h.toggles.IsEnabled(toggle.FeatureGuestAccounts) ||
		!h.toggles.IsEnabled(approvalGuestInvite) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "not found"})
		return
	}

	var body struct {
		InvitedEmail string  `json:"invitedEmail"`
		Message      *string `json:"message,omitempty"`
	}
	if err := decodeApprovalJSON(w, r, 4096, &body); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	email, err := identity.ValidateAndCanonicalizeEmail(body.InvitedEmail)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid email"})
		return
	}
	var message *string
	if body.Message != nil {
		trimmed := strings.TrimSpace(*body.Message)
		if trimmed != "" {
			message = &trimmed
		}
	}

	var requestID *int64
	err = h.workerDB.QueryRow(r.Context(),
		`SELECT guest_invite_request_create($1,$2,$3)`, claims.UserID, email.String(), message,
	).Scan(&requestID)
	if err != nil {
		if reducererr.WriteClassified(w, r, err) {
			return
		}
		h.writeApprovalDBErr(w, r, "SubmitGuestInvite failed", err)
		return
	}
	if requestID == nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnprocessableEntity,
			Detail: "no guest invite approval policy is configured"})
		return
	}
	httputil.WriteJSON(w, http.StatusCreated, map[string]int64{"requestId": *requestID})
}

func decodeApprovalJSON(w http.ResponseWriter, r *http.Request, max int64, dst any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, max))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON object")
	}
	return nil
}
