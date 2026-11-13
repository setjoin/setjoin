package handlers

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/httputil"
)

// OIDCAuthRequestCompleter is the narrow storage seam required to bind an OP
// authorization request to the authenticated Setjoin session.
type OIDCAuthRequestCompleter interface {
	CompleteAuthRequest(
		ctx context.Context,
		id string,
		userID int64,
		authTime time.Time,
		acr string,
		amr []string,
	) error
}

// OIDCProviderCompleteHandler completes the trusted, admin-registered OIDC
// client's authorization request from an already-authenticated Setjoin
// session, then returns to zitadel's authorization callback.
type OIDCProviderCompleteHandler struct {
	Completer OIDCAuthRequestCompleter
}

func (h *OIDCProviderCompleteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(ctxKeyUser).(*token.Claims)
	if !ok || claims == nil || claims.UserID <= 0 {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	requestID := r.URL.Query().Get("id")
	if requestID == "" || len(requestID) > 256 || h.Completer == nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "Invalid authorization request")
		return
	}

	authTime := time.Now()
	if claims.SessionAuthTime != nil && *claims.SessionAuthTime > 0 {
		authTime = time.Unix(*claims.SessionAuthTime, 0)
	}
	if err := h.Completer.CompleteAuthRequest(
		r.Context(), requestID, claims.UserID, authTime, claims.ACR, claims.AMR,
	); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "Invalid authorization request")
		return
	}

	http.Redirect(
		w,
		r,
		"/authorize/callback?id="+url.QueryEscape(requestID),
		http.StatusFound,
	)
}
