package handlers

import (
	"net/http"

	"setjoin.com/authserver/internal/token"
)

// JWKSHandler serves the first-party JSON Web Key Set (ADR-005): the active +
// retiring ES256 public keys, keyed by kid, that resource servers (the
// mailserver gateway) use to verify first-party authserver tokens offline — no
// shared secret. It is DISTINCT from the OIDC OP `/keys` endpoint (RS256, the
// external-RP surface), which is untouched.
type JWKSHandler struct {
	KeySet *token.KeySet
}

// ServeHTTP returns the JWKS as application/json. Public (RFC 8414 §3 — a JWKS is
// public). A short Cache-Control lets resource servers cache it while keeping
// rotation propagation bounded (the gateway also refreshes on unknown-kid).
func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := h.KeySet.MarshalJWKS()
	if err != nil {
		http.Error(w, "failed to marshal JWKS", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
