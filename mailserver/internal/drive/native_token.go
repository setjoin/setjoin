package drive

import (
	"net/http"
	"time"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
)

// driveNativeTokenTTL is long enough for window-closed native sync (Electron
// main process, no renderer) — capped by session revocation, not by this TTL
// alone (batch-3 item 6).
const driveNativeTokenTTL = 12 * time.Hour

// registerNativeTokenRoute wires POST /drive/native-token (Task 17b).
func (h *Handler) registerNativeTokenRoute(mux router) {
	mux.HandleFunc("POST /drive/native-token", h.mintNativeToken)
}

// SetJWTProvider wires the gateway's JWT provider so /drive/native-token can
// mint — a post-construction setter (the admin_roles.go/jmap/handler.go
// idiom) rather than growing NewHandler's signature again for one route
// only main.go's real wiring needs; tests that never exercise native-token
// leave it nil and mintNativeToken 500s cleanly instead of panicking.
func (h *Handler) SetJWTProvider(p *auth.JWTProvider) { h.jwt = p }

type nativeTokenOut struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expiresAt"`
}

// mintNativeToken serves POST /drive/native-token — the P1 batch-3 item 6
// bridge for native (Electron/desktop) clients holding no server-origin
// cookie: an already-authenticated request (cookie OR Bearer — the normal
// chain, both work; a still-valid drive-scoped token presented as Bearer is
// exactly the sliding-renewal path) mints itself a scoped mirror. See
// auth.JWTProvider.IssueDriveNativeToken for why JTI/FamilyID are carried
// forward unchanged (revocation-with-session) and Cnf is never copied
// (unbound — skips the DPoP branch), and chain.go's AuthenticateRequest for
// the scope-containment guard (the other half of the containment: this
// token authenticates ONLY /drive/* paths).
//
// Session-policy containment (er5-s11, sealed anchor cand-drive-token-renewal):
// the mirror is a DERIVED credential, so it can never outlive or shed its
// source session.
//   - TTL clamp: the minted lifetime is capped at the SOURCE access token's
//     remaining expiry (in addition to driveNativeTokenTTL). Without the
//     clamp, sliding renewal kept re-minting 12h mirrors from a session whose
//     own policy-limited lifetime was nearly spent — the derived chain
//     outliving the session policy it was derived from. JTI/FamilyID still
//     propagate (revocation still kills the chain instantly); the clamp adds
//     the expiry boundary.
//   - Device-bound refusal: a device-bound session (Device claim present)
//     cannot mint at all. IssueDriveNativeToken drops the Device claim, so
//     the derived token would carry no device binding — a MAM-bound session
//     escaping its device constraint on a /drive/* scope. Fail closed instead
//     of minting the uncontained credential.
func (h *Handler) mintNativeToken(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if h.jwt == nil {
		h.logger.Error("drive: native-token route hit with no JWTProvider wired (SetJWTProvider never called)")
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "native-token minting is not configured")
		return
	}
	if claims.Device != nil {
		h.logger.Warn("drive: native-token mint refused for device-bound session", "user_id", claims.UserID)
		httputil.WriteProblemStatus(w, http.StatusForbidden, "native tokens are unavailable to device-bound sessions")
		return
	}
	ttl := driveNativeTokenTTL
	if claims.ExpiresAt != nil {
		remaining := time.Until(claims.ExpiresAt.Time)
		if remaining <= 0 {
			httputil.WriteProblemStatus(w, http.StatusUnauthorized, "session expired")
			return
		}
		if remaining < ttl {
			ttl = remaining
		}
	}
	token, expiresAt, err := h.jwt.IssueDriveNativeToken(claims, "drive", ttl)
	if err != nil {
		h.logger.Error("drive: native-token mint failed", "user_id", claims.UserID, "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "token mint failed")
		return
	}
	writeJSON(w, http.StatusOK, nativeTokenOut{Token: token, ExpiresAt: expiresAt.UTC().Format(time.RFC3339)})
}
