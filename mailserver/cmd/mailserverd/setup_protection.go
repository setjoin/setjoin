package main

import (
	"crypto/subtle"
	"log/slog"
	"net/http"

	"setjoin.com/shared/httputil"
)

// Owner decision A3 — setup endpoint protection: the first-boot setup surface
// is (a) rate limited, (b) 404 after setup completes (never a "done" answer),
// and (c) setup CALLS require the one-time setup token install.sh generated
// and printed (SETJOIN_SETUP_TOKEN).

// setupTokenHeader carries the one-time setup token on control-socket setup
// calls (POST /setup/preflight, POST /setup/restore). Not a credential — the
// header NAME.
var setupTokenHeader = http.CanonicalHeaderKey("X-Setup-Token")

// setupStatusGate wraps the status handler (admin.SetupHandler.SetupStatus —
// GET /setup/status) with the A3 completion posture: once any user exists the
// endpoint answers a bare 404 — byte-identical to any other unknown route —
// instead of confirming "initialized": true to the unauthenticated internet.
// A DB failure also 404s (fail closed: uncertainty must not disclose setup
// state). Only the genuinely uninitialized system (0 users) reaches the
// status handler, whose {"initialized": false} answer the webmail setup
// wizard polls for.
//
// Rate limiting is applied separately at registration (d.setupLimit — pinned
// by the route-inventory golden + load-bearing chain test).
func setupStatusGate(db queryRower, status http.HandlerFunc, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var count int
		if err := db.QueryRow(r.Context(), `SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
			logger.Warn("setup status: user count check failed — refusing to disclose state", "error", err)
			http.NotFound(w, r)
			return
		}
		if count > 0 {
			// Setup completed: the endpoint no longer exists for the public mux.
			http.NotFound(w, r)
			return
		}
		status(w, r)
	}
}

// setupTokenGate requires the install-generated one-time setup token on every
// setup CALL (preflight/restore on the local control socket). The token is
// one-time in effect: it only ever matters while the system is uninitialized,
// and both endpoints already refuse (409) once users exist. An empty
// configured token fails CLOSED — the endpoints answer 503 until
// SETJOIN_SETUP_TOKEN is set, so a deployment that predates the token (or lost
// it from its env) can never silently run an unauthenticated setup surface
// again.
func setupTokenGate(setupToken string, logger *slog.Logger, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if setupToken == "" {
			logger.Error("setup call refused: SETJOIN_SETUP_TOKEN is not configured (re-run install.sh or set it in the service env)")
			httputil.WriteProblemStatus(w, http.StatusServiceUnavailable, "setup token not configured")
			return
		}
		provided := r.Header.Get(setupTokenHeader)
		if subtle.ConstantTimeCompare([]byte(provided), []byte(setupToken)) != 1 {
			logger.Warn("setup call refused: invalid setup token", "remote_addr", r.RemoteAddr)
			httputil.WriteProblemStatus(w, http.StatusForbidden, "invalid setup token")
			return
		}
		next(w, r)
	}
}
