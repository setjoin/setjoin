package middleware

import (
	"crypto/subtle"
	"log/slog"
	"net/http"
	"os"
	"strings"
)

// SecurityHeaders adds baseline security headers to all responses.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		// camera/microphone/autoplay are (self), not (): the SAME origin serves
		// the Meet app, and camera=() denies getUserMedia to the whole document
		// — PreJoin's device probe rejected with NotAllowedError in every
		// spec-compliant browser, so no participant could ever publish audio or
		// video (found live by the B1 webmail-UI gate; the earlier raw-SDK
		// media smoke never loaded a gateway-served page, so the header never
		// applied). autoplay=(self) is needed for remote participant
		// audio/video elements, which the LiveKit client attaches and plays
		// without a user gesture. Everything else stays fully denied.
		w.Header().Set("Permissions-Policy",
			"camera=(self), microphone=(self), autoplay=(self), "+
				"geolocation=(), payment=(), usb=(), magnetometer=(), "+
				"gyroscope=(), accelerometer=()")
		isTLS := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
		connectSrc := "'self' wss: https:"
		if !isTLS {
			connectSrc += " http:"
		}
		// This header keeps script-src 'unsafe-inline' deliberately: it applies to
		// EVERY response and to the WHOLE document, including SvelteKit's per-build
		// inline hydration bootstrap (whose hash changes each build) and app.html's
		// pre-paint theme script — a static header can't track the bootstrap hash, so
		// it can't drop 'unsafe-inline' without breaking hydration. The strict
		// inline-script lockdown for the app runtime lives in the SvelteKit build-time
		// <meta> CSP (svelte.config.js, mode:'hash'): script-src 'self' + the
		// bootstrap hash, NO 'unsafe-inline'. A <meta> CSP governs only content AFTER
		// it, which is the bootstrap + anything the app injects at runtime (the real
		// XSS surface) — so an injected inline script in the app is blocked. The small
		// static pre-paint theme script sits BEFORE the meta and is governed only by
		// this header. style-src keeps 'unsafe-inline' (pervasive inline style=""
		// attributes; hash mode does not cover style attributes). The real XSS barrier
		// for untrusted email is the sandbox="" iframe in ReadingPane; this header is
		// defense-in-depth (object-src scoped to self+blob:, base-uri/form-action
		// self, and frame-ancestors none — which a <meta> CSP cannot express, only
		// a header).
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				// 'wasm-unsafe-eval' (Meet B1 Task 16b, locked triple-lock delta):
				// background blur's WASM segmentation model (@livekit/track-
				// processors/@mediapipe/tasks-vision) fails WebAssembly.instantiate
				// under Chromium's CSP unless script-src carries either
				// 'unsafe-eval' or the narrower 'wasm-unsafe-eval' (which allows
				// ONLY wasm compilation, never textual eval/new Function) — verified
				// against the pinned package's bundled wasm glue at authoring time.
				// Mirrored in svelte.config.js's meta CSP and Electron's
				// SESSION_CSP in the same commit; 'unsafe-inline' is untouched
				// everywhere (still banned in the other two homes, still present
				// here for the pre-meta-CSP bootstrap reason documented below).
				"script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; "+
				"style-src 'self' 'unsafe-inline'; "+
				// https: is required for the reading-pane remote-image opt-in
				// (sanitize.ts allowRemoteImages, trusted-sender + "Load images"):
				// a srcdoc iframe with no own `csp` attribute inherits this header's
				// policy, so without https: here the opt-in was silently dead — the
				// sanitizer let the <img src="https://…"> through but the browser's
				// own CSP enforcement dropped the fetch regardless of user consent.
				"img-src 'self' data: blob: https:; "+
				"font-src 'self'; "+
				"connect-src "+connectSrc+"; "+
				// + Drive P3 loopback (spec Sec8.2 locked delta): the in-app SecureViewer
				// streams native AV from the ticketed 127.0.0.1 render server (offline-
				// core's tiny_http loopback, ARCH-017). media-src ONLY -- connect/script/
				// frame untouched. See csp.test.ts's mirrored svelte.config.js guard and
				// session-lockdown.ts's SESSION_CSP (Electron's own layered header).
				"media-src 'self' blob: http://127.0.0.1:*; "+
				// 'self' + blob: only (never a remote origin) -- Drive P3's
				// SecureViewer renders PDF/ready-office-rendition previews via
				// <embed type="application/pdf" src={blob:...}>, and object-src
				// (not img-src/media-src) is what gates <object>/<embed>/<applet>
				// resource loading. A bare 'none' silently killed every such
				// preview: no console error a user would notice, just an empty
				// embed (B5, 2026-07-11 codebase review). script-src untouched.
				"object-src 'self' blob:; "+
				"base-uri 'self'; "+
				"form-action 'self'; "+
				"frame-src 'self'; "+
				"frame-ancestors 'none';")
		next.ServeHTTP(w, r)
	})
}

// HSTS adds Strict-Transport-Security header. Only applied when the request
// came over TLS (or a trusted proxy terminated TLS with X-Forwarded-Proto: https)
// to avoid bricking dev environments running without TLS.
func HSTS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		}
		next.ServeHTTP(w, r)
	})
}

// MetricsAuth restricts access to /metrics using a bearer token.
// Set METRICS_TOKEN env var to require Bearer authentication.
//
// Fail-closed by default: when METRICS_TOKEN is unset, /metrics returns 401
// for every request. Set METRICS_ALLOW_UNAUTHENTICATED=1 to explicitly opt
// into unauthenticated scraping (e.g. a trusted-network Prometheus scrape) —
// this is an opt-in exception, not the default.
func MetricsAuth(next http.Handler) http.Handler {
	token := os.Getenv("METRICS_TOKEN")
	allowUnauth := os.Getenv("METRICS_ALLOW_UNAUTHENTICATED")
	optOut := token == "" && (allowUnauth == "1" || allowUnauth == "true")
	if token == "" {
		if optOut {
			slog.Warn("/metrics is publicly UNAUTHENTICATED: METRICS_TOKEN is unset and " +
				"METRICS_ALLOW_UNAUTHENTICATED is set, so anyone who can reach the listener " +
				"can scrape metrics (info disclosure). This opt-out is intended for a " +
				"trusted-network Prometheus scrape only.")
		} else {
			slog.Warn("/metrics is DISABLED (401): METRICS_TOKEN is unset. Set METRICS_TOKEN " +
				"to require Bearer authentication, or set METRICS_ALLOW_UNAUTHENTICATED=1 to " +
				"explicitly allow unauthenticated scraping on a trusted network.")
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token == "" {
			if !optOut {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") || subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(auth, "Bearer ")), []byte(token)) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
