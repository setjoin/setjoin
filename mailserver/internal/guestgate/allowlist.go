// Package guestgate enforces the guest-accounts EXPLICIT route ALLOWLIST
// (spec P11b, inverted from a deny list at the codex round: a deny list
// loses by default every time a route is added). Everything a guest claim
// may reach is enumerated below; everything else on the /api surface is 404
// — indistinguishable from a route that does not exist.
//
// THE LIST BETWEEN THE MARKERS IS THE SINGLE SOURCE: the middleware and
// scripts/check-guest-doors.sh both read it. Do not encode guest route
// decisions anywhere else.
package guestgate

import (
	"regexp"
	"strings"
)

type rule struct {
	method string // "" = any method
	kind   string // "prefix" | "root-prefix" | "exact" | "regex"
	pat    string
	re     *regexp.Regexp
}

// guest-allowlist-begin
var allowRules = []rule{
	// Chat: the guest app. Door verbs are BZ215-denied in the reducers (P2);
	// the route surface itself is open.
	{"", "prefix", "/chat/", nil},
	// The live rail exception (§4.1): chat push + reconnect ride these two
	// EXACT routes; their streams are self-scoped and the push seam applies
	// the guest belt (chain.AuthenticatePushToken).
	{"GET", "exact", "/jmap/ws", nil},
	{"GET", "exact", "/jmap/eventsource", nil},
	// Session/capabilities — the REAL routes (there is no /jmap/session or
	// /auth/session; review-fold E-B2): the JMAP discovery/session doc is
	// GET /.well-known/jmap (main.go:2922 — the guest arm returns the
	// fail-closed capability set, P11a) and the session read is GET /auth/me
	// (main.go:2951, the authserver proxy webmail's checkAuth fetches).
	// EXACT: /auth/me/* subroutes (org-chart, app-passwords, …) stay denied.
	{"GET", "exact", "/.well-known/jmap", nil},
	{"GET", "exact", "/auth/me", nil},
	// Refresh/logout: reachable by this gate because the pinned-branch wrap
	// covers bare-root /auth (E-B1/E-B3). The AUTHSERVER is the real refresh
	// authority (RefreshTokens honors users.enabled; guest_set_status revokes
	// the family) — this gate is only the belt: an inactive guest's
	// still-valid access token 401s here (BZ219 at validation) instead of
	// reaching the proxy; an EXPIRED access token fails AuthenticateRequest
	// and passes through to the authserver, whose enabled-check contains it.
	{"POST", "exact", "/auth/refresh", nil},
	{"POST", "exact", "/auth/logout", nil},
	// Drive (codex C-3, honest containment story): these routes are GENERIC
	// Drive readers/writers — nodes_meta.go and content.go authorize by
	// SPACE MEMBERSHIP (driveMemberScope*SQL → drive_member_role), not by
	// attachment row. What makes them attachment-only FOR A GUEST is the
	// grant door, not the route: drive_member_grant /
	// drive_folder_member_grant refuse guest grantees (BZ215, Task 7), so a
	// guest's only space membership is the LIVE chat-derivation
	// (drive_member_role arm 2, V120) — reach = chat-bound spaces of its
	// own channels, revoked the instant the membership goes.
	// POST /drive/native-token is DENIED outright in G0 (P11b); G4 replaces
	// this posture with the viewer-cap + preview tiers.
	{"HEAD", "prefix", "/drive/chunks/", nil},
	{"PUT", "prefix", "/drive/chunks/", nil},
	{"GET", "exact", "/drive/nodes", nil},
	{"GET", "regex", `^/drive/versions/[0-9]+/content$`, nil},
	// Guest G4: office-to-PDF rendition is the view-only rail. Raw content
	// remains separately reducer-gated by allow_download; every other Drive
	// route, including native-token, stays denied by omission.
	{"GET", "regex", `^/drive/versions/[0-9]+/preview$`, nil},
	// Guest invite accept — unauthenticated pre-auth surfaces (G1 spec §11).
	// These are NOT guest-session routes; they are entered before the guest has
	// any session at all (the accept flow is how the guest GETS their first
	// session). They forward to the authserver proxy — the authserver's own
	// enumIPGuard rate-limits them at origin.
	// EXACT: only the exact path, no subroutes.
	{"GET", "exact", "/auth/guest-invite/accept", nil},
	{"POST", "exact", "/auth/guest-invite/accept", nil},
	// Webmail guest invite accept page — pre-auth SvelteKit route.
	// The SPA loads before auth; the page itself calls GET/POST /auth/guest-invite/accept.
	// ROOT-PREFIX: match the original path only; never normalize an /api mount.
	{"GET", "root-prefix", "/guest-invite/", nil},
	// Meet G3: enumerate today's route shapes instead of admitting the whole
	// subtree. Numeric reads and every mutation are reducer-scoped; slug
	// possession exposes only the pre-join projection and never mints a token.
	// A newly-added Meet route therefore remains guest-denied until it receives
	// an explicit posture here.
	{"GET", "exact", "/meet", nil},
	{"POST", "exact", "/meet", nil},
	{"GET", "regex", `^/meet/by-slug/[^/]+$`, nil},
	{"GET", "regex", `^/meet/[0-9]+$`, nil},
	{"POST", "regex", `^/meet/[0-9]+/(join|lock|settings|role|kick|end|knock|recording|captions)$`, nil},
	{"DELETE", "regex", `^/meet/[0-9]+/(recording|captions)$`, nil},
	{"POST", "regex", `^/meet/[0-9]+/requests/[0-9]+$`, nil},
	{"POST", "regex", `^/meet/[0-9]+/breakouts(/(assign|close|join))?$`, nil},
	// Authenticated knock completion deliberately reuses the secret-bound
	// public poll. GET is safe to admit (the same slug+request+secret proof is
	// required of unauthenticated callers); public POST creation stays out so
	// an authenticated guest cannot shed its u: identity into a g: request.
	{"GET", "regex", `^/public/meet/[^/]+/join-request/[0-9]+$`, nil},
	// Browser WebSockets carry the guest access-token cookie as well as the
	// reducer-composed LiveKit token. Let the exact signal mount through the
	// guest gate; LiveKit validates its own signed room grant. The slash on the
	// prefix is deliberate: /rtcx remains denied.
	{"GET", "exact", "/rtc", nil},
	{"GET", "prefix", "/rtc/", nil},
}

// guest-allowlist-end

func init() {
	for i := range allowRules {
		if allowRules[i].kind == "regex" {
			allowRules[i].re = regexp.MustCompile(allowRules[i].pat)
		}
	}
}

// GuestAllowed reports whether a guest claim may reach method+path. path may
// carry the /api/ mount segment; it is trimmed before matching ordinary rules.
func GuestAllowed(method, path string) bool {
	p := path
	if strings.HasPrefix(path, "/api/") {
		p = strings.TrimPrefix(path, "/api")
	}
	for _, r := range allowRules {
		if r.method != "" && r.method != method {
			continue
		}
		switch r.kind {
		case "prefix":
			if strings.HasPrefix(p, r.pat) {
				return true
			}
		case "root-prefix":
			if strings.HasPrefix(path, r.pat) {
				return true
			}
		case "exact":
			if p == r.pat {
				return true
			}
		case "regex":
			if r.re.MatchString(p) {
				return true
			}
		}
	}
	return false
}
