package guestgate

import "testing"

func TestGuestAllowed(t *testing.T) {
	allow := [][2]string{
		{"GET", "/api/chat/conversations"},
		{"POST", "/api/chat/channels/5/messages"},
		// The push/live-rail + session/refresh routes arrive BOTH ways: bare
		// (the pinned-branch dispatch) and /api-prefixed (the mount) — the
		// trim must make them equivalent.
		{"GET", "/jmap/ws"},
		{"GET", "/api/jmap/ws"},
		{"GET", "/jmap/eventsource"},
		{"GET", "/.well-known/jmap"}, // the REAL JMAP discovery/session doc (main.go:2922 — there is no /jmap/session route)
		{"GET", "/auth/me"},          // the REAL session read (main.go:2951 — there is no /auth/session route)
		{"GET", "/api/auth/me"},
		{"POST", "/auth/refresh"},
		{"POST", "/auth/logout"},
		{"HEAD", "/api/drive/chunks/abc123"},
		{"PUT", "/api/drive/chunks/abc123"},
		{"GET", "/api/drive/nodes"},
		{"GET", "/api/drive/versions/42/content"},
		{"GET", "/api/drive/versions/42/preview"},
		// G3 Meet route inventory: every current method+shape is explicit.
		{"GET", "/api/meet"},
		{"POST", "/api/meet"},
		{"GET", "/api/meet/1"},
		{"GET", "/api/meet/by-slug/high-entropy_slug"},
		{"POST", "/api/meet/1/join"},
		{"POST", "/api/meet/1/knock"},
		{"POST", "/api/meet/1/lock"},
		{"POST", "/api/meet/1/settings"},
		{"POST", "/api/meet/1/role"},
		{"POST", "/api/meet/1/kick"},
		{"POST", "/api/meet/1/end"},
		{"POST", "/api/meet/1/recording"},
		{"DELETE", "/api/meet/1/recording"},
		{"POST", "/api/meet/1/captions"},
		{"DELETE", "/api/meet/1/captions"},
		{"POST", "/api/meet/1/requests/2"},
		{"POST", "/api/meet/1/breakouts"},
		{"POST", "/api/meet/1/breakouts/assign"},
		{"POST", "/api/meet/1/breakouts/close"},
		{"POST", "/api/meet/1/breakouts/join"},
		{"GET", "/api/public/meet/high-entropy_slug/join-request/2"},
		{"GET", "/rtc"},
		{"GET", "/rtc/rtc/v1"},
	}
	deny := [][2]string{
		// Meet remains deny-by-default for unenumerated methods/shapes.
		{"POST", "/api/meet/by-slug/standup"},
		{"GET", "/api/meet/1/recording"},
		{"POST", "/api/meet/1/unknown"},
		{"POST", "/api/meet/notanid/join"},
		{"POST", "/api/meet/1/join/extra"},
		{"POST", "/api/public/meet/slug/join-request"},
		{"GET", "/api/public/meet/slug/join-request/notanid"},
		{"GET", "/rtcx"},
		{"GET", "/rtcx/rtc/v1"},
		{"POST", "/api/user/profile"},       // P14(b): a guest may not rename itself (codex C-4)
		{"GET", "/api/auth/me/org-chart"},   // org-people walk (codex C-4) — /auth/me is EXACT, subpaths deny
		{"GET", "/auth/me/org-chart"},       // same, bare-root pinned form
		{"POST", "/api/drive/native-token"}, // DENIED outright in G0 (P11b)
		{"POST", "/api/drive/spaces"},       // the Drive blanket: 3 attachment routes only
		{"GET", "/api/drive/spaces"},
		{"GET", "/api/drive/versions/42"}, // versions listing is NOT the content route
		{"POST", "/jmap"},                 // the whole mail API at its BARE pinned root (the E-B1 hole)
		{"POST", "/api/jmap"},             // and via the mount
		{"POST", "/jmap/upload/1"},
		{"GET", "/jmap/download/1/2/x"},
		{"GET", "/api/contacts"},
		{"GET", "/api/admin/users"},
		{"GET", "/api/drive/versions/42/contentx"}, // suffix precision
		{"GET", "/api/drive/versions/notanid/content"},
		{"GET", "/api/drive/versions/42/previewx"},
		{"GET", "/api/drive/versions/notanid/preview"},
		{"POST", "/api/drive/versions/42/preview"},
	}
	for _, a := range allow {
		if !GuestAllowed(a[0], a[1]) {
			t.Errorf("expected ALLOW %s %s", a[0], a[1])
		}
	}
	for _, d := range deny {
		if GuestAllowed(d[0], d[1]) {
			t.Errorf("expected DENY %s %s", d[0], d[1])
		}
	}
}

func TestGuestGate_AcceptRoutes_Allowed(t *testing.T) {
	cases := []struct {
		method string
		path   string
	}{
		{"GET", "/auth/guest-invite/accept"},
		{"GET", "/api/auth/guest-invite/accept"},
		{"POST", "/auth/guest-invite/accept"},
		{"POST", "/api/auth/guest-invite/accept"},
		{"GET", "/guest-invite/accept"},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			if !GuestAllowed(tc.method, tc.path) {
				t.Errorf("GuestAllowed(%q, %q) = false; want true (pre-auth surface must be reachable)", tc.method, tc.path)
			}
		})
	}
}

func TestGuestGate_AcceptRoutes_NotOracle(t *testing.T) {
	cases := []struct {
		method string
		path   string
	}{
		{"PUT", "/auth/guest-invite/accept"},
		{"HEAD", "/auth/guest-invite/accept"},
		{"GET", "/auth/guest-invite/accept/extra"},
		{"POST", "/auth/guest-invite/accept/extra"},
		{"POST", "/guest-invite/accept"},
		{"GET", "/guest-invite"},
		{"GET", "/api/guest-invite/accept"},
		{"GET", "/apiguest-invite/accept"},
		{"GET", "/apiauth/guest-invite/accept"},
		{"POST", "/apiauth/guest-invite/accept"},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			if GuestAllowed(tc.method, tc.path) {
				t.Errorf("GuestAllowed(%q, %q) = true; want false", tc.method, tc.path)
			}
		})
	}
}
