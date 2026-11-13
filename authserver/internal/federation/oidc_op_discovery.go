package federation

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"

	"setjoin.com/shared/jwtutil"
)

// SupportedACRValues are the Authentication Context Class References this OP can
// assert in id_tokens — the NIST AAL ladder. Advertised in discovery's
// acr_values_supported so relying parties know they can request step-up.
var SupportedACRValues = []string{jwtutil.ACRAAL1, jwtutil.ACRAAL2}

// discoveryFallbacks are the OIDC-discovery fields the wrapper guarantees are
// present. zitadel populates scopes_supported, claims_supported,
// code_challenge_methods_supported and grant_types_supported from its config,
// but exposes no hook for acr_values_supported and may omit a field if the
// config is sparse. The wrapper injects any missing key from these fallbacks
// (never clobbering a value zitadel already provided), so an OAuth/OIDC client
// can always discover scopes, claims, PKCE methods, and the AAL ladder.
var discoveryFallbacks = map[string][]string{
	"acr_values_supported":             SupportedACRValues,
	"code_challenge_methods_supported": {"S256"},
	"scopes_supported":                 {"openid", "profile", "email", "offline_access"},
	"claims_supported": {
		"sub", "email", "email_verified", "name", "acr", "amr",
		"iss", "aud", "exp", "iat", "auth_time", "nonce",
	},
}

// discoveryOverrides narrow capabilities that zitadel advertises at the
// provider level but this storage/client implementation deliberately does not
// support. Setjoin's OP is authorization-code + refresh only.
var discoveryOverrides = map[string][]string{
	"response_types_supported": {"code"},
	"grant_types_supported":    {"authorization_code", "refresh_token"},
}

// OPDiscoveryWrapper wraps the zitadel OP handler so the discovery document
// (/.well-known/openid-configuration) additionally advertises
// acr_values_supported. zitadel's CreateDiscoveryConfig omits that field and
// exposes no hook to set it, so we post-process the JSON for the discovery path
// only; every other path (authorize, token, userinfo, jwks, …) passes straight
// through untouched. The acr/amr claims themselves are already in zitadel's
// default claims_supported.
type OPDiscoveryWrapper struct {
	inner http.Handler
}

// NewOPDiscoveryWrapper returns a handler that augments the OP discovery
// document with acr_values_supported and otherwise delegates to inner.
func NewOPDiscoveryWrapper(inner http.Handler) *OPDiscoveryWrapper {
	return &OPDiscoveryWrapper{inner: inner}
}

func (h *OPDiscoveryWrapper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !isDiscoveryRequest(r) {
		h.inner.ServeHTTP(w, r)
		return
	}

	rec := &discoveryRecorder{header: http.Header{}, status: http.StatusOK}
	h.inner.ServeHTTP(rec, r)

	augmented, ok := augmentDiscovery(rec.body.Bytes())
	if !ok {
		// Not JSON we could augment (e.g. an error response) — pass through verbatim.
		copyHeader(w.Header(), rec.header)
		w.WriteHeader(rec.status)
		w.Write(rec.body.Bytes())
		return
	}

	copyHeader(w.Header(), rec.header)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Del("Content-Length") // body length changed
	w.WriteHeader(rec.status)
	w.Write(augmented)
}

// isDiscoveryRequest reports whether the request targets the OIDC discovery
// document.
func isDiscoveryRequest(r *http.Request) bool {
	return r.Method == http.MethodGet &&
		strings.HasSuffix(r.URL.Path, "/.well-known/openid-configuration")
}

// augmentDiscovery parses the discovery JSON and injects any of the guaranteed
// fields (acr_values_supported, code_challenge_methods_supported,
// scopes_supported, claims_supported) the OP did not already provide, then
// re-serializes. A value the OP supplied is never clobbered. Returns false when
// the body is not a JSON object (e.g. an error response), so the caller passes
// it through verbatim.
func augmentDiscovery(body []byte) ([]byte, bool) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, false
	}
	for key, fallback := range discoveryFallbacks {
		if _, exists := doc[key]; exists {
			continue
		}
		raw, err := json.Marshal(fallback)
		if err != nil {
			return nil, false
		}
		doc[key] = raw
	}
	for key, values := range discoveryOverrides {
		raw, err := json.Marshal(values)
		if err != nil {
			return nil, false
		}
		doc[key] = raw
	}
	// zitadel includes the device endpoint even when Storage does not implement
	// DeviceAuthorizationStorage. Advertising a guaranteed 404/unsupported
	// endpoint is a discovery contract violation, so omit it.
	delete(doc, "device_authorization_endpoint")
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, false
	}
	return out, true
}

func copyHeader(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// discoveryRecorder buffers a handler's response so the body can be rewritten
// before it is flushed to the real ResponseWriter.
type discoveryRecorder struct {
	header      http.Header
	body        bytes.Buffer
	status      int
	wroteHeader bool
}

func (rec *discoveryRecorder) Header() http.Header { return rec.header }

func (rec *discoveryRecorder) WriteHeader(status int) {
	if rec.wroteHeader {
		return
	}
	rec.status = status
	rec.wroteHeader = true
}

func (rec *discoveryRecorder) Write(b []byte) (int, error) {
	if !rec.wroteHeader {
		rec.WriteHeader(http.StatusOK)
	}
	return rec.body.Write(b)
}
