package wellknown

import (
	"net/http"

	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/httputil"
)

// SetJoinResponse advertises server capabilities so clients can auto-configure
// on first connection. Follows RFC 8615 (.well-known).
type SetJoinResponse struct {
	Version         string   `json:"version"`
	CryptoProfile   string   `json:"crypto_profile"`   // "standard", "smx", "hybrid"
	CryptoAlgo      string   `json:"crypto_algorithm"` // "AES-256-GCM", "SM4-GCM"
	PushRelay       string   `json:"push_relay,omitempty"`
	MAMEnabled      bool     `json:"mam_enabled"`                 // whether MAM policies are enforced
	MAMMinVersion   int      `json:"mam_min_version"`             // minimum client version that supports MAM
	Features        []string `json:"features"`                    // list of supported features
	LoginField      string   `json:"login_field"`                 // "email" (default) or "upn"
	LoginDomainHint string   `json:"login_domain_hint,omitempty"` // domain hint for UPN, e.g. "@company.local"
}

// HandleSetJoin serves GET /.well-known/setjoin.
// No authentication required — this is a discovery endpoint.
func HandleSetJoin(cryptoProfile cryptokey.CryptoProfile, pushRelay string, mamEnabled bool, loginField string, loginDomainHint string) http.HandlerFunc {
	algo := cryptokey.AlgorithmTagFromProfile(cryptoProfile)
	if loginField == "" {
		loginField = "email"
	}

	return func(w http.ResponseWriter, r *http.Request) {
		resp := SetJoinResponse{
			Version:         "1.0",
			CryptoProfile:   string(cryptoProfile),
			CryptoAlgo:      algo.String(),
			PushRelay:       pushRelay,
			MAMEnabled:      mamEnabled,
			MAMMinVersion:   1,
			LoginField:      loginField,
			LoginDomainHint: loginDomainHint,
			Features: []string{
				"jmap",
				"mam",
				"push",
				string(cryptoProfile),
			},
		}

		w.Header().Set("Access-Control-Allow-Origin", "*")
		httputil.WriteJSON(w, http.StatusOK, resp)
	}
}
