package scim

import (
	"net/http"
)

// ServiceProviderConfig handles GET /scim/v2/ServiceProviderConfig.
// Returns a static SCIM ServiceProviderConfig response required by Okta and Entra ID
// for initial connection validation.
func (s *Server) ServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	cfg := map[string]interface{}{
		"schemas":          []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"documentationUri": "",
		"patch": map[string]interface{}{
			"supported": true,
		},
		"bulk": map[string]interface{}{
			"supported":      false,
			"maxOperations":  0,
			"maxPayloadSize": 0,
		},
		"filter": map[string]interface{}{
			"supported":  true,
			"maxResults": 1000,
		},
		"changePassword": map[string]interface{}{
			"supported": false,
		},
		"sort": map[string]interface{}{
			"supported": false,
		},
		"etag": map[string]interface{}{
			"supported": false,
		},
		"authenticationSchemes": []map[string]interface{}{
			{
				"name":        "OAuth Bearer Token",
				"description": "SCIM API token",
				"specUri":     "http://tools.ietf.org/html/rfc6750",
				"type":        "oauthbearertoken",
				"primary":     true,
			},
		},
	}

	WriteSCIM(w, http.StatusOK, cfg)
}
