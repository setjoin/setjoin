package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"setjoin.com/shared/httputil"
)

const serverVersion = "2.5.0"

// VersionResponse is the JSON payload for the client version check endpoint.
type VersionResponse struct {
	ServerVersion    string `json:"server_version"`
	MinClientVersion string `json:"min_client_version,omitempty"`
	LatestVersion    string `json:"latest_version,omitempty"`
	UpdateType       string `json:"update_type"` // up_to_date | update_available | update_required | blocked
	UpdateURL        string `json:"update_url,omitempty"`
	SHA256           string `json:"sha256,omitempty"`
	ReleaseNotes     string `json:"release_notes,omitempty"`
	ReleaseDate      string `json:"release_date,omitempty"`
}

// ClientVersion checks for available client updates.
//
// GET /api/v1/version?client={semver}&platform={ios|android}&app={mail|guard}
// No authentication required.
func (h *loginHandler) ClientVersion(w http.ResponseWriter, r *http.Request) {
	clientVer := r.URL.Query().Get("client")
	platform := r.URL.Query().Get("platform")
	app := r.URL.Query().Get("app")

	resp := VersionResponse{
		ServerVersion: serverVersion,
	}

	// If no client params provided, just return server version
	if clientVer == "" || platform == "" || app == "" {
		resp.UpdateType = "up_to_date"
		httputil.WriteJSON(w, http.StatusOK, resp)
		return
	}

	// Defaults when DB is not available
	resp.UpdateType = "up_to_date"

	if h.pool == nil {
		httputil.WriteJSON(w, http.StatusOK, resp)
		return
	}

	// Query latest version for this platform/app
	var latestVer, sha256, releaseNotes, filePath string
	var releaseDate time.Time
	err := h.pool.QueryRow(r.Context(),
		`SELECT version, sha256, COALESCE(release_notes,''), COALESCE(file_path,''), release_date
		 FROM client_versions
		 WHERE platform = $1 AND app = $2
		 ORDER BY string_to_array(version, '.')::int[] DESC LIMIT 1`,
		platform, app,
	).Scan(&latestVer, &sha256, &releaseNotes, &filePath, &releaseDate)
	if err != nil {
		// No versions published yet — client is up to date
		httputil.WriteJSON(w, http.StatusOK, resp)
		return
	}

	resp.LatestVersion = latestVer
	resp.ReleaseDate = releaseDate.Format(time.RFC3339)
	resp.ReleaseNotes = releaseNotes

	cmp := semverCompare(clientVer, latestVer)
	resp.UpdateType = classifyUpdate(clientVer, latestVer, cmp)

	if resp.UpdateType != "up_to_date" && filePath != "" {
		host := r.Host
		if host == "" {
			host = "localhost"
		}
		resp.UpdateURL = fmt.Sprintf("https://%s/clients/%s/%s/%s", host, platform, latestVer, filePath)
		resp.SHA256 = sha256
	}

	httputil.WriteJSON(w, http.StatusOK, resp)
}

// WellKnown serves the SetJoin discovery document.
//
// GET /.well-known/setjoin
// No authentication required.
func (h *loginHandler) WellKnown(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if host == "" {
		host = "localhost"
	}
	resp := map[string]string{
		"version":        serverVersion,
		"jmap_session":   fmt.Sprintf("https://%s/jmap/session", host),
		"client_version": fmt.Sprintf("https://%s/api/v1/version", host),
		"clients_base":   fmt.Sprintf("https://%s/clients", host),
	}
	httputil.WriteJSON(w, http.StatusOK, resp)
}

// classifyUpdate determines the update severity based on version comparison.
func classifyUpdate(client, latest string, cmp int) string {
	if cmp >= 0 {
		return "up_to_date"
	}
	clientMaj, clientMin := parseSemVer(client)
	latestMaj, latestMin := parseSemVer(latest)
	if clientMaj < latestMaj {
		return "blocked"
	}
	if latestMin-clientMin >= 2 {
		return "update_required"
	}
	return "update_available"
}

// parseSemVer extracts major and minor version numbers from a SemVer-like string.
// Returns (0, 0) on parse failure.
func parseSemVer(v string) (major, minor int) {
	if v == "" {
		return 0, 0
	}
	parts := strings.SplitN(v, ".", 3)
	if len(parts) >= 1 {
		major, _ = strconv.Atoi(parts[0])
	}
	if len(parts) >= 2 {
		minor, _ = strconv.Atoi(parts[1])
	}
	return major, minor
}

// semverCompare compares two SemVer-like strings.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
func semverCompare(a, b string) int {
	aParts := strings.SplitN(a, ".", 3)
	bParts := strings.SplitN(b, ".", 3)

	for i := 0; i < 3; i++ {
		av, bv := 0, 0
		if i < len(aParts) {
			av, _ = strconv.Atoi(aParts[i])
		}
		if i < len(bParts) {
			bv, _ = strconv.Atoi(bParts[i])
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
}
