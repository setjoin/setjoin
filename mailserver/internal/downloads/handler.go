// Package downloads serves the self-hosted download page and proxies binary
// assets from the appropriate mirror (GitHub, Gitee, or local air-gap bundle).
package downloads

import (
	"encoding/json"
	"net/http"
)

// Platform describes a downloadable client for a specific OS/arch.
type Platform struct {
	Name     string `json:"name"`      // e.g. "macOS (Apple Silicon)"
	Slug     string `json:"slug"`      // e.g. "macos-arm64"
	Ext      string `json:"ext"`       // e.g. "dmg", "msi", "AppImage"
	StoreURL string `json:"store_url"` // empty if direct download from gateway
}

// DesktopPlatforms lists all downloadable desktop clients.
// Mobile clients are store-only — links to App Store / Play Store / AppGallery
// are rendered by the Svelte downloads page.
var DesktopPlatforms = []Platform{
	{Name: "macOS (Apple Silicon)", Slug: "macos-arm64", Ext: "dmg"},
	{Name: "macOS (Intel)", Slug: "macos-x86_64", Ext: "dmg"},
	{Name: "Windows (x64)", Slug: "windows-x86_64", Ext: "msi"},
	{Name: "Windows (ARM64)", Slug: "windows-arm64", Ext: "msi"},
	{Name: "Linux (x64 AppImage)", Slug: "linux-x86_64", Ext: "AppImage"},
	{Name: "Linux (deb)", Slug: "linux-x86_64-deb", Ext: "deb"},
	{Name: "Linux (rpm)", Slug: "linux-x86_64-rpm", Ext: "rpm"},
}

// HandleDownloadsPage returns a handler for GET /downloads.
// Returns a JSON list of downloadable platforms. The "versions" map is always
// empty: the gateway does not pin per-platform release versions (see
// HandleDownloadAsset — the mirror resolves the current release for "latest").
// The key is kept in the response so the frontend JSON shape stays stable.
func HandleDownloadsPage() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		resp := map[string]any{
			"platforms": DesktopPlatforms,
			"versions":  map[string]string{},
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "response write failed", http.StatusInternalServerError)
		}
	}
}

// HandleDownloadAsset returns a handler for GET /downloads/{platform}.
// Redirects to the appropriate download mirror for the given platform slug.
// The asset name is constructed as SetJoin_{version}_{slug}.{ext}.
func HandleDownloadAsset() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		slug := r.PathValue("platform")
		if slug == "" {
			http.Error(w, "platform is required", http.StatusBadRequest)
			return
		}

		// Find the platform by slug.
		var platform *Platform
		for i := range DesktopPlatforms {
			if DesktopPlatforms[i].Slug == slug {
				platform = &DesktopPlatforms[i]
				break
			}
		}
		if platform == nil {
			http.Error(w, "unknown platform", http.StatusNotFound)
			return
		}

		// If this is a store-only platform (no ext), redirect to store.
		if platform.StoreURL != "" {
			http.Redirect(w, r, platform.StoreURL, http.StatusFound)
			return
		}

		// The gateway does not pin per-platform versions; the mirror resolves
		// the current release for the "latest" segment.
		version := "latest"

		// Construct the asset name and redirect. Use platform.Slug (from the
		// hardcoded DesktopPlatforms allowlist), not the raw request slug, so the
		// redirect target can only ever be built from trusted, fixed segments.
		asset := "SetJoin_" + version + "_" + platform.Slug + "." + platform.Ext

		// Redirect to the gateway's download proxy endpoint, which in turn
		// proxies from the appropriate mirror (GitHub/Gitee/local).
		downloadURL := "/downloads/asset/" + asset
		http.Redirect(w, r, downloadURL, http.StatusFound)
	}
}
