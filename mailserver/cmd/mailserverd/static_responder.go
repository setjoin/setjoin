package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"setjoin.com/mailserver/internal/middleware"
)

const staticRepresentationManifest = "static-representations.v1.json"

type staticSidecar struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type staticAssetRecord struct {
	Path            string                   `json:"path"`
	IdentityBytes   int64                    `json:"identityBytes"`
	IdentitySHA256  string                   `json:"identitySha256"`
	Representations map[string]staticSidecar `json:"representations"`
}

type staticAssetManifest struct {
	SchemaVersion int                 `json:"schemaVersion"`
	BuildID       string              `json:"buildId"`
	Assets        []staticAssetRecord `json:"assets"`
}

type spaStaticHandler struct {
	root       string
	assets     map[string]staticAssetRecord
	needsSetup func(*http.Request) bool
}

func newSPAStaticHandler(root string, needsSetup func(*http.Request) bool) (http.Handler, error) {
	cleanRoot, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return nil, fmt.Errorf("resolve webmail root: %w", err)
	}
	info, err := os.Stat(cleanRoot)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("webmail root is not a directory: %w", err)
	}
	assets, err := loadStaticAssetManifest(cleanRoot)
	if err != nil {
		return nil, err
	}
	return &spaStaticHandler{root: cleanRoot, assets: assets, needsSetup: needsSetup}, nil
}

func loadStaticAssetManifest(root string) (map[string]staticAssetRecord, error) {
	manifestPath := filepath.Join(root, staticRepresentationManifest)
	// #nosec G304 -- root is startup-cleaned to an absolute operator-configured
	// directory; the filename is a fixed constant, never request input.
	bytes, err := os.ReadFile(manifestPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("static representation manifest is missing")
	}
	if err != nil {
		return nil, fmt.Errorf("read static representation manifest: %w", err)
	}
	var manifest staticAssetManifest
	if err := json.Unmarshal(bytes, &manifest); err != nil {
		return nil, fmt.Errorf("decode static representation manifest: %w", err)
	}
	// #nosec G304 -- both path components are fixed beneath the same validated root.
	versionBytes, err := os.ReadFile(filepath.Join(root, "_app", "version.json"))
	if err != nil {
		return nil, fmt.Errorf("read webmail build version: %w", err)
	}
	var version struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(versionBytes, &version); err != nil || version.Version == "" {
		return nil, errors.New("decode webmail build version")
	}
	if manifest.SchemaVersion != 1 || manifest.BuildID != version.Version {
		return nil, errors.New("static representation manifest does not match the webmail build")
	}
	assets := make(map[string]staticAssetRecord, len(manifest.Assets))
	declaredSidecars := make(map[string]struct{})
	for _, asset := range manifest.Assets {
		urlPath, fullPath, ok := containedStaticPath(root, asset.Path)
		if !ok || urlPath == "/"+staticRepresentationManifest {
			return nil, fmt.Errorf("invalid static identity path %q", asset.Path)
		}
		if _, duplicate := assets[urlPath]; duplicate {
			return nil, fmt.Errorf("duplicate static identity path %q", urlPath)
		}
		if err := verifyStaticFile(fullPath, asset.IdentityBytes, asset.IdentitySHA256); err != nil {
			return nil, fmt.Errorf("verify identity %s: %w", urlPath, err)
		}
		asset.Path = urlPath
		for encoding, sidecar := range asset.Representations {
			suffix := map[string]string{"br": ".br", "gzip": ".gz"}[encoding]
			if suffix == "" {
				return nil, fmt.Errorf("unsupported static encoding %q", encoding)
			}
			sidecarPath, sidecarFullPath, sidecarOK := containedStaticPath(root, sidecar.Path)
			if !sidecarOK || sidecarPath != urlPath+suffix || sidecar.Bytes >= asset.IdentityBytes {
				return nil, fmt.Errorf("misbound static sidecar %q", sidecar.Path)
			}
			if err := verifyStaticFile(sidecarFullPath, sidecar.Bytes, sidecar.SHA256); err != nil {
				return nil, fmt.Errorf("verify sidecar %s: %w", sidecarPath, err)
			}
			sidecar.Path = sidecarPath
			asset.Representations[encoding] = sidecar
			declaredSidecars[sidecarPath] = struct{}{}
		}
		assets[urlPath] = asset
	}
	var identityPaths []string
	err = filepath.WalkDir(root, func(filePath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("webmail build contains symlink %s", filePath)
		}
		if entry.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(root, filePath)
		if relErr != nil {
			return relErr
		}
		urlPath := "/" + filepath.ToSlash(rel)
		if strings.HasSuffix(urlPath, ".br") || strings.HasSuffix(urlPath, ".gz") {
			if _, ok := declaredSidecars[urlPath]; !ok {
				return fmt.Errorf("undeclared static sidecar %s", urlPath)
			}
			return nil
		}
		if urlPath != "/"+staticRepresentationManifest {
			identityPaths = append(identityPaths, urlPath)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(identityPaths)
	for _, identityPath := range identityPaths {
		if _, ok := assets[identityPath]; !ok {
			return nil, fmt.Errorf("undeclared static identity %s", identityPath)
		}
	}
	return assets, nil
}

func containedStaticPath(root, requestPath string) (string, string, bool) {
	if requestPath == "" || strings.ContainsRune(requestPath, '\x00') || strings.Contains(requestPath, "\\") {
		return "", "", false
	}
	for _, segment := range strings.Split(requestPath, "/") {
		if segment == ".." {
			return "", "", false
		}
	}
	cleanURLPath := path.Clean("/" + strings.TrimPrefix(requestPath, "/"))
	relativePath := filepath.FromSlash(strings.TrimPrefix(cleanURLPath, "/"))
	fullPath := filepath.Join(root, relativePath)
	rel, err := filepath.Rel(root, fullPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", "", false
	}
	return cleanURLPath, fullPath, true
}

func verifyStaticFile(filePath string, expectedBytes int64, expectedSHA256 string) error {
	if expectedBytes < 0 || len(expectedSHA256) != sha256.Size*2 {
		return errors.New("invalid size or SHA-256")
	}
	file, err := os.Open(filePath) //nolint:gosec // path is contained by containedStaticPath before this call
	if err != nil {
		return err
	}
	defer file.Close()
	hasher := sha256.New()
	written, err := io.Copy(hasher, file)
	if err != nil {
		return err
	}
	if written != expectedBytes || hex.EncodeToString(hasher.Sum(nil)) != expectedSHA256 {
		return errors.New("size or SHA-256 mismatch")
	}
	return nil
}

type acceptedCoding struct {
	quality  float64
	explicit bool
}

func parseAcceptEncoding(header string) map[string]acceptedCoding {
	values := make(map[string]acceptedCoding)
	for _, item := range strings.Split(strings.ToLower(header), ",") {
		parts := strings.Split(strings.TrimSpace(item), ";")
		name := strings.TrimSpace(parts[0])
		if name == "" {
			continue
		}
		quality := 1.0
		for _, parameter := range parts[1:] {
			keyValue := strings.SplitN(strings.TrimSpace(parameter), "=", 2)
			if len(keyValue) == 2 && strings.TrimSpace(keyValue[0]) == "q" {
				parsed, err := strconv.ParseFloat(strings.TrimSpace(keyValue[1]), 64)
				if err != nil || parsed < 0 || parsed > 1 {
					quality = 0
				} else {
					quality = parsed
				}
			}
		}
		if current, ok := values[name]; !ok || quality > current.quality {
			values[name] = acceptedCoding{quality: quality, explicit: true}
		}
	}
	return values
}

func codingQuality(values map[string]acceptedCoding, name string, headerPresent bool) acceptedCoding {
	if value, ok := values[name]; ok {
		return value
	}
	if name != "identity" {
		if wildcard, ok := values["*"]; ok {
			return wildcard
		}
		return acceptedCoding{}
	}
	if !headerPresent {
		return acceptedCoding{quality: 1}
	}
	if wildcard, ok := values["*"]; ok && wildcard.quality == 0 {
		// RFC 9110: identity is acceptable by default unless identity;q=0 or
		// *;q=0 excludes it without a more specific identity preference.
		return acceptedCoding{}
	}
	// Identity is the safe fallback, but an implicit identity does not outrank a
	// positive content coding. An explicit identity q-value is honored normally.
	return acceptedCoding{quality: 0.000001}
}

func chooseStaticRepresentation(record staticAssetRecord, acceptEncoding string, rangeRequest bool) (string, staticSidecar, bool) {
	values := parseAcceptEncoding(acceptEncoding)
	headerPresent := strings.TrimSpace(acceptEncoding) != ""
	identity := codingQuality(values, "identity", headerPresent)
	if rangeRequest {
		return "identity", staticSidecar{}, identity.quality > 0
	}
	type choice struct {
		name    string
		quality float64
		rank    int
		sidecar staticSidecar
	}
	choices := []choice{{name: "identity", quality: identity.quality, rank: 1}}
	for _, candidate := range []struct {
		name string
		rank int
	}{{"br", 3}, {"gzip", 2}} {
		if sidecar, ok := record.Representations[candidate.name]; ok {
			quality := codingQuality(values, candidate.name, headerPresent).quality
			choices = append(choices, choice{name: candidate.name, quality: quality, rank: candidate.rank, sidecar: sidecar})
		}
	}
	sort.SliceStable(choices, func(i, j int) bool {
		if choices[i].quality == choices[j].quality {
			return choices[i].rank > choices[j].rank
		}
		return choices[i].quality > choices[j].quality
	})
	if choices[0].quality <= 0 {
		return "", staticSidecar{}, false
	}
	return choices[0].name, choices[0].sidecar, true
}

func (handler *spaStaticHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		http.NotFound(writer, request)
		return
	}
	if request.URL.Path == "/" && handler.needsSetup != nil && handler.needsSetup(request) {
		http.Redirect(writer, request, "/setup", http.StatusFound)
		return
	}
	urlPath, fullPath, ok := containedStaticPath(handler.root, request.URL.Path)
	if !ok {
		http.NotFound(writer, request)
		return
	}
	// #nosec G703 -- containedStaticPath rejects NUL, backslash and parent
	// segments, then proves filepath.Rel remains beneath handler.root.
	if info, err := os.Stat(fullPath); err == nil && !info.IsDir() {
		handler.serveFile(writer, request, urlPath, fullPath, handler.assets[urlPath])
		return
	}
	if isAssetPath(request.URL.Path) {
		http.NotFound(writer, request)
		return
	}
	handler.serveFile(writer, request, "/index.html", filepath.Join(handler.root, "index.html"), handler.assets["/index.html"])
}

func (handler *spaStaticHandler) serveFile(writer http.ResponseWriter, request *http.Request, urlPath, identityPath string, record staticAssetRecord) {
	rangeRequest := request.Header.Get("Range") != ""
	encoding, sidecar, acceptable := chooseStaticRepresentation(record, request.Header.Get("Accept-Encoding"), rangeRequest)
	if !acceptable {
		writer.WriteHeader(http.StatusNotAcceptable)
		return
	}
	selectedPath := identityPath
	selectedHash := record.IdentitySHA256
	if encoding != "identity" {
		_, selectedPath, _ = containedStaticPath(handler.root, sidecar.Path)
		selectedHash = sidecar.SHA256
		writer.Header().Set("Content-Encoding", encoding)
	}
	writer.Header().Set("Vary", "Accept-Encoding")
	if selectedHash != "" {
		writer.Header().Set("ETag", `"sha256-`+selectedHash+`"`)
	}
	// WP2: the RESOLVED representation (SPA fallback serves /index.html under
	// a different request path) is the one fact only this handler knows; the
	// Cache-Control VALUE stays table-owned (middleware.staticCachePolicy).
	middleware.ResolveStaticCacheRepresentation(request.Context(), urlPath)
	if contentType := staticContentType(urlPath); contentType != "" {
		writer.Header().Set("Content-Type", contentType)
	}
	file, err := os.Open(selectedPath) //nolint:gosec // selected path is constructor-validated or contained above
	if err != nil {
		http.NotFound(writer, request)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		http.NotFound(writer, request)
		return
	}
	servedRequest := request
	if encoding != "identity" && rangeRequest {
		servedRequest = request.Clone(request.Context())
		servedRequest.Header = request.Header.Clone()
		servedRequest.Header.Del("Range")
	}
	http.ServeContent(writer, servedRequest, path.Base(urlPath), info.ModTime(), file)
}

func staticContentType(urlPath string) string {
	switch strings.ToLower(filepath.Ext(urlPath)) {
	case ".js", ".mjs":
		return "text/javascript; charset=utf-8"
	case ".json":
		return "application/json"
	case ".webmanifest":
		return "application/manifest+json"
	}
	return mime.TypeByExtension(filepath.Ext(urlPath))
}
