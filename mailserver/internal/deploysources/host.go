package deploysources

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const maxHostSourceFile = 1 << 20

type HostSource struct {
	Type      string `json:"type"`
	Path      string `json:"path"`
	Location  string `json:"location,omitempty"`
	Ownership string `json:"ownership"`
	Status    string `json:"status"`
}

type HostPlan struct {
	MutatesHost bool     `json:"mutatesHost"`
	Steps       []string `json:"steps"`
}

type HostInventory struct {
	Supported    bool         `json:"supported"`
	Distribution string       `json:"distribution,omitempty"`
	Release      string       `json:"release,omitempty"`
	Architecture string       `json:"architecture"`
	Sources      []HostSource `json:"sources"`
	Diagnostics  []Diagnostic `json:"diagnostics"`
	Plan         HostPlan     `json:"plan"`
}

// InspectUbuntu reads only fixed apt, Docker and os-release paths below root.
// Symlinks and oversized files are reported but never followed.
func InspectUbuntu(root string) HostInventory {
	if root == "" {
		root = "/"
	}
	out := HostInventory{
		Architecture: runtime.GOARCH,
		Sources:      []HostSource{},
		Diagnostics:  []Diagnostic{},
		Plan: HostPlan{MutatesHost: false, Steps: []string{
			"inspect /etc/os-release",
			"inspect APT source definitions without changing them",
			"inspect Docker registry mirrors without changing them",
		}},
	}
	if raw, state := readFixed(root, "/etc/os-release"); state == "ok" {
		fields := parseKeyValues(raw)
		out.Distribution, out.Release = fields["ID"], fields["VERSION_ID"]
		out.Supported = out.Distribution == "ubuntu"
	} else {
		out.Diagnostics = append(out.Diagnostics, Diagnostic{Code: "os_release_" + state, Severity: "warning", Detail: "Ubuntu source inspection could not identify /etc/os-release"})
	}
	if !out.Supported {
		out.Diagnostics = append(out.Diagnostics, Diagnostic{Code: "unsupported_host", Severity: "warning", Detail: "managed host-source inventory currently supports Ubuntu only", Remediation: "use the external-host operator workflow"})
	}

	for _, path := range aptPaths(root) {
		display := displayPath(root, path)
		raw, state := readPath(path)
		if state != "ok" {
			out.Sources = append(out.Sources, HostSource{Type: "apt", Path: display, Ownership: ownership(display), Status: state})
			continue
		}
		out.Sources = append(out.Sources, parseAPT(display, raw)...)
	}
	if raw, state := readFixed(root, "/etc/docker/daemon.json"); state != "missing" {
		path := "/etc/docker/daemon.json"
		if state != "ok" {
			out.Sources = append(out.Sources, HostSource{Type: "docker_registry", Path: path, Ownership: ownership(path), Status: state})
		} else {
			out.Sources = append(out.Sources, parseDocker(path, raw)...)
		}
	}
	sort.Slice(out.Sources, func(i, j int) bool {
		a, b := out.Sources[i], out.Sources[j]
		return a.Type+a.Path+a.Location+a.Status < b.Type+b.Path+b.Location+b.Status
	})
	return out
}

func aptPaths(root string) []string {
	paths := []string{filepath.Join(root, "etc/apt/sources.list")}
	dir := filepath.Join(root, "etc/apt/sources.list.d")
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return paths
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return paths
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".list") || strings.HasSuffix(entry.Name(), ".sources") {
			paths = append(paths, filepath.Join(dir, entry.Name()))
		}
	}
	return paths
}

func readFixed(root, fixed string) ([]byte, string) {
	return readPath(filepath.Join(root, strings.TrimPrefix(fixed, "/")))
}

func readPath(path string) ([]byte, string) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, "missing"
	}
	if err != nil {
		return nil, "unreadable"
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, "symlink_ignored"
	}
	if !info.Mode().IsRegular() {
		return nil, "non_regular_ignored"
	}
	if info.Size() > maxHostSourceFile {
		return nil, "oversized_ignored"
	}
	// The caller cannot select an arbitrary file: every path is constructed from
	// the fixed os-release/APT/Docker inventory plus an injected test root, and
	// the Lstat checks above reject symlinks, non-regular files and oversized
	// inputs before this bounded read.
	raw, err := os.ReadFile(path) //nolint:gosec // G304: fixed inventory paths; root is an inspection/test prefix
	if err != nil {
		return nil, "unreadable"
	}
	return raw, "ok"
}

func parseKeyValues(raw []byte) map[string]string {
	out := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if ok {
			out[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"'`)
		}
	}
	return out
}

func parseAPT(path string, raw []byte) []HostSource {
	if strings.HasSuffix(path, ".sources") {
		return parseDeb822(path, raw)
	}
	rows := []HostSource{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		status := "active"
		if strings.HasPrefix(line, "#") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "#"))
			status = "disabled"
		}
		if !strings.HasPrefix(line, "deb ") && !strings.HasPrefix(line, "deb-src ") {
			continue
		}
		fields := strings.Fields(line)
		index := 1
		if index < len(fields) && strings.HasPrefix(fields[index], "[") {
			for index < len(fields) && !strings.HasSuffix(fields[index], "]") {
				index++
			}
			index++
		}
		location := ""
		if index < len(fields) {
			location = redactLocation(fields[index])
		} else {
			status = "malformed"
		}
		rows = append(rows, HostSource{Type: "apt", Path: path, Location: location, Ownership: ownership(path), Status: status})
	}
	return rows
}

func parseDeb822(path string, raw []byte) []HostSource {
	rows := []HostSource{}
	for _, block := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n\n") {
		fields := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			key, value, ok := strings.Cut(line, ":")
			if ok {
				fields[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
			}
		}
		if fields["uris"] == "" {
			continue
		}
		status := "active"
		if strings.EqualFold(fields["enabled"], "no") {
			status = "disabled"
		}
		for _, location := range strings.Fields(fields["uris"]) {
			rows = append(rows, HostSource{Type: "apt", Path: path, Location: redactLocation(location), Ownership: ownership(path), Status: status})
		}
	}
	return rows
}

func parseDocker(path string, raw []byte) []HostSource {
	var doc struct {
		Mirrors []string `json:"registry-mirrors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return []HostSource{{Type: "docker_registry", Path: path, Ownership: ownership(path), Status: "malformed"}}
	}
	rows := make([]HostSource, 0, len(doc.Mirrors))
	for _, mirror := range doc.Mirrors {
		rows = append(rows, HostSource{Type: "docker_registry", Path: path, Location: redactLocation(mirror), Ownership: ownership(path), Status: "active"})
	}
	if len(rows) == 0 {
		rows = append(rows, HostSource{Type: "docker_registry", Path: path, Ownership: ownership(path), Status: "no_mirrors"})
	}
	return rows
}

func redactLocation(raw string) string {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err == nil && u.Host != "" {
		u.User, u.RawQuery, u.Fragment = nil, "", ""
		return u.String()
	}
	if _, after, ok := strings.Cut(raw, "@"); ok {
		if cut := strings.IndexAny(after, "?#"); cut >= 0 {
			after = after[:cut]
		}
		return "[redacted]@" + after
	}
	if cut := strings.IndexAny(raw, "?#"); cut >= 0 {
		raw = raw[:cut]
	}
	if err != nil || raw == "" {
		return "[invalid]"
	}
	return raw
}

func ownership(path string) string {
	name := strings.ToLower(filepath.Base(path))
	if strings.HasPrefix(name, "setjoin.") || strings.HasPrefix(name, "setjoin-") {
		return "setjoin_managed"
	}
	return "external"
}

func displayPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return "/" + filepath.ToSlash(rel)
}

func (h HostInventory) ValidateNoWritePlan() error {
	if h.Plan.MutatesHost {
		return fmt.Errorf("host source plan unexpectedly permits mutation")
	}
	return nil
}
