// Package appmarket implements the closed Collabora CODE test-application
// lifecycle. It is deliberately not a public plug-in or arbitrary-container
// executor.
package appmarket

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var executionIdentityPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

const (
	managedOwnerLabel        = "com.setjoin.owner"
	managedInstallationLabel = "com.setjoin.installation"
	managedAppLabel          = "com.setjoin.app"
	managedPlanLabel         = "com.setjoin.plan"
	managedOperationLabel    = "com.setjoin.operation"
	managedOwner             = "setjoin-managed-app"
)

// ExecutionIdentity fences Docker resources to one Setjoin installation and
// one reducer-authorized operation. It is runtime state and is never accepted
// from the signed/static application manifest.
type ExecutionIdentity struct {
	InstallationID string
	OperationID    string
}

// ProviderBinding is reducer-authorized runtime input. It is never read from
// the static app manifest or accepted from the Docker command line.
type ProviderBinding struct {
	WOPIOrigin                 string
	AllowInsecureTestTransport bool
}

type Manifest struct {
	SchemaVersion   int               `json:"schemaVersion"`
	AppID           string            `json:"appId"`
	DisplayName     string            `json:"displayName"`
	Channel         string            `json:"channel"`
	Source          string            `json:"source"`
	Image           string            `json:"image"`
	Digest          string            `json:"digest"`
	PlatformDigests map[string]string `json:"platformDigests"`
	ContainerName   string            `json:"containerName"`
	NetworkName     string            `json:"networkName"`
	ConfigVolume    string            `json:"configVolume"`
	ListenAddress   string            `json:"listenAddress"`
	ListenPort      int               `json:"listenPort"`
	License         string            `json:"license"`
	LicenseSource   string            `json:"licenseSource"`
	SourceCode      string            `json:"sourceCode"`
	SupportProfile  string            `json:"supportProfile"`
	RetrievedAt     string            `json:"retrievedAt"`
	Execution       ExecutionIdentity `json:"-"`
	Provider        ProviderBinding   `json:"-"`
}

// RuntimePlan is the single typed source for the closed Collabora Docker
// invocation. Hash is derived from CanonicalJSON and deliberately excludes the
// execution identity so a retry of the same package retains the same plan.
type RuntimePlan struct {
	SchemaVersion   int
	AppID           string
	Image           string
	PlatformDigests PlatformDigestPlan
	ContainerName   string
	NetworkName     string
	ConfigVolume    string
	ListenAddress   string
	ListenPort      int
	Capabilities    []string
	Tmpfs           []string
	PIDsLimit       int
	Memory          string
	CPUs            string
	Restart         string
	LogMaxSize      string
	LogMaxFiles     int
	Environment     []string
	ExtraHosts      []string
	PlanHash        string
	Execution       ExecutionIdentity
}

// PlatformDigestPlan avoids map-order ambiguity in the canonical plan.
type PlatformDigestPlan struct {
	LinuxAMD64 string `json:"linux/amd64"`
	LinuxARM64 string `json:"linux/arm64"`
}

type canonicalRuntimePlan struct {
	SchemaVersion   int                `json:"schemaVersion"`
	AppID           string             `json:"appId"`
	Image           string             `json:"image"`
	PlatformDigests PlatformDigestPlan `json:"platformDigests"`
	ContainerName   string             `json:"containerName"`
	NetworkName     string             `json:"networkName"`
	ConfigVolume    string             `json:"configVolume"`
	ListenAddress   string             `json:"listenAddress"`
	ListenPort      int                `json:"listenPort"`
	Capabilities    []string           `json:"capabilities"`
	Tmpfs           []string           `json:"tmpfs"`
	PIDsLimit       int                `json:"pidsLimit"`
	Memory          string             `json:"memory"`
	CPUs            string             `json:"cpus"`
	Restart         string             `json:"restart"`
	LogMaxSize      string             `json:"logMaxSize"`
	LogMaxFiles     int                `json:"logMaxFiles"`
	Environment     []string           `json:"environment"`
	ExtraHosts      []string           `json:"extraHosts,omitempty"`
}

func ReadManifest(path string) (Manifest, error) {
	// The daemon's root-controlled --office-app-manifest flag owns this path;
	// application requests cannot select an arbitrary file.
	raw, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return Manifest{}, fmt.Errorf("read app manifest: %w", err)
	}
	var manifest Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode app manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func (m Manifest) Validate() error {
	if m.SchemaVersion != 1 || m.AppID != "collabora-code" || m.Channel != "test" ||
		m.Source != "docker.io/collabora/code" || m.ContainerName != "setjoin-collabora-code" ||
		m.NetworkName != "setjoin-office" || m.ConfigVolume != "setjoin-collabora-config" || m.ListenAddress != "127.0.0.1" ||
		m.ListenPort != 9980 || m.License != "MPL-2.0" ||
		m.SupportProfile != "self-supported-test" || !digestPattern.MatchString(m.Digest) ||
		m.Image != "collabora/code@"+m.Digest {
		return errors.New("managed Office manifest violates the closed Collabora package contract")
	}
	for _, platform := range []string{"linux/amd64", "linux/arm64"} {
		if !digestPattern.MatchString(m.PlatformDigests[platform]) {
			return fmt.Errorf("managed Office manifest lacks a valid %s digest", platform)
		}
	}
	return nil
}

// WithExecution returns a manifest bound to reducer-authorized runtime facts.
func (m Manifest) WithExecution(installationID, operationID string) Manifest {
	m.Execution = ExecutionIdentity{InstallationID: installationID, OperationID: operationID}
	return m
}

// WithProvider binds the WOPI origin selected by the reducer-authorized
// operation. HTTP is accepted only for the explicit one-shot E2E rail.
func (m Manifest) WithProvider(wopiPublicBaseURL string, allowInsecureTestTransport bool) Manifest {
	m.Provider = ProviderBinding{WOPIOrigin: wopiPublicBaseURL, AllowInsecureTestTransport: allowInsecureTestTransport}
	return m
}

// wopiHostnamePattern is the RFC 1123 DNS-label grammar for the WOPI hostname.
// collaboraAlias interpolates the hostname into the coolwsd aliasgroup1 value,
// where ',' is the ALIAS SEPARATOR: RFC 3986 sub-delims (notably ',', ';', '=')
// are legal in a URI reg-name and pass url.Parse unharmed, so the hostname must
// be re-validated against a strict DNS grammar — extra labels must never be
// smuggled into the allow-list field (D-MAILSERVER-INTERNAL-APPMARKET-004).
var wopiHostnamePattern = regexp.MustCompile(
	`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

func validWOPIHostname(hostname string) bool {
	if hostname == "" {
		return false
	}
	if net.ParseIP(hostname) != nil {
		return true // bracketed IPv6 / dotted-quad literal, re-bracketed by caller contract
	}
	return wopiHostnamePattern.MatchString(hostname)
}

func collaboraAlias(binding ProviderBinding) (string, bool, error) {
	parsed, err := url.Parse(strings.TrimSpace(binding.WOPIOrigin))
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" {
		return "", false, errors.New("managed Office WOPI origin is invalid")
	}
	hostname := strings.ToLower(parsed.Hostname())
	// Strict hostname grammar: reject RFC 3986 sub-delims (',', ';', '=', '&'
	// ...) that url.Parse tolerates in a reg-name — any character that
	// aliasgroup1 or the Docker env boundary could re-read as structure.
	if !validWOPIHostname(hostname) {
		return "", false, errors.New("managed Office WOPI origin hostname is not a valid DNS name")
	}
	port := parsed.Port()
	if port != "" {
		portNumber, conversionErr := strconv.Atoi(port)
		if conversionErr != nil || portNumber < 1 || portNumber > 65535 {
			return "", false, errors.New("managed Office WOPI origin port is invalid")
		}
	}
	if parsed.Scheme == "https" {
		if hostname == "" {
			return "", false, errors.New("managed Office WOPI HTTPS origin is invalid")
		}
		if port == "" {
			port = "443"
		}
		return "https://" + regexp.QuoteMeta(hostname) + ":" + port, false, nil
	}
	if parsed.Scheme == "http" && binding.AllowInsecureTestTransport &&
		(hostname == "host.docker.internal" || hostname == "127.0.0.1") && port != "" {
		return "http://" + regexp.QuoteMeta(hostname) + ":" + port, true, nil
	}
	return "", false, errors.New("managed Office WOPI origin must use HTTPS")
}

// CompileRuntimePlan compiles every Docker behavior-bearing setting into one
// canonical, hash-addressed plan. Callers must bind execution identity first.
func CompileRuntimePlan(m Manifest) (RuntimePlan, error) {
	if err := m.Validate(); err != nil {
		return RuntimePlan{}, err
	}
	if !executionIdentityPattern.MatchString(m.Execution.InstallationID) ||
		!executionIdentityPattern.MatchString(m.Execution.OperationID) {
		return RuntimePlan{}, errors.New("managed Office execution identity is missing or invalid")
	}
	alias, directHTTP, err := collaboraAlias(m.Provider)
	if err != nil {
		return RuntimePlan{}, err
	}
	extraParams := "--o:ssl.enable=false --o:ssl.termination=true --o:welcome.enable=false --o:mount_jail_tree=false"
	var extraHosts []string
	if directHTTP {
		extraParams = "--o:ssl.enable=false --o:ssl.termination=false --o:welcome.enable=false --o:mount_jail_tree=false"
		extraHosts = []string{"host.docker.internal:host-gateway"}
	}
	canonical := canonicalRuntimePlan{
		SchemaVersion: 1,
		AppID:         m.AppID,
		Image:         m.Image,
		PlatformDigests: PlatformDigestPlan{
			LinuxAMD64: m.PlatformDigests["linux/amd64"],
			LinuxARM64: m.PlatformDigests["linux/arm64"],
		},
		ContainerName: m.ContainerName,
		NetworkName:   m.NetworkName,
		ConfigVolume:  m.ConfigVolume,
		ListenAddress: m.ListenAddress,
		ListenPort:    m.ListenPort,
		Capabilities:  []string{"CHOWN", "FOWNER", "MKNOD", "SETGID", "SETUID", "SYS_CHROOT"},
		Tmpfs: []string{
			"/tmp:rw,noexec,nosuid,mode=1777,size=512m",
			"/opt/cool/child-roots:rw,nosuid,uid=1001,gid=1001,mode=0750,size=2g",
			"/opt/cool/cache:rw,nosuid,uid=1001,gid=1001,mode=0750,size=512m",
		},
		PIDsLimit:   1024,
		Memory:      "4g",
		CPUs:        "4",
		Restart:     "unless-stopped",
		LogMaxSize:  "20m",
		LogMaxFiles: 5,
		Environment: []string{
			"aliasgroup1=" + alias,
			"extra_params=" + extraParams,
		},
		ExtraHosts: extraHosts,
	}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return RuntimePlan{}, fmt.Errorf("encode managed Office runtime plan: %w", err)
	}
	return RuntimePlan{
		SchemaVersion: canonical.SchemaVersion, AppID: canonical.AppID, Image: canonical.Image,
		PlatformDigests: canonical.PlatformDigests, ContainerName: canonical.ContainerName,
		NetworkName: canonical.NetworkName, ConfigVolume: canonical.ConfigVolume,
		ListenAddress: canonical.ListenAddress, ListenPort: canonical.ListenPort,
		Capabilities: canonical.Capabilities, Tmpfs: canonical.Tmpfs, PIDsLimit: canonical.PIDsLimit,
		Memory: canonical.Memory, CPUs: canonical.CPUs, Restart: canonical.Restart,
		LogMaxSize: canonical.LogMaxSize, LogMaxFiles: canonical.LogMaxFiles,
		Environment: canonical.Environment,
		ExtraHosts:  canonical.ExtraHosts,
		PlanHash:    fmt.Sprintf("sha256:%x", sha256.Sum256(raw)), Execution: m.Execution,
	}, nil
}

// CanonicalJSON returns the stable behavior-bearing plan representation.
func (p RuntimePlan) CanonicalJSON() ([]byte, error) {
	return json.Marshal(canonicalRuntimePlan{
		SchemaVersion: p.SchemaVersion, AppID: p.AppID, Image: p.Image,
		PlatformDigests: p.PlatformDigests, ContainerName: p.ContainerName,
		NetworkName: p.NetworkName, ConfigVolume: p.ConfigVolume,
		ListenAddress: p.ListenAddress, ListenPort: p.ListenPort,
		Capabilities: p.Capabilities, Tmpfs: p.Tmpfs, PIDsLimit: p.PIDsLimit,
		Memory: p.Memory, CPUs: p.CPUs, Restart: p.Restart,
		LogMaxSize: p.LogMaxSize, LogMaxFiles: p.LogMaxFiles, Environment: p.Environment,
		ExtraHosts: p.ExtraHosts,
	})
}

func (p RuntimePlan) labels() map[string]string {
	return map[string]string{
		managedOwnerLabel: managedOwner, managedInstallationLabel: p.Execution.InstallationID,
		managedAppLabel: p.AppID, managedPlanLabel: p.PlanHash,
		managedOperationLabel: p.Execution.OperationID,
	}
}

func (p RuntimePlan) platformDigest(platform string) (string, bool) {
	switch platform {
	case "linux/amd64":
		return p.PlatformDigests.LinuxAMD64, true
	case "linux/arm64":
		return p.PlatformDigests.LinuxARM64, true
	default:
		return "", false
	}
}
