package deploy

import (
	"encoding/json"
	"fmt"
	"strings"
)

// SeaweedFSNodeConfig holds the configuration for a single SeaweedFS node.
type SeaweedFSNodeConfig struct {
	VolumePath string
	Peers      []string // master peer addresses (empty for single node)
	S3Port     int
	Rack       string
	MaxVolumes int
}

// SeaweedfsS3ConfigPath is the per-node path the wizard deploys the S3
// identity config to. It matches the shipped HA unit template's mount
// (deploy/seaweedfs-master.service.template: -s3.config=/etc/mail/seaweedfs-s3.json)
// so both deployment tracks load the identity config from one path.
const SeaweedfsS3ConfigPath = "/etc/mail/seaweedfs-s3.json"

// SeaweedfsS3ConfigGroup is the group the deployed identity config is readable
// by: the wizard's generated systemd unit runs weed as User=mail, so the file
// is root-owned with a narrow group-read grant (root:mail 0640) instead of
// world-readable.
const SeaweedfsS3ConfigGroup = "mail"

const systemdUnitTemplate = `[Unit]
Description=SeaweedFS Storage Node
After=network.target

[Service]
Type=simple
User=mail
ExecStart=/usr/local/bin/weed server \
  -dir=%s \
%s  -filer -s3 -s3.port=%d \
  -s3.config=` + SeaweedfsS3ConfigPath + ` \
  -volume.max=%d \
  -rack=%s \
  -dataCenter=dc1
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
`

// GenerateSystemdUnit generates a systemd service unit for a SeaweedFS node.
// The unit always loads the S3 identity config the wizard deploys to
// SeaweedfsS3ConfigPath in the same provisioning step (configureSeaweedFS):
// without -s3.config the S3 gateway would come up with no identity scaffold
// and no enforced authentication surface at all (D-MAILSERVER-DEPLOY-001).
func GenerateSystemdUnit(cfg SeaweedFSNodeConfig) string {
	peerLine := ""
	if len(cfg.Peers) > 0 {
		peerLine = fmt.Sprintf("  -master.peers=%s \\\n", strings.Join(cfg.Peers, ","))
	}

	port := cfg.S3Port
	if port == 0 {
		port = 9000
	}
	maxVolumes := cfg.MaxVolumes
	if maxVolumes == 0 {
		maxVolumes = 100
	}
	rack := cfg.Rack
	if rack == "" {
		rack = "rack1"
	}
	volumePath := cfg.VolumePath
	if volumePath == "" {
		volumePath = "/data/seaweedfs"
	}

	return fmt.Sprintf(systemdUnitTemplate,
		volumePath,
		peerLine,
		port,
		maxVolumes,
		rack,
	)
}

// ── S3 identity config (deployed runtime artifact) ──────────────────────────

// wellKnownS3CredentialSubstrings are vendor defaults and install-time
// placeholder markers that must never appear in any S3 identity config a
// deployment will load. Matched case-insensitively against the raw bytes.
// Shared by the deployed-config validator (ValidateS3IdentitiesConfig) and
// the shipped-artifact guard (seaweedfs_s3_config_test.go).
var wellKnownS3CredentialSubstrings = []string{
	"minioadmin",  // SeaweedFS/MinIO vendor default admin pair
	"changeme",    // generic default-password marker
	"change-me",   // hyphenated variant
	"replace_me",  // placeholder marker
	"replace-me",  // hyphenated placeholder marker
	"<generated",  // unrendered template placeholder
	"{{.",         // unrendered Go template action
	"{{\"",        // unrendered Go template string action
	"your-",       // doc-style placeholder prefix
	"access_key>", // unrendered angle-bracket placeholder tail
	"secret_key>", // unrendered angle-bracket placeholder tail
}

// s3AdminActions is the action set granted to the generated admin identity.
var s3AdminActions = []string{"Admin", "Read", "Write", "List", "Tagging"}

// deployedS3Identity mirrors the SeaweedFS -s3.config identity shape.
type deployedS3Identity struct {
	Name        string `json:"name"`
	Credentials []struct {
		AccessKey string `json:"accessKey"`
		SecretKey string `json:"secretKey"`
	} `json:"credentials"`
	Actions []string `json:"actions"`
}

type deployedS3Config struct {
	Identities []deployedS3Identity `json:"identities"`
}

// RenderSeaweedfsS3Config renders the S3 identity config JSON the deployment
// loads via -s3.config from generated credential material. install.sh
// (single-node track) and configureSeaweedFS (wizard HA track) both produce
// the file through this contract: exactly one admin identity whose
// credentials are the install-time generated pair. Rendering refuses empty
// material and the result is always validated by ValidateS3IdentitiesConfig
// before it can reach a deployment.
func RenderSeaweedfsS3Config(accessKey, secretKey string) (string, error) {
	if strings.TrimSpace(accessKey) == "" || strings.TrimSpace(secretKey) == "" {
		return "", fmt.Errorf("refusing to render the S3 identity config: access and secret keys must both be non-empty generated material")
	}
	cfg := deployedS3Config{
		Identities: []deployedS3Identity{
			{
				Name: "admin",
				Credentials: []struct {
					AccessKey string `json:"accessKey"`
					SecretKey string `json:"secretKey"`
				}{
					{AccessKey: accessKey, SecretKey: secretKey},
				},
				Actions: s3AdminActions,
			},
		},
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal S3 identity config: %w", err)
	}
	raw = append(raw, '\n')
	if err := ValidateS3IdentitiesConfig(raw); err != nil {
		return "", err
	}
	return string(raw), nil
}

// ValidateS3IdentitiesConfig is the deployment-time rejection gate for the S3
// identity config (D-MAILSERVER-DEPLOY-001, med-deploy-s3-credentials-b1r2-001).
//
// The consumer of -s3.config is the weed server binary itself (external), so
// the repo-side gate lives at the producers: install.sh's render step and the
// wizard's configureSeaweedFS both call this before the file a deployment
// will load can exist, failing the install/deployment loud instead of booting
// an S3 gateway on vendor-default or empty credentials. It rejects:
//   - any well-known/placeholder credential marker (minioadmin pair first
//     among them, matched case-insensitively anywhere in the artifact);
//   - invalid JSON, or a config with no identities at all (no identities
//     means no enforced authentication surface);
//   - an "anonymous" identity (unsigned requests must not match anything);
//   - any identity with an empty name, no actions, or an empty/missing
//     credential pair.
//
// This is the runtime (deployed) contract and is deliberately the inverse of
// the shipped repository artifact's contract (seaweedfs_s3_config_test.go),
// which must carry ZERO credentials: the shipped file fails closed, the
// deployed file must authenticate every identity.
func ValidateS3IdentitiesConfig(raw []byte) error {
	lower := strings.ToLower(string(raw))
	for _, marker := range wellKnownS3CredentialSubstrings {
		if strings.Contains(lower, marker) {
			return fmt.Errorf("S3 identity config contains well-known/placeholder credential marker %q; identities must be generated at install time, never defaulted", marker)
		}
	}

	var cfg deployedS3Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("S3 identity config is not valid JSON: %v", err)
	}
	if len(cfg.Identities) == 0 {
		return fmt.Errorf("S3 identity config defines no identities; the identities scaffold is what keeps the S3 API in authenticated mode")
	}
	sawCredential := false
	for i, ident := range cfg.Identities {
		if strings.TrimSpace(ident.Name) == "" {
			return fmt.Errorf("S3 identity config identity[%d] has an empty name", i)
		}
		if strings.EqualFold(ident.Name, "anonymous") {
			return fmt.Errorf("S3 identity config must not define an anonymous identity; unsigned requests must not match anything")
		}
		if len(ident.Actions) == 0 {
			return fmt.Errorf("S3 identity config identity %q grants no actions", ident.Name)
		}
		if len(ident.Credentials) == 0 {
			return fmt.Errorf("S3 identity config identity %q carries no credentials; a deployed identity must authenticate", ident.Name)
		}
		for j, cred := range ident.Credentials {
			if strings.TrimSpace(cred.AccessKey) == "" || strings.TrimSpace(cred.SecretKey) == "" {
				return fmt.Errorf("S3 identity config identity %q credential[%d] has an empty access or secret key", ident.Name, j)
			}
			sawCredential = true
		}
	}
	if !sawCredential {
		return fmt.Errorf("S3 identity config carries no credential material; a deployed S3 gateway must have generated identities")
	}
	return nil
}
