package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"setjoin.com/shared/release"
)

const (
	defaultEntitlementPath       = "/etc/setjoin/entitlement.json"
	defaultEntitlementTrustRoots = "/etc/setjoin/trust/entitlement-keys.json"
	defaultInstallationIDPath    = "/etc/setjoin/installation-id"
	defaultUpdateChannelPath     = "/etc/setjoin/update-channel"
)

var entitlementNow = func() time.Time { return time.Now().UTC() }
var entitlementAtomicReplace = atomicReplaceEntitlement

type entitlementOutput struct {
	EntitlementID  string                   `json:"entitlementId"`
	InstallationID string                   `json:"installationId"`
	CustomerID     string                   `json:"customerId"`
	Channels       []release.Channel        `json:"channels"`
	VersionRanges  []string                 `json:"versionRanges"`
	ValidUntil     string                   `json:"validUntil"`
	GraceUntil     string                   `json:"graceUntil"`
	State          release.EntitlementState `json:"state"`
	Digest         string                   `json:"digest"`
}

func runEntitlement(_ *cmdCtx, action string, args []string) error {
	jsonOutput, positional, err := parseEntitlementArgs(args)
	if err != nil {
		return err
	}
	switch action {
	case "import":
		if len(positional) != 1 {
			return fmt.Errorf("usage: mailctl entitlement import <file> [--json]")
		}
		output, raw, err := verifyEntitlementFile(positional[0])
		if err != nil {
			return err
		}
		if err := entitlementAtomicReplace(entitlementPath(), raw); err != nil {
			return fmt.Errorf("install entitlement: %w", err)
		}
		return printEntitlementOutput(output, jsonOutput, "imported")
	case "show":
		if len(positional) != 0 {
			return fmt.Errorf("usage: mailctl entitlement show [--json]")
		}
		output, _, err := verifyEntitlementFile(entitlementPath())
		if err != nil {
			return err
		}
		return printEntitlementOutput(output, jsonOutput, "installed")
	default:
		return fmt.Errorf("unknown entitlement action: %s (try: import, show)", action)
	}
}

func parseEntitlementArgs(args []string) (bool, []string, error) {
	jsonOutput := false
	positional := make([]string, 0, len(args))
	for _, arg := range args {
		switch arg {
		case "--json":
			jsonOutput = true
		default:
			if strings.HasPrefix(arg, "-") {
				return false, nil, fmt.Errorf("unknown entitlement flag %q", arg)
			}
			positional = append(positional, arg)
		}
	}
	return jsonOutput, positional, nil
}

func verifyEntitlementFile(path string) (entitlementOutput, []byte, error) {
	raw, err := readBoundedFile(path, release.MaxDocumentBytes)
	if err != nil {
		return entitlementOutput{}, nil, fmt.Errorf("read entitlement: %w", err)
	}
	rootRaw, err := readBoundedFile(entitlementTrustRootsPath(), release.MaxDocumentBytes)
	if err != nil {
		return entitlementOutput{}, nil, fmt.Errorf("read entitlement trust roots: %w", err)
	}
	keys, err := release.ParseTrustRootDocument(rootRaw, release.PurposeEntitlement, false)
	if err != nil {
		return entitlementOutput{}, nil, err
	}
	store, err := release.NewTrustStore(keys, false)
	if err != nil {
		return entitlementOutput{}, nil, err
	}
	installationID, err := readBoundedText(installationIDPath())
	if err != nil {
		return entitlementOutput{}, nil, fmt.Errorf("read installation id: %w", err)
	}
	channelRaw, err := readBoundedText(updateChannelPath())
	if err != nil {
		return entitlementOutput{}, nil, fmt.Errorf("read update channel: %w", err)
	}
	channel := release.Channel(channelRaw)
	if channel != release.ChannelEnterprise {
		return entitlementOutput{}, nil, fmt.Errorf("local entitlement import is only valid for the configured enterprise channel")
	}
	verified, err := store.VerifyEntitlementDocument(raw, installationID, channel, entitlementNow())
	if err != nil {
		return entitlementOutput{}, nil, err
	}
	e := verified.Entitlement
	return entitlementOutput{EntitlementID: e.EntitlementID, InstallationID: e.InstallationID, CustomerID: e.CustomerID, Channels: e.Channels, VersionRanges: e.VersionRanges, ValidUntil: e.ValidUntil, GraceUntil: e.GraceUntil, State: verified.State, Digest: verified.Digest}, raw, nil
}

func printEntitlementOutput(output entitlementOutput, jsonOutput bool, verb string) error {
	if jsonOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(output)
	}
	fmt.Printf("Entitlement %s: %s\n", verb, output.EntitlementID)
	fmt.Printf("Installation:        %s\n", output.InstallationID)
	fmt.Printf("Channel:             %s\n", strings.Join(channelsToStrings(output.Channels), ","))
	fmt.Printf("State:               %s\n", output.State)
	fmt.Printf("Valid until:         %s\n", output.ValidUntil)
	fmt.Printf("Grace until:         %s\n", output.GraceUntil)
	fmt.Printf("Document SHA-256:    %s\n", output.Digest)
	return nil
}

func channelsToStrings(channels []release.Channel) []string {
	out := make([]string, len(channels))
	for i, c := range channels {
		out[i] = string(c)
	}
	return out
}
func entitlementPath() string { return envOr("SETJOIN_ENTITLEMENT_PATH", defaultEntitlementPath) }
func entitlementTrustRootsPath() string {
	return envOr("SETJOIN_ENTITLEMENT_TRUST_ROOTS", defaultEntitlementTrustRoots)
}
func installationIDPath() string {
	return envOr("SETJOIN_INSTALLATION_ID_FILE", defaultInstallationIDPath)
}
func updateChannelPath() string {
	return envOr("SETJOIN_UPDATE_CHANNEL_FILE", defaultUpdateChannelPath)
}
func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func readBoundedFile(path string, maximum int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maximum {
		return nil, fmt.Errorf("file exceeds %d bytes", maximum)
	}
	return raw, nil
}
func readBoundedText(path string) (string, error) {
	raw, err := readBoundedFile(path, 256)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(raw))
	if !identifierText(value) {
		return "", fmt.Errorf("invalid bounded identifier")
	}
	return value, nil
}
func identifierText(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-", r)) {
			return false
		}
	}
	return true
}

func atomicReplaceEntitlement(path string, data []byte) error {
	_, err := installPrivateReplace(path, data)
	return err
}
