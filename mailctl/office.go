package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"

	"setjoin.com/shared/toggle"
)

const officeFeatureEndpoint = "/admin/features"

// officeFeatureSpec is the small, stable operator-facing catalog for the
// Office/History command. The authoritative values still come from the
// server's feature registry; these labels and dependency hints keep the CLI
// useful when an older server omits additive metadata.
type officeFeatureSpec struct {
	key               string
	label             string
	defaultEnabled    bool
	dependencies      []string
	configurationHint string
}

// Managed delivery is intentionally absent: it has its own `office apps`
// lifecycle/readiness projection, while this catalog diagnoses the reusable
// Drive/Office foundations shared by BYOL and managed providers.
var officeFeatureSpecs = []officeFeatureSpec{
	{
		key:               toggle.FeatureOfficeEditing,
		label:             "Office online editing",
		defaultEnabled:    false,
		dependencies:      []string{toggle.FeatureDrive},
		configurationHint: "configure only after an approved Office provider and Drive policy are ready",
	},
	{
		key:               toggle.FeatureOfficeLocalOpen,
		label:             "Office local open",
		defaultEnabled:    false,
		dependencies:      []string{toggle.FeatureDrive},
		configurationHint: "configure only after the controlled desktop application policy is ready",
	},
	{
		key:               toggle.FeatureDriveHistory,
		label:             "Drive History",
		defaultEnabled:    false,
		dependencies:      []string{toggle.FeatureDrive},
		configurationHint: "configure only after Drive History retention and access policy are ready",
	},
}

// officeFeatureWire intentionally whitelists the generic admin feature API's
// safe projection. In particular, the Office commands never decode, inspect,
// or print credentials, provider configuration, or arbitrary diagnostic data.
type officeFeatureWire struct {
	Key                  string   `json:"key"`
	Enabled              bool     `json:"enabled"`
	StoredEnabled        *bool    `json:"storedEnabled"`
	DefaultEnabled       *bool    `json:"defaultEnabled"`
	Description          string   `json:"description"`
	Classification       string   `json:"classification"`
	RegistryMode         string   `json:"registryMode"`
	GatewayEffective     *bool    `json:"gatewayEffective"`
	GatewaySource        string   `json:"gatewaySource"`
	ChangeMode           string   `json:"changeMode"`
	DisableBehavior      string   `json:"disableBehavior"`
	Dependencies         []string `json:"dependencies"`
	ConfirmationRequired bool     `json:"confirmationRequired"`
}

// officeFlagStatus is shared by doctor and diagnostics so human and JSON
// output describe exactly the same facts. The Hint field is intentionally
// omitted by diagnostics; diagnostics is a status snapshot, while doctor is
// the operator-facing configuration check.
type officeFlagStatus struct {
	Key                  string   `json:"key"`
	Label                string   `json:"label"`
	Present              bool     `json:"present"`
	State                string   `json:"state"`
	Enabled              bool     `json:"enabled"`
	DefaultEnabled       bool     `json:"defaultEnabled"`
	DefaultOff           bool     `json:"defaultOff"`
	Configured           bool     `json:"configured"`
	GatewayEffective     bool     `json:"gatewayEffective"`
	GatewaySource        string   `json:"gatewaySource"`
	RegistryMode         string   `json:"registryMode,omitempty"`
	Classification       string   `json:"classification,omitempty"`
	ChangeMode           string   `json:"changeMode,omitempty"`
	DisableBehavior      string   `json:"disableBehavior,omitempty"`
	Dependencies         []string `json:"dependencies"`
	ConfirmationRequired bool     `json:"confirmationRequired"`
	Hint                 string   `json:"hint,omitempty"`
}

type officeDoctorReport struct {
	Source   string             `json:"source"`
	Endpoint string             `json:"endpoint"`
	Flags    []officeFlagStatus `json:"flags"`
	Hints    []string           `json:"hints"`
}

type officeDiagnosticFlag struct {
	Key              string   `json:"key"`
	Label            string   `json:"label"`
	Present          bool     `json:"present"`
	State            string   `json:"state"`
	Enabled          bool     `json:"enabled"`
	DefaultEnabled   bool     `json:"defaultEnabled"`
	Configured       bool     `json:"configured"`
	GatewayEffective bool     `json:"gatewayEffective"`
	GatewaySource    string   `json:"gatewaySource"`
	Dependencies     []string `json:"dependencies"`
}

type officeDiagnosticsReport struct {
	Source   string                 `json:"source"`
	Endpoint string                 `json:"endpoint"`
	Status   string                 `json:"status"`
	Flags    []officeDiagnosticFlag `json:"flags"`
}

func runOffice(c *cmdCtx, action string, args []string) error {
	switch action {
	case "doctor":
		return officeDoctorCmd(c, args)
	case "diagnostics":
		return officeDiagnosticsCmd(c, args)
	case "status", "configure", "qualify", "activate", "install", "recover":
		return officeLifecycleCmd(c, action, args)
	default:
		return fmt.Errorf("unknown office action: %s (try: doctor, diagnostics, status, configure, qualify, activate, install, recover)", action)
	}
}

func officeDoctorCmd(c *cmdCtx, args []string) error {
	if err := parseOfficeOutputFlags(c, "office doctor", args); err != nil {
		return err
	}
	rows, err := loadOfficeFeatureRegistry(c)
	if err != nil {
		return err
	}
	flags, missing, dependencyBlockers := buildOfficeFlagStatuses(rows)
	report := officeDoctorReport{
		Source:   "admin feature registry",
		Endpoint: officeFeatureEndpoint,
		Flags:    flags,
		Hints:    officeDoctorHints(flags, missing, dependencyBlockers),
	}

	if c.json {
		if err := printOut(c, report); err != nil {
			return err
		}
	} else if !c.quiet {
		printOfficeDoctorHuman(report)
	}

	if len(missing) > 0 {
		return exitCodeErr{code: 1, msg: fmt.Sprintf(
			"office doctor: server did not report %d required Office/History feature flag(s)", len(missing))}
	}
	if len(dependencyBlockers) > 0 {
		return exitCodeErr{code: 1, msg: "office doctor: one or more enabled flags have disabled Drive dependencies"}
	}
	return nil
}

func officeDiagnosticsCmd(c *cmdCtx, args []string) error {
	if err := parseOfficeOutputFlags(c, "office diagnostics", args); err != nil {
		return err
	}
	rows, err := loadOfficeFeatureRegistry(c)
	if err != nil {
		return err
	}
	flags, missing, _ := buildOfficeFlagStatuses(rows)
	diagnosticFlags := make([]officeDiagnosticFlag, 0, len(flags))
	for _, status := range flags {
		diagnosticFlags = append(diagnosticFlags, officeDiagnosticFlag{
			Key: status.Key, Label: status.Label, Present: status.Present,
			State: status.State, Enabled: status.Enabled,
			DefaultEnabled: status.DefaultEnabled, Configured: status.Configured,
			GatewayEffective: status.GatewayEffective, GatewaySource: status.GatewaySource,
			Dependencies: append([]string(nil), status.Dependencies...),
		})
	}
	status := "ok"
	if len(missing) > 0 {
		status = "partial"
	}
	report := officeDiagnosticsReport{
		Source: "admin feature registry", Endpoint: officeFeatureEndpoint,
		Status: status, Flags: diagnosticFlags,
	}
	if c.json {
		return printOut(c, report)
	}
	if !c.quiet {
		printOfficeDiagnosticsHuman(report)
	}
	return nil
}

func parseOfficeOutputFlags(c *cmdCtx, name string, args []string) error {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.BoolVar(&c.json, "json", c.json, "JSON output")
	fs.BoolVar(&c.quiet, "quiet", c.quiet, "Suppress output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: mailctl office %s [--json]", strings.TrimPrefix(name, "office "))
	}
	return nil
}

func loadOfficeFeatureRegistry(c *cmdCtx) ([]officeFeatureWire, error) {
	var rows []officeFeatureWire
	if err := c.client.DoBounded(http.MethodGet, officeFeatureEndpoint, nil, &rows, 1<<20); err != nil {
		return nil, err
	}
	return rows, nil
}

func buildOfficeFlagStatuses(rows []officeFeatureWire) ([]officeFlagStatus, []string, []string) {
	byKey := make(map[string]officeFeatureWire, len(rows))
	for _, row := range rows {
		if row.Key != "" {
			byKey[row.Key] = row
		}
	}

	statuses := make([]officeFlagStatus, 0, len(officeFeatureSpecs))
	var missing []string
	var dependencyBlockers []string
	for _, spec := range officeFeatureSpecs {
		row, present := byKey[spec.key]
		defaultEnabled := spec.defaultEnabled
		if row.DefaultEnabled != nil {
			defaultEnabled = *row.DefaultEnabled
		}
		effective := row.Enabled
		if row.GatewayEffective != nil {
			effective = *row.GatewayEffective
		}
		configured := row.StoredEnabled != nil
		gatewaySource := row.GatewaySource
		if gatewaySource == "" {
			gatewaySource = "unknown"
		}
		dependencies := append([]string(nil), row.Dependencies...)
		if len(dependencies) == 0 {
			dependencies = append([]string(nil), spec.dependencies...)
		}

		state := "off"
		if effective {
			state = "on"
		}
		if !present {
			state = "missing"
			missing = append(missing, spec.key)
		}
		status := officeFlagStatus{
			Key: spec.key, Label: spec.label, Present: present, State: state,
			Enabled: row.Enabled, DefaultEnabled: defaultEnabled,
			DefaultOff: !defaultEnabled, Configured: configured,
			GatewayEffective: effective, GatewaySource: gatewaySource,
			RegistryMode: row.RegistryMode, Classification: row.Classification,
			ChangeMode: row.ChangeMode, DisableBehavior: row.DisableBehavior,
			Dependencies: dependencies, ConfirmationRequired: row.ConfirmationRequired,
		}
		if !present {
			status.Hint = "not reported by this server; upgrade the server before configuring this flag"
		} else if !effective {
			if !configured && !defaultEnabled {
				status.Hint = fmt.Sprintf("default-OFF; configure with 'mailctl feature set %s on' only after the required policy and evidence are ready", spec.key)
			} else if configured {
				status.Hint = fmt.Sprintf("configured OFF; run 'mailctl feature set %s on' only after the required policy and evidence are ready", spec.key)
			} else {
				status.Hint = spec.configurationHint
			}
		} else {
			status.Hint = spec.configurationHint
		}
		statuses = append(statuses, status)
	}

	// The three Office/History rows depend on Drive. The dependency is not a
	// fourth Office flag, so use it only when the generic registry returned it;
	// an older server that omits it is reported via the normal hint instead of
	// being guessed as healthy or unhealthy.
	if drive, ok := byKey[toggle.FeatureDrive]; ok {
		driveEffective := drive.Enabled
		if drive.GatewayEffective != nil {
			driveEffective = *drive.GatewayEffective
		}
		if driveEffective {
			return statuses, missing, dependencyBlockers
		}
		for _, status := range statuses {
			if status.GatewayEffective && slices.Contains(status.Dependencies, toggle.FeatureDrive) {
				dependencyBlockers = append(dependencyBlockers, status.Key)
			}
		}
	}
	return statuses, missing, dependencyBlockers
}

func officeDoctorHints(flags []officeFlagStatus, missing, dependencyBlockers []string) []string {
	hints := make([]string, 0, len(flags)+2)
	if len(missing) > 0 {
		hints = append(hints, "The server must expose all three Office/History flags before this command can verify configuration.")
	}
	allDefaultOff := true
	for _, status := range flags {
		if !status.DefaultOff {
			allDefaultOff = false
		}
		if status.Hint != "" {
			hints = append(hints, status.Key+": "+status.Hint)
		}
	}
	if allDefaultOff {
		hints = append(hints, "All Office and Drive History capabilities are default-OFF; no capability is enabled until explicitly configured.")
	}
	if len(dependencyBlockers) > 0 {
		hints = append(hints, "Enabled Office/History capabilities require feature.drive to be enabled before admission can succeed.")
	}
	return hints
}

func printOfficeDoctorHuman(report officeDoctorReport) {
	fmt.Println("Office doctor (sanitized feature status)")
	fmt.Printf("Source: %s  Endpoint: %s\n", report.Source, report.Endpoint)
	for _, status := range report.Flags {
		state := strings.ToUpper(status.State)
		if status.DefaultOff {
			fmt.Printf("  %-25s %-7s default OFF", status.Key, state)
		} else {
			fmt.Printf("  %-25s %-7s default ON", status.Key, state)
		}
		if status.Configured {
			fmt.Print(" configured")
		} else {
			fmt.Print(" registry-default")
		}
		if !status.Present {
			fmt.Print(" missing")
		}
		fmt.Println()
		if status.GatewaySource != "unknown" {
			fmt.Printf("      gateway=%s source=%s\n", boolWord(status.GatewayEffective), status.GatewaySource)
		}
		if len(status.Dependencies) > 0 {
			fmt.Printf("      requires=%s\n", strings.Join(status.Dependencies, ","))
		}
		if status.Hint != "" {
			fmt.Printf("      hint: %s\n", status.Hint)
		}
	}
	for _, hint := range report.Hints {
		fmt.Printf("Hint: %s\n", hint)
	}
}

func printOfficeDiagnosticsHuman(report officeDiagnosticsReport) {
	fmt.Println("Office diagnostics (sanitized server status)")
	fmt.Printf("Source: %s  Endpoint: %s  Status: %s\n", report.Source, report.Endpoint, report.Status)
	for _, status := range report.Flags {
		fmt.Printf("  %-25s %-7s enabled=%s default=%s configured=%t gateway=%s source=%s\n",
			status.Key, status.State, boolWord(status.Enabled), boolWord(status.DefaultEnabled),
			status.Configured, boolWord(status.GatewayEffective), status.GatewaySource)
		if len(status.Dependencies) > 0 {
			fmt.Printf("      requires=%s\n", strings.Join(status.Dependencies, ","))
		}
	}
}

func boolWord(value bool) string {
	if value {
		return "on"
	}
	return "off"
}
