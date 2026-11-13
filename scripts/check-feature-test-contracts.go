package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type manifest struct {
	SchemaVersion int        `json:"schemaVersion"`
	Rollout       string     `json:"rollout"`
	Contracts     []contract `json:"contracts"`
}

type contract struct {
	ID           string        `json:"id"`
	Authority    string        `json:"authority"`
	Status       string        `json:"status"`
	Requirements []requirement `json:"requirements"`
}

type requirement struct {
	ID          string     `json:"id"`
	Risk        string     `json:"risk"`
	Obligations []string   `json:"obligations"`
	Evidence    []evidence `json:"evidence,omitempty"`
	Exception   *exception `json:"exception,omitempty"`
}

type evidence struct {
	ID         string         `json:"id"`
	Kind       string         `json:"kind"`
	Path       string         `json:"path"`
	Selector   string         `json:"selector"`
	Gate       string         `json:"gate"`
	SkipPolicy string         `json:"skipPolicy"`
	Covers     []string       `json:"covers"`
	Result     *resultBinding `json:"result,omitempty"`
}

type resultBinding struct {
	Format    string `json:"format"`
	GateClass string `json:"gateClass"`
	Report    string `json:"report"`
	Suite     string `json:"suite"`
	TestID    string `json:"testId"`
}

type exception struct {
	Owner      string `json:"owner"`
	ApprovedBy string `json:"approvedBy"`
	Reason     string `json:"reason"`
	Tracking   string `json:"tracking"`
	Expires    string `json:"expires"`
}

var idPattern = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*$`)

type validator struct {
	root   string
	today  time.Time
	errors []string
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: check-feature-test-contracts.go <repo-root> <manifest.json>")
		os.Exit(2)
	}
	root, err := filepath.Abs(os.Args[1])
	if err != nil {
		fatal(err)
	}
	data, err := os.ReadFile(os.Args[2])
	if err != nil {
		fatal(err)
	}
	var m manifest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		fatal(fmt.Errorf("invalid manifest JSON: %w", err))
	}
	if err := ensureEOF(dec); err != nil {
		fatal(err)
	}
	v := validator{root: root, today: time.Now().UTC().Truncate(24 * time.Hour)}
	v.validate(m)
	if len(v.errors) != 0 {
		sort.Strings(v.errors)
		for _, msg := range v.errors {
			fmt.Fprintf(os.Stderr, "feature-test-contracts: %s\n", msg)
		}
		os.Exit(1)
	}
	fmt.Printf("feature-test-contracts: PASS (%d contract(s), rollout=%s)\n", len(m.Contracts), m.Rollout)
}

func ensureEOF(dec *json.Decoder) error {
	var extra any
	err := dec.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("manifest contains more than one JSON value")
	}
	return err
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "feature-test-contracts:", err)
	os.Exit(1)
}

func (v *validator) validate(m manifest) {
	if m.SchemaVersion != 1 {
		v.add("schemaVersion must be 1")
	}
	if m.Rollout != "pilot" && m.Rollout != "enforced" {
		v.add("rollout must be pilot or enforced")
	}
	if len(m.Contracts) == 0 {
		v.add("contracts must not be empty")
	}
	seenContracts := map[string]bool{}
	for i, c := range m.Contracts {
		where := fmt.Sprintf("contracts[%d]", i)
		if !validID(c.ID) {
			v.add("%s.id is invalid", where)
		} else if seenContracts[c.ID] {
			v.add("duplicate contract id %q", c.ID)
		}
		seenContracts[c.ID] = true
		if c.Status != "planned" && c.Status != "enforced" {
			v.add("%s.status must be planned or enforced", where)
		}
		v.requireFile(where+".authority", c.Authority, "")
		if len(c.Requirements) == 0 {
			v.add("%s.requirements must not be empty", where)
		}
		seenRequirements := map[string]bool{}
		for j, r := range c.Requirements {
			rwhere := fmt.Sprintf("%s.requirements[%d]", where, j)
			if !validID(r.ID) {
				v.add("%s.id is invalid", rwhere)
			} else if seenRequirements[r.ID] {
				v.add("%s has duplicate requirement id %q", where, r.ID)
			}
			seenRequirements[r.ID] = true
			v.validateRequirement(m.Rollout, c.Status, rwhere, r)
		}
	}
}

func (v *validator) validateRequirement(rollout, status, where string, r requirement) {
	if r.Risk != "standard" && r.Risk != "high" && r.Risk != "critical" {
		v.add("%s.risk must be standard, high, or critical", where)
	}
	obligations := uniqueIDs(v, where+".obligations", r.Obligations)
	if len(obligations) == 0 {
		v.add("%s.obligations must not be empty", where)
	}
	if len(r.Evidence) != 0 && r.Exception != nil {
		v.add("%s cannot declare both evidence and exception", where)
	}
	if status == "enforced" && len(r.Evidence) == 0 && r.Exception == nil {
		v.add("%s enforced requirement needs evidence or an exception", where)
	}
	covered := map[string]bool{}
	seenEvidence := map[string]bool{}
	for i, e := range r.Evidence {
		ewhere := fmt.Sprintf("%s.evidence[%d]", where, i)
		if !validID(e.ID) {
			v.add("%s.id is invalid", ewhere)
		} else if seenEvidence[e.ID] {
			v.add("%s has duplicate evidence id %q", where, e.ID)
		}
		seenEvidence[e.ID] = true
		if e.Kind != "guard" && e.Kind != "go" && e.Kind != "vitest" && e.Kind != "pgtap" && e.Kind != "playwright" && e.Kind != "protocol" && e.Kind != "manual" {
			v.add("%s.kind is unsupported", ewhere)
		}
		if status == "enforced" && rollout == "pilot" && e.Kind != "guard" && e.Result == nil {
			v.add("%s pilot enforced evidence must be a guard or have a result binding", ewhere)
		}
		if e.SkipPolicy != "forbid" && e.SkipPolicy != "report" {
			v.add("%s.skipPolicy must be forbid or report", ewhere)
		}
		if status == "enforced" && e.SkipPolicy != "forbid" {
			v.add("%s enforced evidence must forbid skips", ewhere)
		}
		v.requireFile(ewhere+".path", e.Path, e.Selector)
		v.requireFile(ewhere+".gate", e.Gate, "")
		v.validateResultBinding(ewhere+".result", e.Kind, e.Result)
		if status == "enforced" && e.Kind == "guard" {
			if e.Gate != e.Path {
				v.add("%s guard evidence must be its own gate", ewhere)
			}
			if !strings.HasPrefix(e.Path, "scripts/check-") || !strings.HasSuffix(e.Path, ".sh") {
				v.add("%s guard path must match scripts/check-*.sh", ewhere)
			}
			v.requireGuardSelfTest(ewhere, e.Path)
		}
		if status == "enforced" && e.Result != nil {
			if !strings.HasPrefix(e.Gate, "scripts/check-") || !strings.HasSuffix(e.Gate, ".sh") {
				v.add("%s result-bound gate must match scripts/check-*.sh", ewhere)
			}
			v.requireGuardSelfTest(ewhere, e.Gate)
		}
		for obligation := range uniqueIDs(v, ewhere+".covers", e.Covers) {
			if !obligations[obligation] {
				v.add("%s covers undeclared obligation %q", ewhere, obligation)
			}
			covered[obligation] = true
		}
	}
	if status == "enforced" && r.Exception == nil {
		for obligation := range obligations {
			if !covered[obligation] {
				v.add("%s obligation %q has no evidence", where, obligation)
			}
		}
	}
	if r.Exception != nil {
		v.validateException(where+".exception", *r.Exception)
	}
}

func (v *validator) validateResultBinding(where, kind string, result *resultBinding) {
	if result == nil {
		if kind != "guard" && kind != "manual" {
			v.add("%s is required for executable evidence", where)
		}
		return
	}
	formats := map[string]string{
		"go":         "go-json",
		"vitest":     "vitest-json",
		"pgtap":      "tap",
		"playwright": "playwright-json",
		"protocol":   "playwright-json",
	}
	want, ok := formats[kind]
	if !ok {
		v.add("%s is not allowed for evidence kind %q", where, kind)
		return
	}
	if result.Format != want {
		v.add("%s.format must be %q for evidence kind %q", where, want, kind)
	}
	if result.GateClass != "merge" && result.GateClass != "release" {
		v.add("%s.gateClass must be merge or release", where)
	}
	if !normalizedRelative(result.Report) {
		v.add("%s.report must be a normalized repository-relative path", where)
	}
	if strings.TrimSpace(result.Suite) == "" || strings.TrimSpace(result.TestID) == "" {
		v.add("%s requires suite and testId", where)
	}
}

func (v *validator) requireGuardSelfTest(where, rel string) {
	if rel == "" || filepath.IsAbs(rel) || filepath.Clean(rel) != rel {
		return
	}
	full := filepath.Join(v.root, rel)
	data, err := os.ReadFile(full)
	if err != nil {
		return
	}
	companion := strings.TrimSuffix(full, ".sh") + "-selftest.sh"
	if bytes.Contains(data, []byte("--self-test")) {
		return
	}
	if info, err := os.Stat(companion); err == nil && info.Mode().IsRegular() {
		return
	}
	v.add("%s guard must expose --self-test or have companion %s", where, filepath.Base(companion))
}

func (v *validator) validateException(where string, e exception) {
	if strings.TrimSpace(e.Owner) == "" || strings.TrimSpace(e.ApprovedBy) == "" || strings.TrimSpace(e.Reason) == "" || strings.TrimSpace(e.Tracking) == "" {
		v.add("%s requires owner, approvedBy, reason, and tracking", where)
	}
	if strings.EqualFold(strings.TrimSpace(e.Owner), strings.TrimSpace(e.ApprovedBy)) && strings.TrimSpace(e.Owner) != "" {
		v.add("%s owner and approvedBy must differ", where)
	}
	expires, err := time.Parse("2006-01-02", e.Expires)
	if err != nil {
		v.add("%s.expires must be YYYY-MM-DD", where)
	} else if !expires.After(v.today) {
		v.add("%s expired on %s", where, e.Expires)
	}
}

func (v *validator) requireFile(where, rel, selector string) {
	if rel == "" {
		v.add("%s is required", where)
		return
	}
	if !normalizedRelative(rel) {
		v.add("%s must be a normalized repository-relative path", where)
		return
	}
	full := filepath.Join(v.root, rel)
	info, err := os.Stat(full)
	if err != nil || !info.Mode().IsRegular() {
		v.add("%s does not name a regular file: %s", where, rel)
		return
	}
	if selector == "" {
		return
	}
	data, err := os.ReadFile(full)
	if err != nil || !bytes.Contains(data, []byte(selector)) {
		v.add("%s selector %q is missing from %s", where, selector, rel)
	}
}

func normalizedRelative(rel string) bool {
	return rel != "" && !filepath.IsAbs(rel) && filepath.Clean(rel) == rel && rel != "." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func uniqueIDs(v *validator, where string, values []string) map[string]bool {
	result := map[string]bool{}
	for _, value := range values {
		if !validID(value) {
			v.add("%s contains invalid id %q", where, value)
			continue
		}
		if result[value] {
			v.add("%s contains duplicate id %q", where, value)
		}
		result[value] = true
	}
	return result
}

func validID(value string) bool {
	return idPattern.MatchString(value)
}

func (v *validator) add(format string, args ...any) {
	v.errors = append(v.errors, fmt.Sprintf(format, args...))
}
