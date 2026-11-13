package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ca_docs_consistency_test.go — D-DOCS-001 doc-vs-artifact consistency gate.
//
// docs/conditional-access.md documents the committed CA artifacts:
//   - docs/starter-packs/minimal-safe.json
//   - docs/starter-packs/cis-style.json
//   - docs/starter-packs/dengbao-level3.json
//   - docs/examples/conditional-access-policy-repo/.policy/cookbook.json
//
// The gate mechanically fails when the operator guide claims an
// observation-only (report_only) posture that the committed JSONs contradict
// (CWE-1188 manifesting as documentation-of-control mismatch): an operator
// following the documented install/import commands must get the enforcement
// states the artifacts actually carry, never an undocumented deny/MFA
// activation with no observation window.
//
// If this test fails: either the doc drifted from the artifacts (fix the doc
// or repoint the packs — flipping artifact states is a product decision) or a
// new claim phrasing must be added to reportOnlyClaimRe below.

// committedCAArtifacts are the pack documents the operator guide makes state
// claims about, relative to the repository root.
var committedCAArtifacts = []string{
	"docs/starter-packs/minimal-safe.json",
	"docs/starter-packs/cis-style.json",
	"docs/starter-packs/dengbao-level3.json",
	"docs/examples/conditional-access-policy-repo/.policy/cookbook.json",
}

// caDocPolicy is the subset of a CA export policy the gate compares.
type caDocPolicy struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

// caDocArtifact is the subset of a CA export document the gate compares.
type caDocArtifact struct {
	SchemaVersion int           `json:"schemaVersion"`
	Policies      []caDocPolicy `json:"policies"`
}

// reportOnlyClaimRe matches doc phrasings that claim every policy in a
// referenced artifact is observation-only. Extend alongside the doc: a new
// exclusivity phrasing that this regex misses silently disarms the gate.
var reportOnlyClaimRe = regexp.MustCompile(
	"(?i)(\\ball([ \t]+in)?[ \t]+`?report_only`?|" +
		"状态均为[ \t]*`?report_only`?|" +
		"safe-rollout[ \t]+begins[ \t]+in[ \t]+`?report_only`?)")

// packFileRefRe matches mentions of a committed artifact file in the doc.
var packFileRefRe = regexp.MustCompile(
	`(minimal-safe|cis-style|dengbao-level3)\.json|cookbook\.json`)

// caDocsRepoRoot walks up from the test working directory (the mailctl package
// dir under `go test`) to the repository root, identified by the operator guide.
func caDocsRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("ca docs repo root: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, statErr := os.Stat(filepath.Join(dir, "docs", "conditional-access.md")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("ca docs consistency: repo root containing docs/conditional-access.md not found")
	return ""
}

// loadCAArtifact reads and parses a committed CA pack document.
func loadCAArtifact(t *testing.T, root, rel string) caDocArtifact {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read committed CA artifact %s: %v", rel, err)
	}
	var doc caDocArtifact
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse committed CA artifact %s: %v", rel, err)
	}
	if len(doc.Policies) == 0 {
		t.Fatalf("committed CA artifact %s has no policies; is it still the reconciled pack?", rel)
	}
	return doc
}

// allReportOnly reports whether every policy in the artifact is report_only.
func allReportOnly(doc caDocArtifact) bool {
	for _, p := range doc.Policies {
		if p.State != "report_only" {
			return false
		}
	}
	return true
}

// checkReportOnlyClaims lint-checks docText: any line carrying a
// report_only-exclusivity claim must not reference an artifact that ships a
// non-report_only policy. File references on the claim line itself and on the
// line immediately after it (comment-above-command shape) are checked.
// Returns human-readable violations; empty means the doc is consistent.
func checkReportOnlyClaims(docText string, artifacts map[string]caDocArtifact) []string {
	var violations []string
	lines := strings.Split(docText, "\n")
	for i, line := range lines {
		if !reportOnlyClaimRe.MatchString(line) {
			continue
		}
		refs := packFileRefRe.FindAllString(line, -1)
		if i+1 < len(lines) {
			refs = append(refs, packFileRefRe.FindAllString(lines[i+1], -1)...)
		}
		seen := map[string]bool{}
		for _, ref := range refs {
			if seen[ref] {
				continue
			}
			seen[ref] = true
			doc, ok := artifacts[ref]
			if !ok {
				continue
			}
			if !allReportOnly(doc) {
				states := make([]string, 0, len(doc.Policies))
				for _, p := range doc.Policies {
					states = append(states, p.Name+"="+p.State)
				}
				violations = append(violations, fmt.Sprintf(
					"line %d claims a report_only-only posture but %s ships enforcing policies (states: %s)",
					i+1, ref, strings.Join(states, ", ")))
			}
		}
	}
	return violations
}

// docJSONBlocks extracts the contents of ```json fenced code blocks.
func docJSONBlocks(docText string) [][]byte {
	var (
		blocks [][]byte
		cur    []string
		in     bool
	)
	for _, line := range strings.Split(docText, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") {
			if in {
				blocks = append(blocks, []byte(strings.Join(cur, "\n")))
				cur = nil
				in = false
			} else if strings.TrimPrefix(trimmed, "```") == "json" {
				in = true
			}
			continue
		}
		if in {
			cur = append(cur, line)
		}
	}
	return blocks
}

// TestCADocsEnforcementClaimsMatchArtifacts is the doc-lint gate: the operator
// guide must never document enforcing starter packs or the CI cookbook as
// report_only-only. Fails on the exact D-DOCS-001 contradiction shape.
//
// Note: this gate compares enforcement states only. It deliberately does not
// pin the packs to validateDoc offline: cis-style.json and dengbao-level3.json
// currently fail the committed seam's device_trust enum (they use "unmanaged";
// shared/threat/policyschema.go allows managed/known/unknown/risky). That is a
// pre-existing artifact-vs-schema defect outside this package's scope,
// reported separately.
func TestCADocsEnforcementClaimsMatchArtifacts(t *testing.T) {
	root := caDocsRepoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "docs", "conditional-access.md"))
	if err != nil {
		t.Fatalf("read docs/conditional-access.md: %v", err)
	}
	docText := string(raw)

	artifacts := map[string]caDocArtifact{}
	for _, rel := range committedCAArtifacts {
		artifacts[filepath.Base(rel)] = loadCAArtifact(t, root, rel)
	}

	// Non-vacuity: the guide must still reference the committed artifacts,
	// otherwise the gate below would pass on a doc that no longer says
	// anything checkable.
	if len(packFileRefRe.FindAllString(docText, -1)) == 0 {
		t.Fatalf("docs/conditional-access.md no longer references any committed CA artifact; doc-lint gate is vacuous")
	}

	for _, v := range checkReportOnlyClaims(docText, artifacts) {
		t.Errorf("docs/conditional-access.md: %s", v)
	}
}

// TestCADocLintGateFailsOnContradictedClaim proves the gate actually fails
// when a report_only claim is contradicted by committed artifacts, and stays
// quiet for a truthful claim about a genuinely report_only-only pack.
func TestCADocLintGateFailsOnContradictedClaim(t *testing.T) {
	minimalSafe := loadCAArtifact(t, caDocsRepoRoot(t), "docs/starter-packs/minimal-safe.json")
	contradicted := map[string]caDocArtifact{
		"minimal-safe.json": minimalSafe,
		"synthetic.json": {Policies: []caDocPolicy{
			{Name: "a", State: "report_only"},
			{Name: "b", State: "report_only"},
		}},
	}

	doc := "# Start from a pack: all in `report_only`\n" +
		"mailctl ca install-pack docs/starter-packs/minimal-safe.json\n" +
		"| Minimal safe | `minimal-safe.json` | all `report_only` |\n" +
		"| Synthetic | `synthetic.json` | all `report_only` |\n" +
		"- 状态均为 `report_only` 的 `synthetic.json`\n"

	violations := checkReportOnlyClaims(doc, contradicted)
	if len(violations) != 2 {
		t.Fatalf("expected exactly 2 violations for the contradicted minimal-safe claims, got %d: %v",
			len(violations), violations)
	}
	for _, v := range violations {
		if !strings.Contains(v, "minimal-safe.json") {
			t.Errorf("violation does not name the contradicted artifact: %s", v)
		}
	}

	// The truthful synthetic claims (synthetic.json is really report_only-only)
	// must not be flagged — the gate fires only on contradiction.
	truthfulOnly := checkReportOnlyClaims(
		"| Synthetic | `synthetic.json` | all `report_only` |", contradicted)
	if len(truthfulOnly) != 0 {
		t.Errorf("truthful report_only claim flagged: %v", truthfulOnly)
	}
}

// docSamplePolicies extracts CA policy samples from one ```json fenced block.
// Two shapes carry policy state: the full policy document (top-level
// "policies" array, the §3 format sample) and the §4.1–4.3 cookbook-sample
// shape — a bare single-policy object with "name" and "state" fields.
// Anything else (condition/grant snippets, non-policy JSON) yields no samples.
// Before this helper existed the bare §4.1–4.3 objects were skipped entirely,
// so a flipped state in them escaped the cookbook cross-reference (Astra
// wave12-14 med-shard3-005 finding (a)).
func docSamplePolicies(block []byte) []caDocPolicy {
	var asDoc caDocArtifact
	if err := json.Unmarshal(block, &asDoc); err == nil && len(asDoc.Policies) > 0 {
		return asDoc.Policies
	}
	var asSingle caDocPolicy
	if err := json.Unmarshal(block, &asSingle); err == nil &&
		asSingle.Name != "" && asSingle.State != "" {
		return []caDocPolicy{asSingle}
	}
	return nil
}

// caDocCookbookSection returns the Cookbook section of the operator guide: the
// lines from its "## … Cookbook" heading up to (not including) the next "## "
// section heading. ok is false when the heading structure changed, and callers
// must treat that as a vacuous gate and fail.
func caDocCookbookSection(docText string) (section string, ok bool) {
	lines := strings.Split(docText, "\n")
	start := -1
	for i, line := range lines {
		if strings.HasPrefix(line, "## ") && strings.Contains(line, "Cookbook") {
			start = i
			break
		}
	}
	if start < 0 {
		return "", false
	}
	for end := start + 1; end < len(lines); end++ {
		if strings.HasPrefix(lines[end], "## ") {
			return strings.Join(lines[start:end], "\n"), true
		}
	}
	return strings.Join(lines[start:], "\n"), true
}

// caDocSampleViolations cross-references every policy sample embedded in
// docText (both shapes from docSamplePolicies) against the committed cookbook:
// a sample whose policy name exists in the cookbook must carry the cookbook's
// enforcement state. Returns the violations plus the set of cookbook policy
// names the samples actually exercise, for non-vacuity assertions.
func caDocSampleViolations(docText string, cookbook caDocArtifact) (violations []string, matched map[string]bool) {
	committed := map[string]string{}
	for _, p := range cookbook.Policies {
		committed[p.Name] = p.State
	}
	matched = map[string]bool{}
	for i, block := range docJSONBlocks(docText) {
		for _, p := range docSamplePolicies(block) {
			want, ok := committed[p.Name]
			if !ok {
				continue // pattern outside the committed cookbook
			}
			matched[p.Name] = true
			if p.State != want {
				violations = append(violations, fmt.Sprintf(
					"doc sample policy %q (json block %d): state %q contradicts committed cookbook.json state %q",
					p.Name, i, p.State, want))
			}
		}
	}
	return violations, matched
}

// TestCADocSamplesMatchCommittedCookbook cross-references the MFA baseline and
// the other embedded policy samples against the committed CI cookbook: any doc
// sample whose policy name exists in cookbook.json must carry the same
// enforcement state, so §4.1 can never silently flip relative to the artifact
// operators actually import. Non-vacuity is anchored to the §4 Cookbook
// region: §4.1–4.3 are the samples the guide itself documents as the committed
// cookbook (§4.7), so the unrelated §3 format document must not be able to
// satisfy the cross-reference on §4's behalf (that masking is exactly what let
// a §4.1 state flip escape the gate before — Astra wave12-14 med-shard3-005).
func TestCADocSamplesMatchCommittedCookbook(t *testing.T) {
	root := caDocsRepoRoot(t)
	rawDoc, err := os.ReadFile(filepath.Join(root, "docs", "conditional-access.md"))
	if err != nil {
		t.Fatalf("read docs/conditional-access.md: %v", err)
	}
	docText := string(rawDoc)
	cookbook := loadCAArtifact(t, root, "docs/examples/conditional-access-policy-repo/.policy/cookbook.json")

	docViolations, _ := caDocSampleViolations(docText, cookbook)
	for _, v := range docViolations {
		t.Errorf("docs/conditional-access.md: %s", v)
	}

	section, ok := caDocCookbookSection(docText)
	if !ok {
		t.Fatalf("docs/conditional-access.md no longer has a Cookbook section heading; the §4 ↔ cookbook.json cross-reference is vacuous")
	}
	_, sectionMatched := caDocSampleViolations(section, cookbook)
	for _, p := range cookbook.Policies {
		if !sectionMatched[p.Name] {
			t.Errorf("docs/conditional-access.md Cookbook section no longer embeds a sample named %q; the §4 ↔ cookbook.json cross-reference is vacuous for it",
				p.Name)
		}
	}
}

// TestCADocSampleGateFailsWhenSection41FlipsToReportOnly is the mutation-proof
// self-test arm for the cross-reference gate: it flips the §4.1 sample state
// back to report_only in the real guide text — the exact regression shape the
// Astra wave12-14 review flagged (a §4.1 flip to report_only used to pass
// because the bare sample objects were never parsed) — and requires the gate
// to fail on it.
func TestCADocSampleGateFailsWhenSection41FlipsToReportOnly(t *testing.T) {
	root := caDocsRepoRoot(t)
	rawDoc, err := os.ReadFile(filepath.Join(root, "docs", "conditional-access.md"))
	if err != nil {
		t.Fatalf("read docs/conditional-access.md: %v", err)
	}
	docText := string(rawDoc)
	cookbook := loadCAArtifact(t, root, "docs/examples/conditional-access-policy-repo/.policy/cookbook.json")

	// Positive control: the committed guide must be clean before the mutation,
	// otherwise the arm below would prove nothing.
	if clean, _ := caDocSampleViolations(docText, cookbook); len(clean) != 0 {
		t.Fatalf("docs/conditional-access.md already contradicts cookbook.json; the mutation arm would be meaningless: %v", clean)
	}

	// Locate the §4.1 sample inside the Cookbook section and flip its state.
	section, ok := caDocCookbookSection(docText)
	if !ok {
		t.Fatalf("docs/conditional-access.md no longer has a Cookbook section heading; cannot run the §4.1 mutation arm")
	}
	var original, flipped string
	for _, block := range docJSONBlocks(section) {
		policies := docSamplePolicies(block)
		if len(policies) == 1 && policies[0].Name == "Require MFA — All Users" {
			original = string(block)
			flipped = strings.Replace(original, `"state": "on"`, `"state": "report_only"`, 1)
			break
		}
	}
	if original == "" || flipped == original {
		t.Fatalf("could not locate the §4.1 sample (a bare policy object named %q with state \"on\"); the mutation arm needs it present",
			"Require MFA — All Users")
	}
	if !strings.Contains(docText, original) {
		t.Fatalf("§4.1 sample block content not found verbatim in the guide; the mutation arm would be a no-op")
	}
	mutatedDoc := strings.Replace(docText, original, flipped, 1)

	violations, _ := caDocSampleViolations(mutatedDoc, cookbook)
	for _, v := range violations {
		if strings.Contains(v, "Require MFA — All Users") && strings.Contains(v, "report_only") {
			return // the gate caught the §4.1 flip: mutation-proofed
		}
	}
	t.Fatalf("flipping the §4.1 sample to report_only escaped the cookbook cross-reference gate (violations: %v)", violations)
}
