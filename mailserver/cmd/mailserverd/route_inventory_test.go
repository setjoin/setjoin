package main

// Golden route-inventory guard (c8).
//
// http.ServeMux does not expose its pattern table, so the inventory is captured
// AT REGISTER TIME: the six registrars are re-run against a recordingMux with
// every gatewayDeps middleware field replaced by a name-carrying recorder
// (describeMW). Each middleware application wraps the handler in a
// describedHandler that accumulates the wrapper names outermost-first, so when
// the registrar finally calls mux.Handle the recorder reads the FULL chain off
// the handler value. The result — every (method+pattern → middleware chain) —
// is pinned to testdata/route_inventory.golden.
//
// Any drift (a dropped/added route, a changed wrapper chain, a reordered
// chain) fails TestRouteInventoryGolden. Intentional changes: re-run with
// UPDATE_GOLDEN=1 and review the golden diff in the commit.
//
// What this cannot see: pool identity (app pool vs BYPASSRLS workerPool) is
// decided at handler CONSTRUCTION in runGateway, before registration — that
// invariant stays guarded by scripts/check-rls-coverage.sh. SCIM registers via
// its own sub-router on the concrete *http.ServeMux (not through a registrar)
// and is therefore out of scope for the legacy gateway golden. The emitted
// inventory is broader: package-local Drive/Chat/Meet/SCIM recorders are merged
// before the OpenAPI guards run.

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"net/http/httptest"
	"setjoin.com/mailserver/internal/caldav"
	"setjoin.com/mailserver/internal/carddav"
	"setjoin.com/mailserver/internal/config"
	"setjoin.com/mailserver/internal/meet"
	"setjoin.com/mailserver/internal/updates"
	sharedcfg "setjoin.com/shared/config"

	"setjoin.com/mailserver/internal/middleware"
)

const goldenPath = "testdata/route_inventory.golden"

// describedHandler is a registration-time chain recorder. It is never served.
type describedHandler struct {
	next  http.Handler
	chain []string // outermost wrapper first
}

func (d *describedHandler) ServeHTTP(http.ResponseWriter, *http.Request) {
	panic("describedHandler records registrations; it must never serve requests")
}

// describeMW returns a middleware stub that stamps its name onto the chain.
func describeMW(name string) middlewareFunc {
	return func(next http.Handler) http.Handler {
		if inner, ok := next.(*describedHandler); ok {
			return &describedHandler{next: inner.next, chain: append([]string{name}, inner.chain...)}
		}
		return &describedHandler{next: next, chain: []string{name}}
	}
}

func chainOf(h http.Handler) string {
	if dh, ok := h.(*describedHandler); ok {
		return strings.Join(dh.chain, " > ")
	}
	return "(none)"
}

// recordingMux satisfies the router interface, mirrors every pattern into a
// real ServeMux (pattern-syntax + conflict validation identical to production)
// and records the middleware fingerprint per pattern.
type recordingMux struct {
	real    *http.ServeMux
	records map[string]string
	errs    []error
}

func newRecordingMux() *recordingMux {
	return &recordingMux{real: http.NewServeMux(), records: map[string]string{}}
}

func (m *recordingMux) Handle(pattern string, h http.Handler) { m.record(pattern, chainOf(h)) }

func (m *recordingMux) HandleFunc(pattern string, _ func(http.ResponseWriter, *http.Request)) {
	m.record(pattern, "(none)")
}

func (m *recordingMux) record(pattern, chain string) {
	if _, dup := m.records[pattern]; dup {
		m.errs = append(m.errs, fmt.Errorf("duplicate route registration: %q", pattern))
		return
	}
	if err := registerConflictChecked(m.real, pattern); err != nil {
		m.errs = append(m.errs, err)
		return
	}
	m.records[pattern] = chain
}

func registerConflictChecked(mux *http.ServeMux, pattern string) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("invalid or conflicting route pattern %q: %v", pattern, recovered)
		}
	}()
	mux.Handle(pattern, http.NotFoundHandler()) // panics on invalid/conflicting patterns, like production
	return nil
}

func (m *recordingMux) err() error {
	if len(m.errs) == 0 {
		return nil
	}
	return fmt.Errorf("route inventory recording failed: %v", m.errs)
}

// recordingDeps builds a gatewayDeps whose middleware record their names and
// whose handlers are inert zero values (method values on nil receivers are
// legal; nothing is ever served). Conditionally-registered surfaces (favicon,
// air-gap feed, CalDAV/CardDAV, the Meet /rtc proxy) are force-enabled so the
// inventory is total.
func recordingDeps() *gatewayDeps {
	return &gatewayDeps{
		cfg: &config.Config{
			WebsiteDir:     "webmail-build",              // favicon route registers
			CryptoReloader: config.NewCryptoReloader(""), // wellknown handler reads the profile at registration
		},
		cfgPtr:      &sharedcfg.ConfigPtr[config.Config]{},
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		authProxy:   http.NotFoundHandler(),
		airgapStore: &updates.Store{},
		caldavH:     &caldav.Handler{},
		carddavH:    &carddav.Handler{},
		// force-enabled so /rtc appears in the golden inventory (meetCfg.Configured()
		// gates that registration in registerPublicRoutes, Task 13).
		meetCfg: meet.Config{APIKey: "key", APISecret: "secret", WSURL: "ws://127.0.0.1:7880"},

		requireAuth:                      describeMW("requireAuth"),
		authLimit:                        describeMW("authLimit"),
		adminLimit:                       describeMW("adminLimit"),
		setupLimit:                       describeMW("setupLimit"),
		bookingReadLimit:                 describeMW("bookingReadLimit"),
		bookingWriteLimit:                describeMW("bookingWriteLimit"),
		meetGuestReadLimit:               describeMW("meetGuestReadLimit"),
		meetGuestWriteLimit:              describeMW("meetGuestWriteLimit"),
		requireMailPerm:                  describeMW("requireMailPerm"),
		requireSystemPerm:                describeMW("requireSystemPerm"),
		requireLogsPerm:                  describeMW("requireLogsPerm"),
		requireAuthPerm:                  describeMW("requireAuthPerm"),
		requireSignInPerm:                describeMW("requireSignInPerm"),
		requireMamRead:                   describeMW("requireMamRead"),
		requireMamWrite:                  describeMW("requireMamWrite"),
		requireRolesManage:               describeMW("requireRolesManage"),
		requireCAPolicyRead:              describeMW("requireCAPolicyRead"),
		requireCAPolicyWrite:             describeMW("requireCAPolicyWrite"),
		requireScopeSetsManage:           describeMW("requireScopeSetsManage"),
		requireApprovalsManage:           describeMW("requireApprovalsManage"),
		requireApprovalsView:             describeMW("requireApprovalsView"),
		requireChatComplianceManage:      describeMW("requireChatComplianceManage"),
		requireChatComplianceView:        describeMW("requireChatComplianceView"),
		requireChatEDiscovery:            describeMW("requireChatEDiscovery"),
		requireDriveView:                 describeMW("requireDriveView"),
		requireOfficeView:                describeMW("requireOfficeView"),
		requireOfficeManage:              describeMW("requireOfficeManage"),
		requireAppsView:                  describeMW("requireAppsView"),
		requireAppsManage:                describeMW("requireAppsManage"),
		requireFederationManage:          describeMW("requireFederationManage"),
		requireGuestsManage:              describeMW("requireGuestsManage"),
		requireGuestsView:                describeMW("requireGuestsView"),
		guestFeatureGate:                 describeMW("guestFeatureGate"),
		requireSharingManage:             describeMW("requireSharingManage"),
		requireSharingRead:               describeMW("requireSharingRead"),
		requireExchangeAssessmentRead:    describeMW("requireExchangeAssessmentRead"),
		requireExchangeAssessmentRun:     describeMW("requireExchangeAssessmentRun"),
		requireExchangeAssessmentDecide:  describeMW("requireExchangeAssessmentDecide"),
		requireExchangeAssessmentAttest:  describeMW("requireExchangeAssessmentAttest"),
		requireExchangeAssessmentAudit:   describeMW("requireExchangeAssessmentAudit"),
		requireExchangeAssessmentPublish: describeMW("requireExchangeAssessmentPublish"),
		requireExchangeAssessmentDelete:  describeMW("requireExchangeAssessmentDelete"),
		requireUsersDelete:               describeMW("requireUsersDelete"),
		requireUsersRead:                 describeMW("requireUsersRead"),
		requireUsersPwReset:              describeMW("requireUsersPwReset"),
		requireUsersImpersonate:          describeMW("requireUsersImpersonate"),
		requireDomainsWrite:              describeMW("requireDomainsWrite"),
		requireQueueWrite:                describeMW("requireQueueWrite"),
		requireBackupWrite:               describeMW("requireBackupWrite"),
		requireComplianceWrite:           describeMW("requireComplianceWrite"),
		requireSecurityWrite:             describeMW("requireSecurityWrite"),
		requireSystemConfig:              describeMW("requireSystemConfig"),
		requireSystemUpgrade:             describeMW("requireSystemUpgrade"),
		requireSystemRecovery:            describeMW("requireSystemRecovery"),
		requireOfflinePolicy:             describeMW("requireOfflinePolicy"),
		requireIdentityWrite:             describeMW("requireIdentityWrite"),
		requireAuditRead:                 describeMW("requireAuditRead"),
		requireAuditExport:               describeMW("requireAuditExport"),
		requireIdentityJobAccess:         describeMW("requireIdentityJobAccess"),
		requireUsersCreate:               describeMW("requireUsersCreate"),
		requireUsersSuspend:              describeMW("requireUsersSuspend"),
		requireMailPipeline:              describeMW("requireMailPipeline"),
		requireMailSecurity:              describeMW("requireMailSecurity"),
		requireMailExport:                describeMW("requireMailExport"),
		telemetryLimit:                   describeMW("telemetryLimit"),
		linkProtectLimit:                 describeMW("linkProtectLimit"),
		requireOrgWideSurface:            describeMW("requireOrgWideSurface"),
		requireImpersonateTarget:         describeMW("requireImpersonateTarget"),
		requireWebhookCap:                describeMW("requireWebhookCap"),
		requireCalendarSubCap:            describeMW("requireCalendarSubCap"),
		recoveryLimit:                    describeMW("recoveryLimit"),
		requireReason: func(perm string) middlewareFunc {
			return describeMW("requireReason(" + perm + ")")
		},
		requireApp: func(app string) middlewareFunc {
			return describeMW("requireApp(" + app + ")")
		},
		requireAppFeatureFirst: func(feature, app string) middlewareFunc {
			return describeMW("requireAppFeatureFirst(" + feature + "," + app + ")")
		},
	}
}

func registerAll(d *gatewayDeps, mux router) {
	d.registerPublicRoutes(mux)
	d.registerJMAPRoutes(mux)
	d.registerAuthProxyRoutes(mux)
	d.registerProtocolRoutes(mux)
	d.registerUserRoutes(mux)
	d.registerAdminRoutes(mux)
}

func collectInventory(d *gatewayDeps) (map[string]string, error) {
	m := newRecordingMux()
	registerAll(d, m)
	return m.records, m.err()
}

func buildInventory(t *testing.T, d *gatewayDeps) map[string]string {
	t.Helper()
	records, err := collectInventory(d)
	if err != nil {
		t.Fatal(err)
	}
	return records
}

const routeInventorySchemaVersion = 1

var routeInventoryConditionNames = []string{"airgap", "meet", "website", "caldav", "carddav"}

type routeInventoryOperation struct {
	Method          string   `json:"method"`
	Path            string   `json:"path"`
	Pattern         string   `json:"pattern"`
	Owner           string   `json:"owner,omitempty"`
	Mount           string   `json:"mount,omitempty"`
	Middleware      string   `json:"middleware"`
	Visibility      string   `json:"visibility"`
	SatisfyingMasks []string `json:"satisfying_masks"`
}

type routeInventoryArtifact struct {
	SchemaVersion int                       `json:"schema_version"`
	RunID         string                    `json:"run_id,omitempty"`
	Owner         string                    `json:"owner"`
	Mount         string                    `json:"mount,omitempty"`
	Conditions    []string                  `json:"conditions,omitempty"`
	Operations    []routeInventoryOperation `json:"operations"`
}

func recordingDepsForMask(mask int) *gatewayDeps {
	d := recordingDeps()
	if mask&(1<<0) == 0 {
		d.airgapStore = nil
	}
	if mask&(1<<1) == 0 {
		d.meetCfg = meet.Config{}
	}
	if mask&(1<<2) == 0 {
		d.cfg.WebsiteDir = ""
	}
	if mask&(1<<3) == 0 {
		d.caldavH = nil
	}
	if mask&(1<<4) == 0 {
		d.carddavH = nil
	}
	return d
}

func routePatternParts(pattern string) (method, path string) {
	method = "ANY"
	path = pattern
	if before, after, ok := strings.Cut(pattern, " "); ok {
		method = strings.ToUpper(before)
		path = after
	}
	return method, path
}

// routeVisibility derives the OpenAPI x-visibility family from the recorded
// wrapper chain. ADMIN means the wrapper chain carries an authorization
// boundary: a ROLE wrapper or a PERMISSION wrapper (the RBAC require<Perm>
// family). Plain requireAuth, app-token gates, and the per-user fan-out
// ceilings (perUserResourceCap: requireWebhookCap / requireCalendarSubCap,
// ER5 S10) are quota/admission middleware, not authorization boundaries —
// they stay PUBLIC. The caps ride only the create of a self-service path
// whose list/delete stay plain requireAuth, so counting them as admin would
// split one path's x-visibility and break the path-granular spec stamp.
func routeVisibility(chain string) string {
	for _, wrapper := range strings.Split(chain, " > ") {
		if !strings.HasPrefix(wrapper, "require") {
			continue
		}
		if wrapper == "requireAuth" || wrapper == "requireApp" ||
			strings.HasPrefix(wrapper, "requireApp(") ||
			strings.HasPrefix(wrapper, "requireAppFeatureFirst(") {
			continue
		}
		switch wrapper {
		case "requireWebhookCap", "requireCalendarSubCap":
			continue
		}
		return "admin"
	}
	return "public"
}

func buildGatewayArtifact() (routeInventoryArtifact, error) {
	type aggregate struct {
		chain string
		masks []string
	}
	all := make(map[string]*aggregate)
	for mask := 0; mask < 1<<len(routeInventoryConditionNames); mask++ {
		records, err := collectInventory(recordingDepsForMask(mask))
		if err != nil {
			return routeInventoryArtifact{}, fmt.Errorf("configuration mask %05b: %w", mask, err)
		}
		for pattern, chain := range records {
			entry := all[pattern]
			if entry == nil {
				entry = &aggregate{chain: chain}
				all[pattern] = entry
			} else if entry.chain != chain {
				return routeInventoryArtifact{}, fmt.Errorf("route %q changes middleware between masks: %q vs %q", pattern, entry.chain, chain)
			}
			entry.masks = append(entry.masks, fmt.Sprintf("%05b", mask))
		}
	}

	patterns := make([]string, 0, len(all))
	for pattern := range all {
		patterns = append(patterns, pattern)
	}
	sort.Strings(patterns)
	artifact := routeInventoryArtifact{
		SchemaVersion: routeInventorySchemaVersion,
		Owner:         "gateway",
		Conditions:    append([]string(nil), routeInventoryConditionNames...),
		Operations:    make([]routeInventoryOperation, 0, len(patterns)),
	}
	for _, pattern := range patterns {
		method, path := routePatternParts(pattern)
		entry := all[pattern]
		artifact.Operations = append(artifact.Operations, routeInventoryOperation{
			Method:          method,
			Path:            path,
			Pattern:         pattern,
			Owner:           "gateway",
			Middleware:      entry.chain,
			Visibility:      routeVisibility(entry.chain),
			SatisfyingMasks: entry.masks,
		})
	}
	return artifact, nil
}

func allRouteInventoryMasks() []string {
	masks := make([]string, 0, 1<<len(routeInventoryConditionNames))
	for mask := 0; mask < 1<<len(routeInventoryConditionNames); mask++ {
		masks = append(masks, fmt.Sprintf("%05b", mask))
	}
	return masks
}

func readRouteInventoryArtifact(path string) (routeInventoryArtifact, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return routeInventoryArtifact{}, err
	}
	var artifact routeInventoryArtifact
	if err := json.Unmarshal(data, &artifact); err != nil {
		return routeInventoryArtifact{}, fmt.Errorf("decode %s: %w", path, err)
	}
	if artifact.SchemaVersion != routeInventorySchemaVersion {
		return routeInventoryArtifact{}, fmt.Errorf("%s: schema_version=%d, want %d", path, artifact.SchemaVersion, routeInventorySchemaVersion)
	}
	if artifact.Owner == "" || len(artifact.Operations) == 0 {
		return routeInventoryArtifact{}, fmt.Errorf("%s: owner and non-empty operations are required", path)
	}
	return artifact, nil
}

func mergeRouteInventoryArtifacts(gateway routeInventoryArtifact, children map[string]routeInventoryArtifact) (routeInventoryArtifact, error) {
	if gateway.Owner != "gateway" || len(gateway.Operations) == 0 {
		return routeInventoryArtifact{}, fmt.Errorf("gateway artifact is missing or empty")
	}
	required := map[string]string{
		"drive": "/drive/",
		"chat":  "/chat/",
		"meet":  "/meet/",
		"scim":  "/scim/",
	}
	for owner, mount := range required {
		child, ok := children[owner]
		if !ok {
			return routeInventoryArtifact{}, fmt.Errorf("missing route inventory owner %q", owner)
		}
		if child.Owner != owner || child.Mount != mount || len(child.Operations) == 0 {
			return routeInventoryArtifact{}, fmt.Errorf("invalid %s artifact: owner=%q mount=%q operations=%d", owner, child.Owner, child.Mount, len(child.Operations))
		}
		if gateway.RunID != "" && child.RunID != gateway.RunID {
			return routeInventoryArtifact{}, fmt.Errorf("stale %s artifact: run_id=%q, want %q", owner, child.RunID, gateway.RunID)
		}
	}

	mounts := make(map[string]routeInventoryOperation)
	for _, operation := range gateway.Operations {
		if operation.Pattern == "/drive/" || operation.Pattern == "/chat/" || operation.Pattern == "/meet/" || operation.Pattern == "/meet" {
			mounts[operation.Pattern] = operation
		}
	}
	for _, mount := range []string{"/drive/", "/chat/", "/meet/", "/meet"} {
		if _, ok := mounts[mount]; !ok {
			return routeInventoryArtifact{}, fmt.Errorf("gateway mount %q is missing", mount)
		}
	}

	merged := routeInventoryArtifact{
		SchemaVersion: routeInventorySchemaVersion,
		RunID:         gateway.RunID,
		Owner:         "merged",
		Conditions:    append([]string(nil), gateway.Conditions...),
	}
	seen := make(map[string]string)
	add := func(operation routeInventoryOperation) error {
		key := operation.Method + " " + operation.Path
		if prior, exists := seen[key]; exists {
			return fmt.Errorf("duplicate operation %s from %s and %s", key, prior, operation.Owner)
		}
		if operation.Method == "" || operation.Path == "" || operation.Owner == "" || operation.Visibility == "" {
			return fmt.Errorf("operation %q is missing method, path, owner, or visibility", key)
		}
		seen[key] = operation.Owner
		merged.Operations = append(merged.Operations, operation)
		return nil
	}
	for _, operation := range gateway.Operations {
		if _, opaque := mounts[operation.Pattern]; opaque {
			continue
		}
		if err := add(operation); err != nil {
			return routeInventoryArtifact{}, err
		}
	}
	owners := []string{"drive", "chat", "meet", "scim"}
	for _, owner := range owners {
		child := children[owner]
		for _, operation := range child.Operations {
			method, path := routePatternParts(operation.Pattern)
			if method != operation.Method || path != operation.Path {
				return routeInventoryArtifact{}, fmt.Errorf("%s operation fields disagree for pattern %q", owner, operation.Pattern)
			}
			operation.Owner = owner
			operation.Mount = child.Mount
			if owner == "scim" {
				operation.Middleware = "scimAuthenticate > requireContentType"
				operation.Visibility = "public"
				operation.SatisfyingMasks = allRouteInventoryMasks()
			} else {
				mountPattern := child.Mount
				if owner == "meet" && operation.Path == "/meet" {
					mountPattern = "/meet"
				}
				outer := mounts[mountPattern]
				operation.Middleware = outer.Middleware
				operation.Visibility = outer.Visibility
				operation.SatisfyingMasks = append([]string(nil), outer.SatisfyingMasks...)
			}
			if err := add(operation); err != nil {
				return routeInventoryArtifact{}, err
			}
		}
	}
	sort.Slice(merged.Operations, func(i, j int) bool {
		left := merged.Operations[i].Method + " " + merged.Operations[i].Path
		right := merged.Operations[j].Method + " " + merged.Operations[j].Path
		return left < right
	})
	return merged, nil
}

func writeRouteInventoryOutput(path string, artifact routeInventoryArtifact) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".partial-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	encoder := json.NewEncoder(tmp)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(artifact); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func writeRouteInventoryArtifact(dir, filename string, artifact routeInventoryArtifact) error {
	if dir == "" {
		return fmt.Errorf("ROUTE_INVENTORY_OUTPUT_DIR is empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filename+".partial-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	encoder := json.NewEncoder(tmp)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(artifact); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, filepath.Join(dir, filename))
}

func renderInventory(records map[string]string) string {
	patterns := make([]string, 0, len(records))
	for p := range records {
		patterns = append(patterns, p)
	}
	sort.Strings(patterns)
	var b strings.Builder
	b.WriteString("# Golden route inventory — every registered route and its middleware chain\n")
	b.WriteString("# (outermost wrapper first). Regenerate after an INTENTIONAL route change:\n")
	b.WriteString("#   UPDATE_GOLDEN=1 go test ./cmd/mailserverd/ -run TestRouteInventoryGolden\n")
	b.WriteString("# and review the diff in the commit. See route_inventory_test.go.\n")
	for _, p := range patterns {
		fmt.Fprintf(&b, "%s\t%s\n", p, records[p])
	}
	return b.String()
}

func TestRouteInventoryGolden(t *testing.T) {
	got := renderInventory(buildInventory(t, recordingDeps()))

	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("golden regenerated: %s (%d routes)", goldenPath, strings.Count(got, "\n")-4)
		return
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("golden file missing (%v) — run UPDATE_GOLDEN=1 go test ./cmd/mailserverd/ -run TestRouteInventoryGolden", err)
	}
	if got == string(want) {
		return
	}
	// Line-level diff so the drift is named, not just detected.
	gotLines := strings.Split(got, "\n")
	wantLines := strings.Split(string(want), "\n")
	gotSet := make(map[string]bool, len(gotLines))
	wantSet := make(map[string]bool, len(wantLines))
	for _, l := range gotLines {
		gotSet[l] = true
	}
	for _, l := range wantLines {
		wantSet[l] = true
	}
	for _, l := range wantLines {
		if l != "" && !gotSet[l] {
			t.Errorf("route inventory drift — missing/changed: %s", l)
		}
	}
	for _, l := range gotLines {
		if l != "" && !wantSet[l] {
			t.Errorf("route inventory drift — new/changed:     %s", l)
		}
	}
	t.Error("route inventory drifted from testdata/route_inventory.golden — if intentional, regenerate with UPDATE_GOLDEN=1 and review the diff")
}

func TestRouteInventoryEmit(t *testing.T) {
	dir := os.Getenv("ROUTE_INVENTORY_OUTPUT_DIR")
	if dir == "" {
		t.Skip("ROUTE_INVENTORY_OUTPUT_DIR is not set")
	}
	runID := os.Getenv("ROUTE_INVENTORY_RUN_ID")
	if runID == "" {
		t.Fatal("ROUTE_INVENTORY_RUN_ID is required when emitting route inventory")
	}
	artifact, err := buildGatewayArtifact()
	if err != nil {
		t.Fatal(err)
	}
	if len(artifact.Operations) == 0 {
		t.Fatal("gateway route inventory is empty")
	}
	artifact.RunID = runID
	if err := writeRouteInventoryArtifact(dir, "gateway.json", artifact); err != nil {
		t.Fatal(err)
	}
}

func TestRouteInventoryMerge(t *testing.T) {
	inputDir := os.Getenv("ROUTE_INVENTORY_INPUT_DIR")
	outputPath := os.Getenv("ROUTE_INVENTORY_MERGED_OUTPUT")
	if inputDir == "" || outputPath == "" {
		t.Skip("ROUTE_INVENTORY_INPUT_DIR and ROUTE_INVENTORY_MERGED_OUTPUT are not set")
	}
	gateway, err := readRouteInventoryArtifact(filepath.Join(inputDir, "gateway.json"))
	if err != nil {
		t.Fatal(err)
	}
	children := make(map[string]routeInventoryArtifact)
	for _, owner := range []string{"drive", "chat", "meet", "scim"} {
		artifact, err := readRouteInventoryArtifact(filepath.Join(inputDir, owner+".json"))
		if err != nil {
			t.Fatal(err)
		}
		children[owner] = artifact
	}
	merged, err := mergeRouteInventoryArtifacts(gateway, children)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeRouteInventoryOutput(outputPath, merged); err != nil {
		t.Fatal(err)
	}
}

func TestRouteInventoryMergePreservesPrivateOuterBoundary(t *testing.T) {
	gateway, err := buildGatewayArtifact()
	if err != nil {
		t.Fatal(err)
	}
	children := make(map[string]routeInventoryArtifact)
	for owner, mount := range map[string]string{"drive": "/drive/", "chat": "/chat/", "meet": "/meet/", "scim": "/scim/"} {
		path := mount + "fixture"
		if owner == "meet" {
			path = "/meet"
		}
		children[owner] = routeInventoryArtifact{
			SchemaVersion: routeInventorySchemaVersion,
			Owner:         owner,
			Mount:         mount,
			Operations: []routeInventoryOperation{{
				Method:  "GET",
				Path:    path,
				Pattern: "GET " + path,
			}},
		}
	}
	merged, err := mergeRouteInventoryArtifacts(gateway, children)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range merged.Operations {
		if operation.Owner == "gateway" {
			if operation.Pattern == "/drive/" || operation.Pattern == "/chat/" || operation.Pattern == "/meet/" || operation.Pattern == "/meet" {
				t.Errorf("opaque mount survived merge: %s", operation.Pattern)
			}
			continue
		}
		if operation.Owner == "scim" {
			if operation.Visibility != "public" || operation.Middleware == "" {
				t.Errorf("SCIM boundary missing: %+v", operation)
			}
			continue
		}
		if operation.Visibility != "public" || !strings.Contains(operation.Middleware, "requireAuth") || len(operation.SatisfyingMasks) != 32 {
			t.Errorf("private outer mount boundary missing: %+v", operation)
		}
	}
}

func TestRouteInventoryMergeRejectsMissingOwnerAndDuplicate(t *testing.T) {
	gateway, err := buildGatewayArtifact()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mergeRouteInventoryArtifacts(gateway, nil); err == nil {
		t.Fatal("merge accepted missing owner artifacts")
	}
	children := make(map[string]routeInventoryArtifact)
	for owner, mount := range map[string]string{"drive": "/drive/", "chat": "/chat/", "meet": "/meet/", "scim": "/scim/"} {
		children[owner] = routeInventoryArtifact{
			SchemaVersion: routeInventorySchemaVersion,
			Owner:         owner,
			Mount:         mount,
			Operations: []routeInventoryOperation{{
				Method: "GET", Path: "/duplicate", Pattern: "GET /duplicate",
			}},
		}
	}
	if _, err := mergeRouteInventoryArtifacts(gateway, children); err == nil {
		t.Fatal("merge accepted duplicate child operations")
	}
}

func TestRouteInventoryConditionalMasks(t *testing.T) {
	artifact, err := buildGatewayArtifact()
	if err != nil {
		t.Fatal(err)
	}
	byPattern := make(map[string]routeInventoryOperation, len(artifact.Operations))
	for _, operation := range artifact.Operations {
		byPattern[operation.Pattern] = operation
	}
	cases := []struct {
		pattern string
		bit     byte
	}{
		{"POST /admin/updates/airgap/upload", '1'},
		{"/rtc", '1'},
		{"GET /favicon.ico", '1'},
		{"/caldav/", '1'},
		{"/carddav/", '1'},
	}
	for index, tc := range cases {
		op, ok := byPattern[tc.pattern]
		if !ok {
			t.Fatalf("conditional route %q missing", tc.pattern)
		}
		if len(op.SatisfyingMasks) != 16 {
			t.Errorf("%s: got %d satisfying masks, want 16", tc.pattern, len(op.SatisfyingMasks))
		}
		for _, mask := range op.SatisfyingMasks {
			// Masks are rendered airgap,meet,website,caldav,carddav from the
			// most-significant display position to the least-significant bit.
			position := 4 - index
			if len(mask) != 5 || mask[position] != tc.bit {
				t.Errorf("%s: invalid satisfying mask %q for condition %s", tc.pattern, mask, routeInventoryConditionNames[index])
			}
		}
	}
	if got := len(byPattern["POST /jmap"].SatisfyingMasks); got != 32 {
		t.Errorf("unconditional route POST /jmap has %d masks, want 32", got)
	}
}

func TestRouteInventoryRecorderRejectsDuplicateAndInvalid(t *testing.T) {
	m := newRecordingMux()
	m.Handle("GET /ok", http.NotFoundHandler())
	m.Handle("GET /ok", http.NotFoundHandler())
	m.Handle("not a valid pattern with spaces", http.NotFoundHandler())
	if err := m.err(); err == nil {
		t.Fatal("recorder accepted duplicate and invalid route patterns")
	}
}

func TestLegacyUpgradeRouteBoundary(t *testing.T) {
	records := buildInventory(t, recordingDeps())

	for _, pattern := range []string{
		"POST /admin/system/upgrade/check",
		"POST /admin/system/upgrade/apply",
		"POST /admin/system/upgrade/rollback",
	} {
		if _, ok := records[pattern]; !ok {
			t.Errorf("legacy 410 compatibility route %q is not registered", pattern)
		}
	}
	if _, ok := records["GET /admin/system/upgrade/status"]; !ok {
		t.Error("read-only upgrade history route is not registered")
	}
	for _, pattern := range []string{
		"POST /admin/updates/server/upload",
		"GET /admin/updates/server/history",
	} {
		if _, ok := records[pattern]; ok {
			t.Errorf("dead server-update UI route %q must remain absent", pattern)
		}
	}
}

// Hard pins independent of the golden file (survive a careless regeneration):
// the deliberately-unwrapped WS upgrade, the JMAP auth wrap, the auth-proxy
// rate limit, and one admin chain in canonical adminLimit>requireAuth>perm order.
func TestRouteInventory_LoadBearingChains(t *testing.T) {
	inv := buildInventory(t, recordingDeps())
	pins := map[string]string{
		"GET /jmap/ws":     "(none)", // RFC 6455: cookie auth inside the Upgrade handler; adding middleware here breaks browser WS
		"POST /jmap":       "requireAuth",
		"POST /auth/login": "authLimit",
		// Owner decision A3: the unauthenticated setup completion-state endpoint
		// must never lose its per-IP rate limiter (and the 404-after-completion
		// gate lives inside the handler — setup_protection.go).
		"GET /setup/status":                                                 "setupLimit",
		"GET /auth/password-policy":                                         "authLimit",
		"GET /auth/guest-invite/accept":                                     "authLimit",
		"POST /auth/guest-invite/accept":                                    "authLimit",
		"PUT /admin/features/{key}":                                         "adminLimit > requireAuth > requireSystemConfig > requireReason(system.config)",
		"DELETE /admin/features/{key}":                                      "adminLimit > requireAuth > requireSystemConfig > requireReason(system.config)",
		"PUT /admin/features/registry-mode":                                 "adminLimit > requireAuth > requireSystemConfig > requireReason(system.config)",
		"/auth/admin/":                                                      "authLimit > requireAuth > requireIdentityWrite",
		"GET /admin/identity/v2/sources":                                    "adminLimit > requireAuth > requireUsersRead",
		"GET /admin/identity/v2/people/{id}":                                "adminLimit > requireAuth > requireUsersRead",
		"GET /admin/identity/v2/conflicts/{id}":                             "adminLimit > requireAuth > requireUsersRead",
		"POST /admin/identity/v2/conflicts/{id}/decision":                   "adminLimit > requireAuth > requireIdentityWrite > requireReason(identity.write)",
		"GET /admin/identity/v2/events":                                     "adminLimit > requireAuth > requireAuditRead",
		"GET /admin/identity/v2/transitions/{id}":                           "adminLimit > requireAuth > requireUsersRead",
		"GET /admin/identity/v2/transitions/{id}/report":                    "adminLimit > requireAuth > requireAuditExport",
		"POST /admin/identity/v2/transitions/preview":                       "adminLimit > requireAuth > requireIdentityWrite > requireReason(identity.write)",
		"POST /admin/identity/v2/transitions/{id}/step-up/challenge":        "adminLimit > requireAuth > requireIdentityWrite",
		"POST /admin/identity/v2/transitions/{id}/step-up/complete":         "adminLimit > requireAuth > requireIdentityWrite",
		"POST /admin/identity/v2/transitions/{id}/request":                  "adminLimit > requireAuth > requireIdentityWrite > requireReason(identity.write)",
		"POST /admin/identity/v2/transitions/{id}/approve":                  "adminLimit > requireAuth > requireIdentityWrite > requireReason(identity.write)",
		"POST /admin/identity/v2/transitions/{id}/deny":                     "adminLimit > requireAuth > requireIdentityWrite > requireReason(identity.write)",
		"POST /admin/identity/v2/transitions/{id}/execute":                  "adminLimit > requireAuth > requireIdentityWrite > requireReason(identity.write)",
		"POST /admin/identity/v2/transitions/{id}/cancel":                   "adminLimit > requireAuth > requireIdentityWrite > requireReason(identity.write)",
		"POST /admin/identity/v2/transitions/{id}/effects/{effectId}/retry": "adminLimit > requireAuth > requireIdentityWrite > requireReason(identity.write)",
		"POST /admin/identity/v2/transitions/{id}/rollback-preview":         "adminLimit > requireAuth > requireIdentityWrite > requireReason(identity.write)",
		"POST /admin/identity/v2/transitions/{id}/rollback":                 "adminLimit > requireAuth > requireIdentityWrite > requireReason(identity.write)",
		"GET /admin/identity/v2/upgrade/status":                             "adminLimit > requireAuth > requireSystemUpgrade > requireIdentityWrite",
		"POST /admin/identity/v2/upgrade/canary":                            "adminLimit > requireAuth > requireSystemUpgrade > requireIdentityWrite > requireReason(identity.write)",
		"POST /admin/identity/v2/upgrade/rollback":                          "adminLimit > requireAuth > requireSystemUpgrade > requireIdentityWrite > requireReason(identity.write)",
		// D-MAILSERVER-INTERNAL-DEPLOY-R-001: the deploy status body is a
		// secret-sensitive read surface (projection carries key paths/flags
		// only); it must stay gated to system.upgrade holders, never the
		// any-of-four System-console scopes (which include backup.read).
		"GET /admin/deploy/status": "adminLimit > requireAuth > requireSystemUpgrade",
		// D-MAILSERVER-INTERNAL-USER-F-002: the M365 consent callback is an
		// authenticated, mail.pipeline-gated mutation (server-side single-use
		// consent state + verify-before-persist + audit). It must NEVER go
		// back to an unauthenticated "(none)" chain — the cookie/query state
		// pair alone is not authentication. er5-s10 adds requireOrgWideSurface:
		// the consent flow binds a TENANT, which is installation-global, so a
		// domain-scoped admin is refused before the handler (strengthening —
		// the never-unauthenticated + pipeline-gated pins are unchanged).
		"GET /admin/migration/m365/callback": "requireAuth > requireMailPipeline > requireOrgWideSurface",
	}
	for pattern, chain := range pins {
		got, ok := inv[pattern]
		if !ok {
			t.Errorf("load-bearing route missing: %q", pattern)
			continue
		}
		if got != chain {
			t.Errorf("load-bearing chain changed on %q: got %q, want %q", pattern, got, chain)
		}
	}
}

// Selftest: prove the mechanism FIRES on the drift classes it guards.
func TestRouteInventory_MechanismFires(t *testing.T) {
	base := renderInventory(buildInventory(t, recordingDeps()))

	// (a) a dropped route (whole registrar left out) must change the inventory.
	m := newRecordingMux()
	d := recordingDeps()
	d.registerPublicRoutes(m)
	d.registerJMAPRoutes(m)
	d.registerAuthProxyRoutes(m)
	d.registerProtocolRoutes(m)
	d.registerUserRoutes(m)
	// registerAdminRoutes deliberately omitted
	if err := m.err(); err != nil {
		t.Fatal(err)
	}
	if renderInventory(m.records) == base {
		t.Fatal("selftest: dropping every admin route did NOT change the inventory — the guard is asleep")
	}

	// (b) a changed middleware chain must change the inventory: swap the
	// requireAuth recorder for a differently-named one (models a route being
	// re-wrapped / un-wrapped).
	d2 := recordingDeps()
	d2.requireAuth = describeMW("TAMPERED")
	if renderInventory(buildInventory(t, d2)) == base {
		t.Fatal("selftest: a changed middleware chain did NOT change the inventory — the guard is asleep")
	}
}

// TestRouteInventoryCacheControlCensusFreeze pins every Cache-Control value
// the pre-WP2 handlers set, through the middleware table (plan WP2 req 2 —
// the freeze lives HERE and in cache_control_test.go; the two tables must not
// drift apart). Values verified against the pre-migration handlers
// (apidocs.go, downloads, airgap HandleAppcast, wellknown, unfurl, blob,
// content_serve, eventsource, favicon) — exact rows are pinned EXACTLY:
// sibling redirect handlers that previously emitted no header stay no-store.
func TestRouteInventoryCacheControlCensusFreeze(t *testing.T) {
	cases := map[string]string{
		"/favicon.ico":                                 "public, max-age=604800, immutable",
		"/api/fonts/ibm-plex-sans-400.woff2":           "public, max-age=31536000, immutable",
		"/api/fonts/ibm-plex-sans-500.woff2":           "public, max-age=31536000, immutable",
		"/chat/unfurl/image/abc":                       "private, max-age=31536000, immutable",
		"/jmap/download/a/b/c.txt":                     "private, max-age=31536000, immutable, no-transform",
		"/blobs/aaa":                                   "private, max-age=31536000, immutable",
		"/.well-known/autoconfig/mail/config-v1.1.xml": "public, max-age=86400",
		"/.well-known/setjoin":                         "public, max-age=3600",
		"/updates/appcast":                             "public, max-age=300",
		"/downloads":                                   "public, max-age=3600",
		"/api/openapi.yaml":                            "public, max-age=300",
		"/api/openapi.json":                            "public, max-age=300",
		"/api/docs":                                    "no-store", // pre-wave handler emitted no header
		"/api/redoc.standalone.js":                     "public, max-age=86400",
		"/api/logo.svg":                                "public, max-age=86400",
		"/jmap/eventsource":                            "no-cache",
		"/admin/identity/v2/diagnostics/42/download":   "private, no-store",
		"/admin/identity/v2/sources":                   "private, no-cache",
		// Deny-by-default + formerly-headerless siblings.
		"/downloads/macos":       "no-store",
		"/downloads/asset/pkg-1": "no-store",
		"/updates/slug/file.pkg": "no-store",
		"/api/openapi.full.yaml": "no-store",
		"/mail-attachment/abc":   "private, max-age=31536000, immutable, no-transform",
		"/link-protect":          "no-store",
	}
	for path, want := range cases {
		rec := httptest.NewRecorder()
		middleware.CacheControl(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if got := rec.Header().Get("Cache-Control"); got != want {
			t.Errorf("%s: Cache-Control = %q, want %q", path, got, want)
		}
	}
}
