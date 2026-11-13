package directorysync

// Authoritative reconciliation acceptance tests (med-shard2-012,
// D-MAILSERVER-INTERNAL-DIRECTORYSYNC-001/-002). Deletion/revocation is
// derived only from an explicit upstream tombstone the connector attests;
// absence from a page, failed or partial scans, and malformed or mail-less
// objects never deprovision and never wedge the source cursor. Session,
// OAuth-token and websocket revocation itself is the reducer-owned disable
// path (identity_source_entry_apply); at this engine seam the tests assert
// the disable entry is staged within the same single Sync cycle before the
// page cursor commits.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/uuid"
	"setjoin.com/mailserver/internal/identitysource"
)

// sequencedFetch is one scripted connector cycle.
type sequencedFetch struct {
	objects []Object
	after   Cursor
	err     error
}

// sequenceConnector replays a per-cycle fetch script so multi-cycle
// reconciliation behavior (retry, incremental pages, re-presented objects)
// is exercisable with the same fake-store seam as the unit tests.
type sequenceConnector struct {
	label   string
	fetches []sequencedFetch
	calls   int
}

func (c *sequenceConnector) Label() string    { return c.label }
func (c *sequenceConnector) Preflight() error { return nil }

func (c *sequenceConnector) DecodeCursor(json.RawMessage) (Cursor, error) {
	return testCursor("before"), nil
}

func (c *sequenceConnector) Fetch(context.Context, Cursor) ([]Object, Cursor, error) {
	i := c.calls
	if i >= len(c.fetches) {
		i = len(c.fetches) - 1
	}
	c.calls++
	fetch := c.fetches[i]
	return fetch.objects, fetch.after, fetch.err
}

func (c *sequenceConnector) ValidateObject(Object, bool) error { return nil }

func stagedEntries(store *fakeStore) []identitysource.Entry {
	var out []identitysource.Entry
	for _, page := range store.pages {
		out = append(out, page.Entries...)
	}
	return out
}

func payloadOperation(t *testing.T, entry identitysource.Entry) (string, any) {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(entry.Payload, &payload); err != nil {
		t.Fatalf("decode payload for %s: %v", entry.ImmutableSubject, err)
	}
	op, _ := payload["operation"].(string)
	return op, payload["enabled"]
}

// A directory object explicitly deleted upstream (tombstone) is disabled
// locally within one cycle: the disable entry — the reducer seam that revokes
// sessions, OAuth tokens, and websocket subscriptions — is staged in the very
// same Sync call, before the page cursor commits. A tombstone propagates even
// when upstream deletion scrubbed the mail attribute, and it never destroys
// data (disable-first).
func TestSyncTombstonePropagatesDisableWithinOneCycle(t *testing.T) {
	store := &fakeStore{source: identitysource.Source{Cursor: json.RawMessage(`{"cursor":"before"}`)}, acquired: true}
	connector := &fakeConnector{
		label:  "TEST",
		before: testCursor("before"),
		after:  testCursor("after"),
		objects: []Object{
			{Subject: "live", Email: "live@example.com"},
			{Subject: "deleted-scrubbed", Tombstone: true},
			{Subject: "deleted-with-mail", Tombstone: true, Email: "gone@example.com", DisplayName: "Former"},
			{Subject: "suspended", Disabled: true, Email: "suspended@example.com"},
		},
	}
	result, err := (Engine{Store: store, Connector: connector, Instance: uuid.New()}).Sync(context.Background())
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(store.pages) != 1 {
		t.Fatalf("pages=%d want=1", len(store.pages))
	}
	page := store.pages[0]
	if string(page.Cursor) != `{"cursor":"after"}` {
		t.Fatalf("tombstone cycle must commit the page cursor, got %s", page.Cursor)
	}
	bySubject := make(map[string]identitysource.Entry, len(page.Entries))
	for _, entry := range page.Entries {
		bySubject[entry.ImmutableSubject] = entry
	}
	want := map[string]string{
		"live":              "upsert",
		"deleted-scrubbed":  "disable",
		"deleted-with-mail": "disable",
		"suspended":         "disable",
	}
	for subject, wantOp := range want {
		entry, ok := bySubject[subject]
		if !ok {
			t.Fatalf("subject %q not staged within the one cycle", subject)
		}
		op, enabled := payloadOperation(t, entry)
		if op != wantOp {
			t.Fatalf("subject %q operation=%q want=%q", subject, op, wantOp)
		}
		if wantOp == "disable" && enabled != false {
			t.Fatalf("subject %q disable payload must carry enabled=false, got %v", subject, enabled)
		}
	}
	if result.Updated != 4 || result.Errors != 0 {
		t.Fatalf("result=%+v want Updated=4 Errors=0", result)
	}
}

// Negative: an object absent from an incremental page is never deleted. The
// engine synthesizes no entry for absent subjects, so no enabled anchor is
// dropped and nothing is revoked pending an authoritative tombstone or a
// future full-reconciliation pass.
func TestSyncIncrementalAbsenceNeverDeletes(t *testing.T) {
	store := &fakeStore{source: identitysource.Source{Cursor: json.RawMessage(`{"cursor":"before"}`)}, acquired: true}
	connector := &sequenceConnector{
		label: "TEST",
		fetches: []sequencedFetch{
			{objects: []Object{
				{Subject: "anchor-a", Email: "a@example.com"},
				{Subject: "anchor-b", Email: "b@example.com"},
			}, after: testCursor("c1")},
			// Incremental page: anchor-a was not modified upstream and is
			// absent. Absence must never imply deletion.
			{objects: []Object{
				{Subject: "anchor-b", Email: "b@example.com"},
			}, after: testCursor("c2")},
		},
	}
	engine := Engine{Store: store, Connector: connector, Instance: uuid.New()}
	if _, err := engine.Sync(context.Background()); err != nil {
		t.Fatalf("cycle 1 Sync: %v", err)
	}
	second, err := engine.Sync(context.Background())
	if err != nil {
		t.Fatalf("cycle 2 Sync: %v", err)
	}
	if second.Skipped != 0 || second.Errors != 0 {
		t.Fatalf("cycle 2 result=%+v want no skips and no errors", second)
	}
	if len(store.pages) != 2 {
		t.Fatalf("pages=%d want=2", len(store.pages))
	}
	incremental := store.pages[1]
	if string(incremental.Cursor) != `{"cursor":"c2"}` {
		t.Fatalf("incremental cursor=%s want c2", incremental.Cursor)
	}
	if len(incremental.Entries) != 1 || incremental.Entries[0].ImmutableSubject != "anchor-b" {
		t.Fatalf("incremental page must only carry the present object, got %+v", incremental.Entries)
	}
	anchorA := 0
	for _, entry := range stagedEntries(store) {
		if entry.ImmutableSubject != "anchor-a" {
			continue
		}
		anchorA++
		op, enabled := payloadOperation(t, entry)
		if op != "upsert" || enabled != true {
			t.Fatalf("anchor-a must never be disabled/deleted by absence, got operation=%s enabled=%v", op, enabled)
		}
	}
	if anchorA != 1 {
		t.Fatalf("anchor-a staged %d times across both cycles, want exactly the one cycle-1 upsert", anchorA)
	}
}

// Negative: a failed or partial scan neither deletes objects nor advances the
// cursor past unscanned state — the engine stages nothing at all — and a
// retry from the same committed cursor converges to the intended page without
// duplicate side effects.
func TestSyncFailedScanNeitherDeletesNorAdvancesCursor(t *testing.T) {
	objects := []Object{
		{Subject: "anchor-a", Email: "a@example.com"},
		{Subject: "leaver", Tombstone: true, Email: "leaver@example.com"},
	}
	store := &fakeStore{source: identitysource.Source{Cursor: json.RawMessage(`{"cursor":"before"}`)}, acquired: true}
	connector := &sequenceConnector{
		label: "TEST",
		fetches: []sequencedFetch{
			// Failed scan: transport error after a partial result. The
			// partial page must be discarded entirely.
			{objects: objects, after: testCursor("after"), err: errors.New("connection reset mid-scan")},
			// Retry presents the same page from the same committed cursor.
			{objects: objects, after: testCursor("after")},
		},
	}
	engine := Engine{Store: store, Connector: connector, Instance: uuid.New()}
	if _, err := engine.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "connection reset mid-scan") {
		t.Fatalf("failed scan must surface the transport error, got %v", err)
	}
	if len(store.pages) != 0 {
		t.Fatalf("failed scan staged %d pages; it must neither delete nor advance", len(store.pages))
	}
	result, err := engine.Sync(context.Background())
	if err != nil {
		t.Fatalf("retry Sync: %v", err)
	}
	if len(store.pages) != 1 {
		t.Fatalf("retry pages=%d want=1", len(store.pages))
	}
	page := store.pages[0]
	if string(page.Cursor) != `{"cursor":"after"}` {
		t.Fatalf("retry cursor=%s want after", page.Cursor)
	}
	if len(page.Entries) != 2 {
		t.Fatalf("retry entries=%d want=2", len(page.Entries))
	}
	op, enabled := payloadOperation(t, page.Entries[1])
	if page.Entries[1].ImmutableSubject != "leaver" || op != "disable" || enabled != false {
		t.Fatalf("retry must converge the tombstoned leaver exactly once, got %+v op=%s enabled=%v",
			page.Entries[1], op, enabled)
	}
	if page.BatchID == uuid.Nil {
		t.Fatal("retry must stage under a fresh batch id")
	}
	if result.Updated != 2 || result.Errors != 0 {
		t.Fatalf("retry result=%+v want Updated=2 Errors=0", result)
	}
}

// Negative: mail-less in-scope upserts are skip-and-quarantined with loud
// error accounting instead of staging a deterministic BZ228 block that would
// wedge the source cursor every cycle; disable propagation continues past the
// quarantined object in the same page, and the quarantine accounting survives
// cursor advancement into later cycles (re-accounted, never silently
// cleared). A malformed object (missing immutable subject) likewise skips
// without freezing the rest of the page.
func TestSyncMailLessQuarantineSurvivesCyclesAndKeepsDisabling(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mailLess := Object{Subject: "mail-less", DisplayName: "No Mail Attribute"}
	disabled := Object{Subject: "suspended", Disabled: true, Email: "suspended@example.com"}
	store := &fakeStore{source: identitysource.Source{Cursor: json.RawMessage(`{"cursor":"before"}`)}, acquired: true}
	connector := &sequenceConnector{
		label: "TEST",
		fetches: []sequencedFetch{
			{objects: []Object{mailLess, disabled}, after: testCursor("c1")},
			// Later cycle re-presents the unchanged mail-less object: the
			// accounting must recur rather than be remembered-and-cleared.
			{objects: []Object{mailLess, disabled}, after: testCursor("c2")},
		},
	}
	engine := Engine{Store: store, Connector: connector, Instance: uuid.New(), Logger: logger}
	first, err := engine.Sync(context.Background())
	if err != nil {
		t.Fatalf("cycle 1 Sync: %v", err)
	}
	if first.Skipped != 1 || first.Errors != 0 {
		t.Fatalf("cycle 1 result=%+v want Skipped=1 Errors=0", first)
	}
	if len(store.pages) != 1 {
		t.Fatalf("cycle 1 pages=%d want=1", len(store.pages))
	}
	firstPage := store.pages[0]
	if len(firstPage.Entries) != 1 || firstPage.Entries[0].ImmutableSubject != "suspended" {
		t.Fatalf("mail-less object must not stage a BZ228 block and disable propagation must continue past it: %+v", firstPage.Entries)
	}
	op, _ := payloadOperation(t, firstPage.Entries[0])
	if op != "disable" {
		t.Fatalf("suspended operation=%q want disable", op)
	}
	if string(firstPage.Cursor) != `{"cursor":"c1"}` {
		t.Fatalf("cycle 1 cursor=%s; quarantine must not wedge cursor advancement", firstPage.Cursor)
	}
	second, err := engine.Sync(context.Background())
	if err != nil {
		t.Fatalf("cycle 2 Sync: %v", err)
	}
	if second.Skipped != 1 {
		t.Fatalf("cycle 2 result=%+v want Skipped=1 (accounting survives into later cycles)", second)
	}
	if len(store.pages) != 2 || string(store.pages[1].Cursor) != `{"cursor":"c2"}` {
		t.Fatalf("cycle 2 must apply and advance normally, pages=%d", len(store.pages))
	}
	if got := strings.Count(logBuf.String(), "level=ERROR"); got < 2 {
		t.Fatalf("loud quarantine accounting missing: %d ERROR records in %q", got, logBuf.String())
	}
	if !strings.Contains(logBuf.String(), "mail-less") {
		t.Fatalf("quarantine log must name the quarantined object: %q", logBuf.String())
	}
}

// Negative: one malformed object (missing immutable subject) is skipped and
// quarantined with loud accounting instead of failing the whole page, so
// disable propagation for the remaining objects is never frozen.
func TestSyncMalformedObjectDoesNotFreezeDisablePropagation(t *testing.T) {
	store := &fakeStore{source: identitysource.Source{Cursor: json.RawMessage(`{"cursor":"before"}`)}, acquired: true}
	connector := &fakeConnector{
		label:  "TEST",
		before: testCursor("before"),
		after:  testCursor("after"),
		objects: []Object{
			{Subject: "", Email: "ghost@example.com"},
			{Subject: "suspended", Disabled: true, Email: "suspended@example.com"},
		},
	}
	result, err := (Engine{Store: store, Connector: connector, Instance: uuid.New()}).Sync(context.Background())
	if err != nil {
		t.Fatalf("a malformed object must not fail the page: %v", err)
	}
	if result.Skipped != 1 || result.Updated != 1 {
		t.Fatalf("result=%+v want Skipped=1 Updated=1", result)
	}
	if len(store.pages) != 1 || len(store.pages[0].Entries) != 1 || store.pages[0].Entries[0].ImmutableSubject != "suspended" {
		t.Fatalf("malformed object must not freeze disable propagation: %+v", store.pages)
	}
	if string(store.pages[0].Cursor) != `{"cursor":"after"}` {
		t.Fatalf("cursor=%s want after; the page must still commit", store.pages[0].Cursor)
	}
}
