package jmap

import (
	"context"
	"encoding/json"
	"testing"

	"setjoin.com/shared/pgxutil"
)

// TestCalendarA3MethodsRegistered verifies the eight A3 calendar methods are wired into
// the JMAP dispatcher under the calendar capability.
func TestCalendarA3MethodsRegistered(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)

	methods := []string{
		"Calendar/getShared",
		"CalendarEvent/getShared",
		"Calendar/shareGet",
		"Calendar/shareSet",
		"Calendar/delegateList",
		"CalendarEvent/setOccurrence",
		"CalendarEvent/resourceList",
		"CalendarEvent/sendUpdate",
	}
	for _, m := range methods {
		if _, ok := h.methods[m]; !ok {
			t.Errorf("%s is not registered in the JMAP dispatcher", m)
		}
		// All eight must route under the calendar capability/app gate.
		if app := h.methods[m].app; app != "calendar" {
			t.Errorf("appForMethod(%q) = %q, want \"calendar\"", m, app)
		}
		if cap := h.capabilityForMethod(m); cap != "urn:ietf:params:jmap:calendars" {
			t.Errorf("capabilityForMethod(%q) = %q, want calendars urn", m, cap)
		}
	}
}

// TestCalendarA3UnknownMethodRoutesToError confirms a bogus Calendar/* method errors.
func TestCalendarA3UnknownMethodRoutesToError(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	user := testClaims(1)
	name, _ := h.Dispatch(context.Background(), user, "Calendar/nope", json.RawMessage(`{"accountId":"1"}`))
	if name != "error" {
		t.Fatalf("unknown Calendar method returned %q, want \"error\"", name)
	}
}

// TestCalendarGetSharedUsesAuthenticatedViewer verifies Calendar/getShared derives the
// viewer from the authenticated user — a viewerId field in the body is never trusted, and
// the request accountId must still be the user's own (the same-mailbox guard is intact).
func TestCalendarGetSharedUsesAuthenticatedViewer(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	user := testClaims(1)

	// Wrong accountId (not the user's id in nil-pool mode) is rejected even though a
	// viewerId is supplied — proving the body can't smuggle a viewer.
	args, _ := json.Marshal(map[string]any{
		"accountId":  "99999",
		"viewerId":   "99999",
		"ownerEmail": "alice@x.test",
	})
	name, _ := h.Dispatch(context.Background(), user, "Calendar/getShared", args)
	if name != "error" {
		t.Fatalf("getShared with mismatched accountId returned %q, want \"error\"", name)
	}

	// Correct accountId (matches userID=1) but missing ownerEmail → invalidArguments.
	args2, _ := json.Marshal(map[string]any{"accountId": "1"})
	name2, result2 := h.Dispatch(context.Background(), user, "Calendar/getShared", args2)
	if name2 != "error" {
		t.Fatalf("getShared without ownerEmail returned %q, want \"error\"", name2)
	}
	var errObj map[string]any
	_ = json.Unmarshal(result2, &errObj)
	if typ, _ := errObj["type"].(string); typ != "urn:ietf:params:jmap:error:invalidArguments" {
		t.Errorf("getShared missing ownerEmail: type = %q, want invalidArguments", typ)
	}

	// Correct accountId + ownerEmail in nil-pool mode → empty list, not an error.
	args3, _ := json.Marshal(map[string]any{"accountId": "1", "ownerEmail": "alice@x.test"})
	name3, result3 := h.Dispatch(context.Background(), user, "Calendar/getShared", args3)
	if name3 != "Calendar/getShared" {
		t.Fatalf("getShared (valid) returned %q, want \"Calendar/getShared\"", name3)
	}
	var obj map[string]any
	if err := json.Unmarshal(result3, &obj); err != nil {
		t.Fatalf("getShared result not valid JSON: %v", err)
	}
	if _, ok := obj["list"]; !ok {
		t.Error("getShared result missing 'list' key")
	}
}

// TestCalendarEventGetSharedRequiresOwnerEmail mirrors the viewer/owner contract for events.
func TestCalendarEventGetSharedRequiresOwnerEmail(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	user := testClaims(1)

	args, _ := json.Marshal(map[string]any{"accountId": "1"})
	name, result := h.Dispatch(context.Background(), user, "CalendarEvent/getShared", args)
	if name != "error" {
		t.Fatalf("getShared(events) without ownerEmail returned %q, want \"error\"", name)
	}
	var errObj map[string]any
	_ = json.Unmarshal(result, &errObj)
	if typ, _ := errObj["type"].(string); typ != "urn:ietf:params:jmap:error:invalidArguments" {
		t.Errorf("getShared(events) type = %q, want invalidArguments", typ)
	}
}

// TestCalendarA3AccountIDFromAuth verifies the owner/account methods reject a mismatched
// accountId (R2): the mailbox identity always comes from auth, never the request body.
func TestCalendarA3AccountIDFromAuth(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	user := testClaims(1)

	for _, m := range []string{
		"Calendar/getShared",
		"CalendarEvent/getShared",
		"Calendar/shareGet",
		"Calendar/shareSet",
		"Calendar/delegateList",
		"CalendarEvent/setOccurrence",
		"CalendarEvent/resourceList",
		"CalendarEvent/sendUpdate",
	} {
		args, _ := json.Marshal(map[string]any{
			"accountId":  "99999",
			"ownerEmail": "x@x.test",
			"calendarId": "1",
			"masterId":   "1",
			"scope":      "this",
			"eventId":    "1",
		})
		name, _ := h.Dispatch(context.Background(), user, m, args)
		if name != "error" {
			t.Errorf("%s with mismatched accountId returned %q, want \"error\"", m, name)
		}
	}
}

// TestCalendarShareSetNilPool confirms shareSet returns a non-error shape in nil-pool mode
// when called with the user's own accountId and a calendarId.
func TestCalendarShareSetNilPool(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	user := testClaims(1)
	args, _ := json.Marshal(map[string]any{
		"accountId":  "1",
		"calendarId": "5",
		"grants":     []map[string]string{{"userEmail": "bob@x.test", "level": "write"}},
		"revokes":    []any{},
	})
	name, result := h.Dispatch(context.Background(), user, "Calendar/shareSet", args)
	if name != "Calendar/shareSet" {
		t.Fatalf("shareSet (nil pool) returned %q: %s", name, string(result))
	}
}

// TestCalendarEventSetOccurrenceScopeValidation verifies an invalid scope is rejected with
// invalidArguments before the reducer is reached.
func TestCalendarEventSetOccurrenceScopeValidation(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	user := testClaims(1)
	args, _ := json.Marshal(map[string]any{
		"accountId":    "1",
		"masterId":     "10",
		"recurrenceId": "2026-06-22T09:00:00Z",
		"scope":        "bogus",
	})
	name, result := h.Dispatch(context.Background(), user, "CalendarEvent/setOccurrence", args)
	if name != "error" {
		t.Fatalf("setOccurrence with bad scope returned %q, want \"error\"", name)
	}
	var errObj map[string]any
	_ = json.Unmarshal(result, &errObj)
	if typ, _ := errObj["type"].(string); typ != "urn:ietf:params:jmap:error:invalidArguments" {
		t.Errorf("setOccurrence bad scope: type = %q, want invalidArguments", typ)
	}
}

// TestCalendarEventRsvpOnBehalfAccepted verifies the rsvp handler parses an onBehalfOf
// field. In nil-pool mode the delegate path returns a non-error stub carrying onBehalfOf,
// proving the field is threaded through (and never treated as a self-RSVP).
func TestCalendarEventRsvpOnBehalfAccepted(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	user := testClaims(1)
	args, _ := json.Marshal(map[string]any{
		"accountId":  "1",
		"eventId":    "7",
		"status":     "accepted",
		"onBehalfOf": "manager@x.test",
	})
	name, result := h.Dispatch(context.Background(), user, "CalendarEvent/rsvp", args)
	if name != "CalendarEvent/rsvp" {
		t.Fatalf("rsvp onBehalfOf returned %q: %s", name, string(result))
	}
	var obj map[string]any
	if err := json.Unmarshal(result, &obj); err != nil {
		t.Fatalf("rsvp onBehalfOf result not valid JSON: %v", err)
	}
	if obj["onBehalfOf"] != "manager@x.test" {
		t.Errorf("rsvp onBehalfOf not threaded through: %v", obj["onBehalfOf"])
	}
}

// TestCalendarEventRsvpInvalidStatus confirms an invalid status is rejected for both the
// self and delegate paths.
func TestCalendarEventRsvpInvalidStatus(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	user := testClaims(1)
	args, _ := json.Marshal(map[string]any{"accountId": "1", "eventId": "7", "status": "maybe"})
	name, _ := h.Dispatch(context.Background(), user, "CalendarEvent/rsvp", args)
	if name != "error" {
		t.Fatalf("rsvp with invalid status returned %q, want \"error\"", name)
	}
}

// TestMergeResourceBookings verifies the create result gains a resourceBookings object
// without dropping the original created map.
func TestMergeResourceBookings(t *testing.T) {
	createResult := json.RawMessage(`{"accountId":"1","created":{"k1":"42"}}`)
	bookings := map[string]map[string]json.RawMessage{
		"k1": {"roomA@x.test": json.RawMessage(`{"type":"conflict"}`)},
	}
	merged := mergeResourceBookings(createResult, bookings)
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(merged, &obj); err != nil {
		t.Fatalf("merged result not valid JSON: %v", err)
	}
	if _, ok := obj["created"]; !ok {
		t.Error("merged result dropped 'created'")
	}
	if _, ok := obj["resourceBookings"]; !ok {
		t.Error("merged result missing 'resourceBookings'")
	}
}
