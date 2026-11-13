// receiver_room_dispatch_test.go — Pillar C2 Task 4: pure-Go unit coverage
// of the content-type dispatch Handle gained for rooms/advisories
// (roomContentType/advisoryContentType -> handleRoom). The dispatch itself
// requires a real DB round trip once past the toggle gate (federation_apply_room's
// exactly-once bookkeeping is Step 1, unconditionally — see that file's
// header), so the actual routing-into-federation_apply_room behavior is
// proven live by room_apply_integration_test.go (DB-gated). This file covers
// what IS provable without a database: the toggle gate applies uniformly
// across every content type BEFORE any dispatch decision or DB access is
// made, and the two new constants carry their contracted wire values.
package federation

import (
	"encoding/json"
	"errors"
	"testing"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
)

func TestRoomContentTypeConstants(t *testing.T) {
	if roomContentType != "application/x-setjoin-room" {
		t.Errorf("roomContentType = %q, want application/x-setjoin-room", roomContentType)
	}
	if advisoryContentType != "application/x-setjoin-advisory" {
		t.Errorf("advisoryContentType = %q, want application/x-setjoin-advisory", advisoryContentType)
	}
}

// TestHandle_ToggleGateAppliesBeforeRoomDispatch proves the feature.federation
// toggle check runs BEFORE the content-type dispatch (and therefore before
// any DB access) for room and advisory frames exactly as it already does for
// chat frames — a nil/zero-value WorkerPool would panic on first use, so a
// clean ErrFederationDisabled return (no panic) is itself the proof no DB
// call was attempted. An unknown content_type (Task 8 Step 5's funnel
// fallback) is included in the same loop: the toggle gate is Handle's very
// first check, before ANY dispatch decision (funnel included) is even made.
func TestHandle_ToggleGateAppliesBeforeRoomDispatch(t *testing.T) {
	for _, ct := range []string{roomContentType, advisoryContentType, chatContentType, "application/x-unknown-funnel-test"} {
		t.Run(ct, func(t *testing.T) {
			flags := toggle.NewTestFlags(map[string]bool{"feature.federation": false})
			r := NewReceiver(pgxutil.WorkerPool{}, flags, "peer.test", testLogger())

			payload, err := json.Marshal(map[string]any{"op": "message"})
			if err != nil {
				t.Fatalf("marshal payload: %v", err)
			}
			env := msgEnvelope{PeerSeq: 1, ContentType: ct, Payload: payload}
			envBytes, err := json.Marshal(env)
			if err != nil {
				t.Fatalf("marshal envelope: %v", err)
			}

			_, err = r.Handle(t.Context(), Frame{Kind: KindMsg, StanzaID: "s1", Payload: envBytes})
			if !errors.Is(err, ErrFederationDisabled) {
				t.Fatalf("Handle with feature.federation OFF, content_type %q: err = %v, want ErrFederationDisabled", ct, err)
			}
		})
	}
}
