package user

import (
	"reflect"
	"testing"
)

// TestDevicesHandler_SessionMutationSurfaceIsPinned pins the device-force-logout
// closure (occ_f1816cfcbd06ffe320f81236): the vulnerable
// DELETE /user/devices/{fingerprint}/sessions endpoint (deleted in b07736bdd —
// it removed sessions rows directly and left their access JWTs usable) must
// stay OFF this surface. The handler's exported method set is exactly the
// pinned pair; any session-mutating addition here fails this test until it is
// rerouted through the CA-3a session-revocation contract
// (revoke_user_sessions — the path SessionsHandler.Revoke/RevokeAll bind), so
// the denylist propagates to the gateway.
func TestDevicesHandler_SessionMutationSurfaceIsPinned(t *testing.T) {
	want := []string{"ListDevices", "WipeAck"}
	tp := reflect.TypeOf(&DevicesHandler{})
	got := make([]string, 0, tp.NumMethod())
	for i := 0; i < tp.NumMethod(); i++ {
		got = append(got, tp.Method(i).Name)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("DevicesHandler surface = %v, want exactly %v — a session-mutating method must not reappear here without routing through the revoke_user_sessions contract", got, want)
	}
}
