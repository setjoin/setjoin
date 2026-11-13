package threat

import "testing"

func TestMatchDeviceBound(t *testing.T) {
	cases := []struct {
		name  string
		cond  map[string]interface{}
		bound bool
		want  bool
	}{
		{"absent condition always matches", map[string]interface{}{}, false, true},
		{"require bound, device bound", map[string]interface{}{"device_bound": true}, true, true},
		{"require bound, device NOT bound", map[string]interface{}{"device_bound": true}, false, false},
		{"require unbound, device unbound", map[string]interface{}{"device_bound": false}, false, true},
	}
	for _, c := range cases {
		if got := matchDeviceBound(c.cond, c.bound); got != c.want {
			t.Fatalf("%s: matchDeviceBound=%v want %v", c.name, got, c.want)
		}
	}
}

func TestMatchApprovedClientApp(t *testing.T) {
	// require_approved_client_app:true is satisfied iff the device proof is bound
	// (native shell only); a plain browser (bound=false) fails.
	if !matchApprovedClientApp(map[string]interface{}{}, false) {
		t.Fatal("absent condition must match")
	}
	if !matchApprovedClientApp(map[string]interface{}{"require_approved_client_app": true}, true) {
		t.Fatal("native shell (bound) must satisfy require_approved_client_app")
	}
	if matchApprovedClientApp(map[string]interface{}{"require_approved_client_app": true}, false) {
		t.Fatal("plain browser (unbound) must fail require_approved_client_app")
	}
}

func TestRequireCompliantDeviceAction(t *testing.T) {
	row := PolicyRow{ID: 1, Name: "lockdown"}
	// approved + bound -> allow
	ctx1 := PolicyEvalContext{DeviceBound: true, EnrollState: "approved"}
	if r := dispatchAction(map[string]interface{}{"require_compliant_device": true}, row, ctx1, nil); r.Decision != DecisionAllow {
		t.Fatalf("approved+bound: want allow, got %v", r.Decision)
	}
	// unbound -> block
	ctx2 := PolicyEvalContext{DeviceBound: false, EnrollState: "approved"}
	if r := dispatchAction(map[string]interface{}{"require_compliant_device": true}, row, ctx2, nil); r.Decision != DecisionBlock {
		t.Fatalf("unbound: want block, got %v", r.Decision)
	}
	// bound but not approved (enrolled) -> block
	ctx3 := PolicyEvalContext{DeviceBound: true, EnrollState: "enrolled"}
	if r := dispatchAction(map[string]interface{}{"require_compliant_device": true}, row, ctx3, nil); r.Decision != DecisionBlock {
		t.Fatalf("bound-not-approved: want block, got %v", r.Decision)
	}
}
