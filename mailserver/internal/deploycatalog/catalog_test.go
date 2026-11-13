package deploycatalog

import (
	"reflect"
	"testing"
)

func names(input []Unit) []string {
	result := make([]string, 0, len(input))
	for _, unit := range input {
		result = append(result, unit.Name)
	}
	return result
}

func TestCatalogOwnsFixedOrdersAndRecoverySet(t *testing.T) {
	wantStart := []string{"setjoin-valkey", "setjoin-sfu", "setjoin-egress", "setjoin-funasr", "setjoin-asr-bot", "setjoin-auth", "setjoin", "setjoin-gateway", "setjoin-updater"}
	wantStop := []string{"setjoin-updater", "setjoin-gateway", "setjoin", "setjoin-auth", "setjoin-asr-bot", "setjoin-funasr", "setjoin-egress", "setjoin-sfu", "setjoin-valkey"}
	wantRecovery := []string{"setjoin-auth", "setjoin", "setjoin-updater"}
	if got := names(All()); !reflect.DeepEqual(got, wantStart) {
		t.Fatalf("start order = %v, want %v", got, wantStart)
	}
	if got := names(Stop()); !reflect.DeepEqual(got, wantStop) {
		t.Fatalf("stop order = %v, want %v", got, wantStop)
	}
	if got := names(RecoveryObserved()); !reflect.DeepEqual(got, wantRecovery) {
		t.Fatalf("recovery units = %v, want %v", got, wantRecovery)
	}
}

func TestCatalogRowsAreCompleteAndFixed(t *testing.T) {
	seenNames, seenDestinations, seenOrders := map[string]bool{}, map[string]bool{}, map[int]bool{}
	for _, unit := range All() {
		if unit.Name == "" || unit.Template == "" || unit.Destination == "" || unit.Renderer == "" {
			t.Fatalf("incomplete row: %#v", unit)
		}
		if seenNames[unit.Name] || seenDestinations[unit.Destination] || seenOrders[unit.StartOrder] {
			t.Fatalf("duplicate catalog fact: %#v", unit)
		}
		seenNames[unit.Name], seenDestinations[unit.Destination], seenOrders[unit.StartOrder] = true, true, true
		if unit.Destination != "/etc/systemd/system/"+unit.Name+".service" {
			t.Fatalf("unexpected destination for %s: %s", unit.Name, unit.Destination)
		}
		if unit.Feature != "" && unit.Feature != "captions" {
			t.Fatalf("unknown feature %q", unit.Feature)
		}
	}
	// #264: the Rust front door is a core unit the updater restarts with Go;
	// it is not a recovery-observed unit (rollback points clients back at Go).
	if got := names(Core()); !reflect.DeepEqual(got, []string{"setjoin-auth", "setjoin", "setjoin-gateway"}) {
		t.Fatalf("core units = %v", got)
	}
	if Updater().Name != "setjoin-updater" {
		t.Fatal("updater role is not unique")
	}
}
