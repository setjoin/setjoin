package admin

import (
	"testing"

	"setjoin.com/shared/toggle"
)

// TestSodModeDefaultOff is the critical safety guard: when the toggle key is
// absent (fresh deployment, key never seeded), SodMode must return false so the
// strict 等保三级 SoD regime is NEVER engaged by accident (the toggle registry
// pins the key default-OFF).
func TestSodModeDefaultOff(t *testing.T) {
	// Empty FeatureFlags — key "dengbao.sod_mode" is absent.
	flags := toggle.NewStatic(map[string]bool{})
	if SodMode(flags) {
		t.Fatal("SodMode on an empty FeatureFlags must return false (default-OFF safety guard)")
	}
}

func TestSodModeExplicitFalse(t *testing.T) {
	flags := toggle.NewStatic(map[string]bool{"dengbao.sod_mode": false})
	if SodMode(flags) {
		t.Fatal("SodMode with dengbao.sod_mode=false must return false")
	}
}

func TestSodModeExplicitTrue(t *testing.T) {
	flags := toggle.NewStatic(map[string]bool{"dengbao.sod_mode": true})
	if !SodMode(flags) {
		t.Fatal("SodMode with dengbao.sod_mode=true must return true")
	}
}

func TestDeriveSodClassSingleDistinct(t *testing.T) {
	got := DeriveSodClass([]string{"security", "security"})
	if got != "security" {
		t.Fatalf("DeriveSodClass([security,security]) = %q; want %q", got, "security")
	}
}

func TestDeriveSodClassMixed(t *testing.T) {
	got := DeriveSodClass([]string{"system", "audit"})
	if got != "" {
		t.Fatalf("DeriveSodClass([system,audit]) = %q; want %q", got, "")
	}
}

func TestDeriveSodClassEmpty(t *testing.T) {
	got := DeriveSodClass([]string{})
	if got != "" {
		t.Fatalf("DeriveSodClass([]) = %q; want %q", got, "")
	}
}

func TestDeriveSodClassSingleElement(t *testing.T) {
	got := DeriveSodClass([]string{"audit"})
	if got != "audit" {
		t.Fatalf("DeriveSodClass([audit]) = %q; want %q", got, "audit")
	}
}

func TestDeriveSodClassNilSlice(t *testing.T) {
	got := DeriveSodClass(nil)
	if got != "" {
		t.Fatalf("DeriveSodClass(nil) = %q; want %q", got, "")
	}
}

func TestDeriveSodClassAllEmpty(t *testing.T) {
	// Empty strings (NULL sod_class values that slipped through) should not
	// count toward the distinct set — they are filtered before comparison.
	got := DeriveSodClass([]string{"", "", ""})
	if got != "" {
		t.Fatalf("DeriveSodClass([\"\",\"\",\"\"]) = %q; want %q", got, "")
	}
}

func TestDeriveSodClassMixedWithEmpty(t *testing.T) {
	// A mix of an empty string and a real class: filtered empties leave only
	// "security", so result is "security".
	got := DeriveSodClass([]string{"", "security", "security"})
	if got != "security" {
		t.Fatalf("DeriveSodClass([\"\",security,security]) = %q; want %q", got, "security")
	}
}
