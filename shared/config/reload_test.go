package config

import "testing"

func TestConfigPtrStoreLoad(t *testing.T) {
	ptr := new(ConfigPtr[int])
	if ptr.Load() != nil {
		t.Error("expected nil from empty ConfigPtr")
	}
	val := 42
	ptr.Store(&val)
	if got := ptr.Load(); got == nil || *got != 42 {
		t.Errorf("expected 42, got %v", got)
	}
}
