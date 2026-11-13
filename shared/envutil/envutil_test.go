package envutil

import (
	"os"
	"testing"
)

func TestGetenv_UsesDefault(t *testing.T) {
	os.Unsetenv("TEST_GETENV_UNSET")
	if v := Getenv("TEST_GETENV_UNSET", "default"); v != "default" {
		t.Errorf("expected 'default', got %q", v)
	}
}

func TestGetenv_UsesEnv(t *testing.T) {
	os.Setenv("TEST_GETENV_SET", "hello")
	defer os.Unsetenv("TEST_GETENV_SET")
	if v := Getenv("TEST_GETENV_SET", "default"); v != "hello" {
		t.Errorf("expected 'hello', got %q", v)
	}
}

func TestParseBool_True(t *testing.T) {
	for _, s := range []string{"true", "TRUE", "1"} {
		if !ParseBool(s) {
			t.Errorf("ParseBool(%q) should be true", s)
		}
	}
}

func TestParseBool_False(t *testing.T) {
	for _, s := range []string{"false", "FALSE", "0", "", "garbage"} {
		if ParseBool(s) {
			t.Errorf("ParseBool(%q) should be false", s)
		}
	}
}

func TestRandomID_Format(t *testing.T) {
	id := RandomID()
	if len(id) != 32 {
		t.Errorf("expected 32-char hex, got %d", len(id))
	}
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("RandomID contains non-hex char: %c", c)
		}
	}
}
