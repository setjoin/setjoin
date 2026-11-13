package admin

import (
	"testing"
)

func TestNewAppPasswordsHandler(t *testing.T) {
	h := NewAppPasswordsHandler(nil, nil)
	if h == nil {
		t.Fatal("NewAppPasswordsHandler returned nil")
	}
}
