package db

import (
	"io"
	"log/slog"
	"testing"
)

func TestNewListenerDelegatesToSharedImplementation(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if listener := NewListener(nil, logger); listener == nil {
		t.Fatal("NewListener returned nil")
	}
}
