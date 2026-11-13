package main

import (
	"os"
	"syscall"
	"testing"
)

func TestRequestOverseerListenerReleaseSignalsOnlyEnabledWorker(t *testing.T) {
	var got []os.Signal
	record := func(sig os.Signal) error {
		got = append(got, sig)
		return nil
	}

	if err := requestOverseerListenerRelease(false, record); err != nil {
		t.Fatalf("disabled release: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("disabled release sent %v, want no signal", got)
	}

	if err := requestOverseerListenerRelease(true, record); err != nil {
		t.Fatalf("enabled release: %v", err)
	}
	if len(got) != 1 || got[0] != syscall.SIGUSR2 {
		t.Fatalf("enabled release sent %v, want exactly SIGUSR2", got)
	}
}

func TestRequestOverseerListenerReleasePropagatesSignalFailure(t *testing.T) {
	want := syscall.EPERM
	err := requestOverseerListenerRelease(true, func(os.Signal) error { return want })
	if err != want {
		t.Fatalf("release error = %v, want %v", err, want)
	}
}
