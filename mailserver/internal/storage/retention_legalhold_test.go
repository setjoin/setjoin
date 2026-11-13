package storage

import (
	"context"
	"testing"
	"time"
)

// fakeRetention captures PutObjectLegalHold calls; other methods are no-ops.
type fakeRetention struct {
	calls []struct{ key, status string }
}

func (f *fakeRetention) PutObjectRetention(context.Context, string, string, time.Time) error {
	return nil
}
func (f *fakeRetention) GetObjectRetention(context.Context, string) (*RetentionStatus, error) {
	return nil, nil
}
func (f *fakeRetention) PutObjectLegalHold(_ context.Context, key, status string) error {
	f.calls = append(f.calls, struct{ key, status string }{key, status})
	return nil
}
func (f *fakeRetention) GetObjectLegalHold(context.Context, string) (string, error) {
	return "OFF", nil
}
func (f *fakeRetention) EnsureBucketObjectLock(context.Context, string, int) error { return nil }
func (f *fakeRetention) GetBucketObjectLockConfig(context.Context) (*BucketLockConfig, error) {
	return nil, nil
}

func TestSetLegalHold_DisabledNoOps(t *testing.T) {
	fake := &fakeRetention{}
	r := NewRetentionPolicyRegistry()
	r.SetLegalHoldBackend(fake, false)
	if err := r.SetLegalHold(context.Background(), "abc", true); err != nil {
		t.Fatalf("SetLegalHold: %v", err)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("expected no backend calls when disabled, got %v", fake.calls)
	}
	if r.LegalHoldEnabled() {
		t.Error("LegalHoldEnabled should be false")
	}
}

func TestSetLegalHold_OnOff(t *testing.T) {
	fake := &fakeRetention{}
	r := NewRetentionPolicyRegistry()
	r.SetLegalHoldBackend(fake, true)

	if err := r.SetLegalHold(context.Background(), "hash1", true); err != nil {
		t.Fatalf("SetLegalHold on: %v", err)
	}
	if err := r.SetLegalHold(context.Background(), "hash2", false); err != nil {
		t.Fatalf("SetLegalHold off: %v", err)
	}
	if len(fake.calls) != 2 {
		t.Fatalf("expected 2 calls, got %v", fake.calls)
	}
	if fake.calls[0] != (struct{ key, status string }{"hash1", "ON"}) {
		t.Errorf("call 0 = %v, want {hash1 ON}", fake.calls[0])
	}
	if fake.calls[1] != (struct{ key, status string }{"hash2", "OFF"}) {
		t.Errorf("call 1 = %v, want {hash2 OFF}", fake.calls[1])
	}
}
