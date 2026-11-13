package threat

import (
	"context"
	"testing"
)

type fakeSprayStore struct {
	detect    bool
	locked    []string // sourceIPs locked
	audited   [][]byte
	notified  []string
	callOrder []string
}

func (f *fakeSprayStore) Detect(_ context.Context, _ string, _, _ int) (bool, error) {
	f.callOrder = append(f.callOrder, "detect")
	return f.detect, nil
}

func (f *fakeSprayStore) LockIP(_ context.Context, ip string, _ int) error {
	f.callOrder = append(f.callOrder, "lock")
	f.locked = append(f.locked, ip)
	return nil
}

func (f *fakeSprayStore) Audit(_ context.Context, _ string, m []byte) error {
	f.callOrder = append(f.callOrder, "audit")
	f.audited = append(f.audited, m)
	return nil
}

func (f *fakeSprayStore) Notify(_ context.Context, ip string) error {
	f.callOrder = append(f.callOrder, "notify")
	f.notified = append(f.notified, ip)
	return nil
}

func cfgForSpray() ThreatConfig {
	return ThreatConfig{SprayWindowSecs: 60, SprayMaxUsers: 5, SprayLockoutMins: 15}
}

func TestSprayDetector_NotDetected_NoWrites(t *testing.T) {
	f := &fakeSprayStore{detect: false}
	d := NewSprayDetector(f, cfgForSpray(), nil)
	if got := d.Detect(context.Background(), ConnectionMeta{SourceIP: "9.9.9.9"}); got {
		t.Fatal("expected not detected")
	}
	if len(f.locked)+len(f.audited)+len(f.notified) != 0 {
		t.Fatalf("invariant: no writes when not detected; order=%v", f.callOrder)
	}
}

func TestSprayDetector_Detected_LockAuditNotifyInOrder(t *testing.T) {
	f := &fakeSprayStore{detect: true}
	d := NewSprayDetector(f, cfgForSpray(), nil)
	if got := d.Detect(context.Background(), ConnectionMeta{SourceIP: "9.9.9.9"}); !got {
		t.Fatal("expected detected")
	}
	want := []string{"detect", "lock", "audit", "notify"}
	if len(f.callOrder) != len(want) {
		t.Fatalf("invariant: side-effect order must be %v; got %v", want, f.callOrder)
	}
	for i := range want {
		if f.callOrder[i] != want[i] {
			t.Fatalf("invariant: side-effect order must be %v; got %v", want, f.callOrder)
		}
	}
	if len(f.audited) != 1 || len(f.audited[0]) == 0 {
		t.Fatalf("invariant: exactly one audit row with non-empty metadata; got %v", f.audited)
	}
}
