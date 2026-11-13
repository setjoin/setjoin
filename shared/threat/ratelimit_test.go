package threat

import (
	"context"
	"testing"
)

type fakeRLStore struct {
	count int
	keys  []string
}

func (f *fakeRLStore) Incr(_ context.Context, key string) (int, error) {
	f.keys = append(f.keys, key)
	return f.count, nil
}

func TestRateLimiter_AllowUnderThreshold(t *testing.T) {
	f := &fakeRLStore{count: 3}
	rl := NewRateLimiter(f, ThreatConfig{RateLimitPerMin: 5}, nil)
	if !rl.Allow(context.Background(), ConnectionMeta{Protocol: ProtocolHTTP, SourceIP: "1.1.1.1"}) {
		t.Fatal("count 3 <= limit 5 must allow")
	}
	if len(f.keys) != 1 || f.keys[0] != "auth:http:1.1.1.1" {
		t.Fatalf("invariant: key auth:PROTOCOL:IP; got %v", f.keys)
	}
}

func TestRateLimiter_BlockOverThreshold(t *testing.T) {
	f := &fakeRLStore{count: 6}
	rl := NewRateLimiter(f, ThreatConfig{RateLimitPerMin: 5}, nil)
	if rl.Allow(context.Background(), ConnectionMeta{Protocol: ProtocolHTTP, SourceIP: "1.1.1.1"}) {
		t.Fatal("count 6 > limit 5 must block")
	}
}
