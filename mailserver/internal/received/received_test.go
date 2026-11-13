package received

import (
	"bytes"
	"testing"
	"time"
)

func TestParseTrace_EmptyIsNoHops(t *testing.T) {
	tr, err := ParseTrace([]byte("Subject: hi\r\n\r\n"), Identity{})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if tr.Direction != "inbound" || tr.HopCount != 0 || len(tr.Hops) != 0 {
		t.Fatalf("want inbound/0 hops, got %+v", tr)
	}
}

func TestParseTrace_CapsHopsAt100(t *testing.T) {
	var b []byte
	for i := 0; i < 150; i++ {
		b = append(b, []byte("Received: from a.example by b.example; Wed, 21 Jun 2026 12:00:00 +0000\r\n")...)
	}
	b = append(b, []byte("\r\n")...)
	tr, err := ParseTrace(b, Identity{})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(tr.Hops) != MaxHops || !tr.Truncated {
		t.Fatalf("want %d hops + truncated, got %d trunc=%v", MaxHops, len(tr.Hops), tr.Truncated)
	}
}

func TestParseReceivedLine_FullLine(t *testing.T) {
	line := "from mail.stripe.com (mail.stripe.com [209.85.220.41]) by inbound.setjoin.local with ESMTPS id abc; Wed, 21 Jun 2026 12:00:04 +0000"
	h := parseReceivedLine(0, line, Identity{})
	if !h.ParseOK || h.FromHost != "mail.stripe.com" || h.ByHost != "inbound.setjoin.local" {
		t.Fatalf("hosts: %+v", h)
	}
	if h.IP != "209.85.220.41" || h.RDNS != "mail.stripe.com" || !h.TLSActive {
		t.Fatalf("ip/rdns/tls: %+v", h)
	}
	if h.Timestamp == nil || h.Timestamp.Minute() != 0 {
		t.Fatalf("timestamp: %+v", h.Timestamp)
	}
}

func TestComputeDelays_ChronologicalAndSkew(t *testing.T) {
	t0 := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	t1 := t0.Add(2 * time.Second)
	tneg := t1.Add(-2 * time.Second) // clock skew: 2 s behind t1 → -2000 ms
	hops := []Hop{{Index: 0, Timestamp: &t0}, {Index: 1, Timestamp: &t1}, {Index: 2, Timestamp: &tneg}}
	computeDelaysAndAnchor(hops, Identity{})
	if hops[0].DelayMs != nil {
		t.Fatal("first hop delay must be nil")
	}
	if hops[1].DelayMs == nil || *hops[1].DelayMs != 2000 {
		t.Fatalf("want 2000ms, got %v", hops[1].DelayMs)
	}
	if hops[2].DelayMs == nil || *hops[2].DelayMs != -2000 {
		t.Fatalf("want -2000ms (skew preserved), got %v", hops[2].DelayMs)
	}
}

func TestParseTrace_AllNegativeDelaysStillTracksSlowest(t *testing.T) {
	// Four hops with all-negative inter-hop delays due to clock skew throughout.
	// Chronological order (origin first after ParseTrace reverses the chain):
	//   hop0: 12:00:10 (no delay, first hop)
	//   hop1: 12:00:05 (delay = -5000ms vs hop0)
	//   hop2: 11:59:55 (delay = -10000ms vs hop1)
	//   hop3: 11:59:54 (delay = -1000ms vs hop2) ← least-negative = maximum = "slowest"
	//
	// Received headers are stored most-recent-first; ParseTrace reverses them.
	t0 := "Wed, 21 Jun 2026 12:00:10 +0000"
	t1 := "Wed, 21 Jun 2026 12:00:05 +0000" // delay vs hop0: -5000ms
	t2 := "Wed, 21 Jun 2026 11:59:55 +0000" // delay vs hop1: -10000ms
	t3 := "Wed, 21 Jun 2026 11:59:54 +0000" // delay vs hop2: -1000ms (least-negative = max)
	mkLine := func(ts string) string {
		return "Received: from a.example by b.example; " + ts + "\r\n"
	}
	var raw []byte
	// Most-recent-first in the raw header block; ParseTrace reverses to get hop0..hop3.
	raw = append(raw, []byte(mkLine(t3))...)
	raw = append(raw, []byte(mkLine(t2))...)
	raw = append(raw, []byte(mkLine(t1))...)
	raw = append(raw, []byte(mkLine(t0))...)
	raw = append(raw, []byte("\r\n")...)

	tr, err := ParseTrace(raw, Identity{})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if tr.SlowestHopIndex == nil {
		t.Fatal("SlowestHopIndex must be non-nil when all inter-hop delays are negative")
	}
	// hop index 3 has delay -1000ms (least-negative = maximum across all delays).
	if *tr.SlowestHopIndex != 3 {
		t.Fatalf("want SlowestHopIndex=3 (least-negative delay), got %d", *tr.SlowestHopIndex)
	}
	// TotalTransitMs must be nil: no positive delays contribute to the total.
	if tr.TotalTransitMs != nil {
		t.Fatalf("want TotalTransitMs=nil (all negative delays), got %d", *tr.TotalTransitMs)
	}
}

func TestParseTrace_HostileInputs(t *testing.T) {
	cases := map[string][]byte{
		"oversized-header": append(append([]byte("Received: from a by b\r\n "), bytes.Repeat([]byte("x"), 2<<20)...), []byte("\r\n\r\n")...),
		"garbage-line":     []byte("Received: \x00\x01 not a real line\r\n\r\n"),
		"no-timestamp":     []byte("Received: from a.example by b.example\r\n\r\n"),
		"folded-ipv6":      []byte("Received: from x (x [2001:db8::1])\r\n  by y with ESMTPS;\r\n  Wed, 21 Jun 2026 12:00:00 +0000\r\n\r\n"),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseTrace(raw, Identity{}) // must never panic
			if err != nil {
				t.Fatalf("%s: ParseTrace must degrade to a nil error, got %v", name, err)
			}
		})
	}
}

func TestComputeAnchor_OnlySuffixIsOurs(t *testing.T) {
	self := Identity{Hostnames: map[string]bool{"inbound.setjoin.local": true}}
	// insert a non-ours hop between forged and real to break contiguity
	hops := []Hop{
		{Index: 0, ByHost: "inbound.setjoin.local", ParseOK: true}, // forged claim at origin
		{Index: 1, ByHost: "relay.example", ParseOK: true},
		{Index: 2, ByHost: "inbound.setjoin.local", ParseOK: true}, // real ingress (suffix)
	}
	computeDelaysAndAnchor(hops, self)
	if hops[0].IsOurInfra {
		t.Fatal("forged origin hop must NOT be our infra")
	}
	if !hops[2].IsOurInfra {
		t.Fatal("real ingress (contiguous suffix) must be our infra")
	}
}
