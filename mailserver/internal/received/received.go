// Package received parses an RFC822 message's Received: header chain into a
// structured, ordered delivery Trace. Input is untrusted (any sender writes
// arbitrary Received lines), so parsing is resource-bounded and panic-free.
package received

import (
	"bufio"
	"bytes"
	"io"
	"net/textproto"
	"time"
)

const (
	MaxHops        = 100
	MaxHeaderBytes = 1 << 20 // 1 MiB header cap
)

// Identity is the set of names that count as "our infrastructure".
type Identity struct {
	Hostnames map[string]bool // lowercased setjoin hostnames + accepted domains
}

type Hop struct {
	Index        int        `json:"index"`
	FromHost     string     `json:"fromHost,omitempty"`
	ByHost       string     `json:"byHost,omitempty"`
	WithProtocol string     `json:"withProtocol,omitempty"`
	IP           string     `json:"ip,omitempty"`
	RDNS         string     `json:"rdns,omitempty"`
	Timestamp    *time.Time `json:"timestamp"`
	DelayMs      *int64     `json:"delayMs"`
	TLSActive    bool       `json:"tlsActive"`
	IsOurInfra   bool       `json:"isOurInfra"`
	ParseOK      bool       `json:"parseOk"`
	RawLine      string     `json:"rawLine,omitempty"`
}

type Trace struct {
	Direction       string `json:"direction"`
	HopCount        int    `json:"hopCount"`
	TotalTransitMs  *int64 `json:"totalTransitMs"`
	SlowestHopIndex *int   `json:"slowestHopIndex"`
	Hops            []Hop  `json:"hops"`
	Truncated       bool   `json:"truncated,omitempty"`
}

// ParseTrace reads the header block of raw (bounded to MaxHeaderBytes), extracts
// the Received: chain top-down (most-recent first), reverses to chronological
// origin->destination order, caps at MaxHops, and computes per-hop fields.
func ParseTrace(raw []byte, self Identity) (Trace, error) {
	tr := Trace{Direction: "inbound", Hops: []Hop{}}
	lr := io.LimitReader(bytes.NewReader(raw), MaxHeaderBytes)
	hdr, err := textproto.NewReader(bufio.NewReader(lr)).ReadMIMEHeader()
	if err != nil && len(hdr) == 0 {
		// On unrecoverable header parse failure we degrade to an empty trace. The error
		// return is currently always nil; callers may treat any future error as non-fatal.
		return tr, nil
	}
	received := hdr.Values("Received") // top-down (most recent first)
	if len(received) > MaxHops {
		received = received[:MaxHops]
		tr.Truncated = true
	}
	// Reverse to chronological (origin first).
	n := len(received)
	hops := make([]Hop, n)
	for i := 0; i < n; i++ {
		line := received[n-1-i]
		hops[i] = parseReceivedLine(i, line, self) // Task 2
	}
	computeDelaysAndAnchor(hops, self) // Task 2
	var total int64
	var haveTotal bool
	slowIdx, slowHaveAny := -1, false
	var slowDelay int64
	for i := range hops {
		if hops[i].DelayMs != nil {
			if *hops[i].DelayMs > 0 {
				total += *hops[i].DelayMs
				haveTotal = true
			}
			if !slowHaveAny || *hops[i].DelayMs > slowDelay {
				slowDelay = *hops[i].DelayMs
				slowIdx = i
				slowHaveAny = true
			}
		}
	}
	if haveTotal {
		tr.TotalTransitMs = &total
	}
	if slowIdx >= 0 {
		tr.SlowestHopIndex = &slowIdx
	}
	tr.Hops = hops
	tr.HopCount = n
	return tr, nil
}
