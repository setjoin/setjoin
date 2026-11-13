package federation

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// FrameKind enumerates the s2s wire protocol's frame types.
type FrameKind string

const (
	// KindHello is the first frame sent on every stream, both directions —
	// the app-layer identity assertion (see Hello).
	KindHello FrameKind = "hello"
	// KindMsg carries a federated message.
	KindMsg FrameKind = "msg"
	// KindReceipt carries a delivery receipt back to the sender, keyed by
	// StanzaID — the spike's stand-in for XEP-0184 (doc.go / plan Task 2).
	KindReceipt FrameKind = "receipt"
	// KindAck advances the sender's cursor (federation_ack) — sent for
	// EVERY inbound msg frame, including a duplicate (federation_apply_inbound
	// returning applied=false still MUST be acked, or the sender's cursor
	// never advances and the peer livelocks on the apply-committed/ack-lost
	// crash window — Task 2).
	KindAck FrameKind = "ack"
	// KindReplayReq is a MID-STREAM request, sent when
	// federation_apply_inbound detects a sequence gap on an otherwise-live
	// stream. Distinct from Hello.ResumeFromSeq — see the Hello doc comment
	// below for the disambiguation.
	KindReplayReq FrameKind = "replay_req"
	// KindEphemeral bypasses the outbox/seq/archive entirely — reserved for
	// typing/presence in C2. Not exercised in C0 beyond a shape assertion:
	// no reducer, no outbox row, no ordering guarantee applies to it.
	KindEphemeral FrameKind = "ephemeral"
)

// Frame is the s2s wire envelope. Length-prefixed JSON codec: a 4-byte
// big-endian length prefix followed by the JSON body (WriteFrame/ReadFrame).
// Not a production wire format choice under debate — Global Constraints
// locks the wire shape (XMPP-shaped, stanza-IDs); JSON-over-length-prefix is
// this spike's transport encoding, not itself a locked decision.
type Frame struct {
	Kind     FrameKind       `json:"kind"`
	StanzaID string          `json:"stanzaId,omitempty"`
	Payload  json.RawMessage `json:"payload,omitempty"`
}

// Hello is the app-layer identity assertion carried as the first frame on
// every stream, both directions. TLS carries no SNI on client certs, so
// FromDomain is asserted here and verified post-handshake against the
// presented certificate's SAN + the pinned allow-list anchor (stream.go).
//
// Two resume paths, disambiguated — do not conflate:
//   - Hello.ResumeFromSeq: on a fresh RECONNECT (the stream was re-established
//     after a disconnect), the receiver tells the sender where to resume via
//     the hello it sends back.
//   - replay_req (KindReplayReq): a MID-STREAM request on an otherwise-live
//     stream, sent when federation_apply_inbound detects a sequence gap. The
//     stream never dropped — this is not a reconnect.
//
// Reconnect -> hello.ResumeFromSeq. Gap-on-live-stream -> replay_req frame.
type Hello struct {
	FromDomain    string   `json:"fromDomain"`
	Ver           int      `json:"ver"`
	Caps          []string `json:"caps,omitempty"`
	ResumeFromSeq int64    `json:"resumeFromSeq"`
}

// maxFrameLen bounds a single frame's JSON body — generous for a spike;
// revisit at C1 promotion.
const maxFrameLen = 16 << 20 // 16 MiB

// WriteFrame writes f to w as a 4-byte big-endian length prefix + JSON body.
func WriteFrame(w io.Writer, f Frame) error {
	body, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("federation: marshal frame: %w", err)
	}
	if len(body) > maxFrameLen {
		return fmt.Errorf("federation: frame body %d exceeds max %d", len(body), maxFrameLen)
	}
	var hdr [4]byte
	// #nosec G115 -- len(body) is bounded by the maxFrameLen (16 MiB) check above, well within uint32
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("federation: write frame header: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("federation: write frame body: %w", err)
	}
	return nil
}

// ReadFrame reads one length-prefixed JSON frame from r.
func ReadFrame(r io.Reader) (Frame, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, fmt.Errorf("federation: read frame header: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxFrameLen {
		return Frame{}, fmt.Errorf("federation: frame length %d exceeds max %d", n, maxFrameLen)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return Frame{}, fmt.Errorf("federation: read frame body: %w", err)
	}
	var f Frame
	if err := json.Unmarshal(body, &f); err != nil {
		return Frame{}, fmt.Errorf("federation: unmarshal frame: %w", err)
	}
	return f, nil
}

// mustJSON marshals v (always a Hello/small struct in this package — never
// user-controlled data) to json.RawMessage, panicking on failure. A Hello
// value's marshal error is a programmer bug, never a runtime condition.
func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("federation: marshal %T: %v", v, err))
	}
	return b
}
