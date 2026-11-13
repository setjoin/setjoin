package ldap

// BER frame-cap tests (er5-s15, sealed anchors ldap-ber-length-preauth-
// allocation / unbounded-ldap-ber-message-allocation): the pinned
// vjeantet/ldapserver dependency allocates the attacker-declared BER length
// before parsing, so an unauthenticated client could force a near-2 GiB
// allocation with one frame. admissionConn.frameNext mirrors the library's
// BER length rules at OUR read boundary and refuses any declared length over
// maxLDAPFrameBytes BEFORE the body buffer is allocated, so the pre-TLS-OK
// attack surface is a bounded 1 MiB read. These tests pin the refusal legs.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

var errTestEOF = errors.New("test EOF")

// berFrame renders a BER header declaring n body bytes (definite long form).
func berFrame(n int) []byte {
	var out bytes.Buffer
	out.WriteByte(0x30)
	if n < 0x80 {
		out.WriteByte(byte(n))
	} else {
		lenBytes := 4
		raw := make([]byte, 4)
		binary.BigEndian.PutUint32(raw, uint32(n))
		for lenBytes > 1 && raw[0] == 0 { //nolint:gocritic // minimal encoding
			raw = raw[1:]
			lenBytes--
		}
		out.WriteByte(byte(0x80 | lenBytes))
		out.Write(raw)
	}
	return out.Bytes()
}

// TestFrameNext_DeclaredLengthOverCapRefusedPreAllocation is the sealed-attack
// leg: frames declaring multi-gigabyte and just-over-cap bodies are refused at
// the header scan, before any body allocation. A 2 GiB declaration must cost
// bytes on the wire, not bytes in memory.
func TestFrameNext_DeclaredLengthOverCapRefusedPreAllocation(t *testing.T) {
	cases := []struct {
		name       string
		declared   int
		wireBody   int // how many body bytes actually arrive (hostile clients lie)
		wantErrHas string
	}{
		{"declared 2 GiB", 1 << 31, 0, "out of range"},
		{"declared 1.5 GiB", (3 << 29), 0, "out of range"},
		{"just over cap", maxLDAPFrameBytes + 1, 8, "out of range"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &admissionConn{
				Conn:         &limitedFrameConn{header: berFrame(tc.declared), body: bytes.Repeat([]byte{0x02}, tc.wireBody)},
				state:        newAdmissionLimiter(4, 8).newConnState(),
				writeTimeout: time.Second,
			}
			if err := c.frameNext(); err == nil {
				t.Fatalf("frame with declared length %d accepted; want %s refusal", tc.declared, tc.wantErrHas)
			} else if !bytes.Contains([]byte(err.Error()), []byte(tc.wantErrHas)) {
				t.Fatalf("refusal error = %v; want it to mention %q", err, tc.wantErrHas)
			}
			if len(c.pending) != 0 {
				t.Fatalf("refused frame left %d pending segments; want none", len(c.pending))
			}
		})
	}
}

// TestFrameNext_AtCapAccepted: the cap admits the largest legitimate frames —
// a full maxLDAPFrameBytes body is buffered and queued for the library.
func TestFrameNext_AtCapAccepted(t *testing.T) {
	body := make([]byte, maxLDAPFrameBytes)
	body[0] = 0x02 // messageID TLV tag
	limiter := newAdmissionLimiter(4, 8)
	c := &admissionConn{
		Conn:         &limitedFrameConn{header: berFrame(maxLDAPFrameBytes), body: body},
		state:        limiter.newConnState(),
		writeTimeout: time.Second,
	}
	if err := c.frameNext(); err != nil {
		t.Fatalf("frame at the cap refused: %v", err)
	}
	if len(c.pending) != 2 { // header segment + body segment
		t.Fatalf("accepted frame queued %d segments; want 2", len(c.pending))
	}
}

// TestFrameNext_UnsupportedLengthFormsRefused: BER indefinite length and
// over-long length encodings are refused, mirroring what the library would
// mis-handle.
func TestFrameNext_UnsupportedLengthFormsRefused(t *testing.T) {
	cases := []struct {
		name string
		wire []byte
	}{
		{"indefinite length", []byte{0x30, 0x80, 0x02, 0x01, 0x01}},
		{"five length octets", []byte{0x30, 0x85, 0x00, 0x00, 0x00, 0x00, 0x10}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &admissionConn{
				Conn:         &limitedFrameConn{header: tc.wire},
				state:        newAdmissionLimiter(4, 8).newConnState(),
				writeTimeout: time.Second,
			}
			if err := c.frameNext(); err == nil {
				t.Fatalf("%s accepted; want refusal", tc.name)
			}
		})
	}
}

// limitedFrameConn feeds a fixed header then a fixed body, then errors — the
// wire a hostile framing client controls.
type limitedFrameConn struct {
	header []byte
	body   []byte
}

func (f *limitedFrameConn) Read(p []byte) (int, error) {
	src := f.header
	if len(src) == 0 {
		src = f.body
	}
	if len(src) == 0 {
		return 0, errTestEOF
	}
	n := copy(p, src)
	if len(f.header) > 0 {
		f.header = f.header[n:]
	} else {
		f.body = f.body[n:]
	}
	return n, nil
}
func (f *limitedFrameConn) Write(b []byte) (int, error)      { return len(b), nil }
func (f *limitedFrameConn) Close() error                     { return nil }
func (f *limitedFrameConn) LocalAddr() net.Addr              { return addrStub{} }
func (f *limitedFrameConn) RemoteAddr() net.Addr             { return addrStub{} }
func (f *limitedFrameConn) SetDeadline(time.Time) error      { return nil }
func (f *limitedFrameConn) SetReadDeadline(time.Time) error  { return nil }
func (f *limitedFrameConn) SetWriteDeadline(time.Time) error { return nil }

type addrStub struct{}

func (addrStub) Network() string { return "tcp" }
func (addrStub) String() string  { return "test" }
