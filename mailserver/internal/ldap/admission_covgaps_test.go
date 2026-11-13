package ldap

import (
	"bytes"
	"errors"
	"io"
	"net"
	"reflect"
	"testing"
	"time"

	goldapmessage "github.com/vjeantet/goldap/message"
	ldap "github.com/vjeantet/goldap/message"
	ldapserver "github.com/vjeantet/ldapserver"
)

// --- unit-level fakes for the admission framing/gate tests ---

// fakeBERConn adapts a byte buffer to net.Conn for framing unit tests.
type fakeBERConn struct {
	bytes.Reader
}

func (c *fakeBERConn) Write(p []byte) (int, error)        { return len(p), nil }
func (c *fakeBERConn) Close() error                       { return nil }
func (c *fakeBERConn) LocalAddr() net.Addr                { return fakeAdmissionAddr{} }
func (c *fakeBERConn) RemoteAddr() net.Addr               { return fakeAdmissionAddr{} }
func (c *fakeBERConn) SetDeadline(t time.Time) error      { return nil }
func (c *fakeBERConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *fakeBERConn) SetWriteDeadline(t time.Time) error { return nil }

type fakeAdmissionAddr struct{}

func (fakeAdmissionAddr) Network() string { return "tcp" }
func (fakeAdmissionAddr) String() string  { return "127.0.0.1:0" }

var _ net.Conn = (*fakeBERConn)(nil)

// busyCaptureWriter records the protocol op handed to the response writer.
type busyCaptureWriter struct {
	wrote []ldap.ProtocolOp
	names []string
}

func (w *busyCaptureWriter) Write(po ldap.ProtocolOp) {
	w.wrote = append(w.wrote, po)
	w.names = append(w.names, reflect.TypeOf(po).Name())
}

// admissionInnerSpy records whether the wrapped handler was served.
type admissionInnerSpy struct {
	served int
}

func (s *admissionInnerSpy) ServeLDAP(_ ldapserver.ResponseWriter, _ *ldapserver.Message) {
	s.served++
}

// --- tests ---

// TestAdmissionGate_AbandonBypassesAdmission pins the ABANDON exemption:
// abandon carries the cancellation signal, holds no grant, and must reach
// the wrapped handler without contending for pool slots.
func TestAdmissionGate_AbandonBypassesAdmission(t *testing.T) {
	inner := &admissionInnerSpy{}
	// Zero-capacity pool: any admission attempt would shed instead of serve.
	gate := &admissionGate{inner: inner, poolSlots: make(chan struct{})}
	msg := &ldapserver.Message{
		LDAPMessage: goldapmessage.NewLDAPMessageWithProtocolOp(goldapmessage.AbandonRequest(1)),
	}
	gate.ServeLDAP(&busyCaptureWriter{}, msg)
	if inner.served != 1 {
		t.Fatalf("abandon served=%d, want 1 (exempt from admission)", inner.served)
	}
}

// TestWriteBusyResponse_OpSpecificShapes pins the protocol-appropriate busy
// response: every operation class receives a response of its own kind.
func TestWriteBusyResponse_OpSpecificShapes(t *testing.T) {
	cases := []struct {
		name     string
		op       ldap.ProtocolOp
		wantName string
	}{
		{"bind", goldapmessage.BindRequest{}, "BindResponse"},
		{"search", goldapmessage.SearchRequest{}, "SearchResultDone"},
		{"compare", goldapmessage.CompareRequest{}, "CompareResponse"},
		{"extended", goldapmessage.ExtendedRequest{}, "ExtendedResponse"},
		{"other (del)", goldapmessage.DelRequest("cn=old,dc=example,dc=org"), "LDAPResult"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &busyCaptureWriter{}
			msg := &ldapserver.Message{
				LDAPMessage: goldapmessage.NewLDAPMessageWithProtocolOp(tc.op),
			}
			writeBusyResponse(w, msg, "server busy")
			if len(w.names) != 1 {
				t.Fatalf("wrote %d responses, want 1", len(w.names))
			}
			if got := w.names[0]; got != tc.wantName {
				t.Errorf("response op = %q, want %q", got, tc.wantName)
			}
		})
	}
}

// TestAdmissionConn_ReadZeroLengthBuffer covers the empty-buffer guard.
func TestAdmissionConn_ReadZeroLengthBuffer(t *testing.T) {
	c := &admissionConn{Conn: &fakeBERConn{}, writeTimeout: time.Second}
	n, err := c.Read(nil)
	if n != 0 || err != nil {
		t.Fatalf("Read(nil) = %d, %v; want 0, nil", n, err)
	}
}

// TestAdmissionConn_ReadPartialSegment pins the buffered-segment split: a
// caller reading with a small buffer consumes the pending segment piecemeal.
func TestAdmissionConn_ReadPartialSegment(t *testing.T) {
	frame := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	c := &admissionConn{Conn: &fakeBERConn{}, writeTimeout: time.Second, pending: [][]byte{frame}}
	first := make([]byte, 2)
	n, err := c.Read(first)
	if err != nil || n != 2 {
		t.Fatalf("first read = %d, %v; want 2, nil", n, err)
	}
	if !bytes.Equal(first, frame[:2]) {
		t.Fatalf("first read bytes = %x, want %x", first, frame[:2])
	}
	rest := make([]byte, 8)
	n, err = c.Read(rest)
	if err != nil || n != len(frame)-2 {
		t.Fatalf("second read = %d, %v; want %d, nil", n, err, len(frame)-2)
	}
	if !bytes.Equal(rest[:n], frame[2:]) {
		t.Fatalf("second read bytes = %x, want %x", rest[:n], frame[2:])
	}
	// The segment list is now empty; the next read frames from the wire
	// and hits EOF.
	if _, err := c.Read(rest); err == nil {
		t.Fatal("read past frame end: want EOF, got nil")
	}
}

// TestAdmissionListener_AddrDelegates covers the listener address pass-through.
func TestAdmissionListener_AddrDelegates(t *testing.T) {
	inner := &fakeListener{addr: fakeAdmissionAddr{}}
	l := newAdmissionListener(inner, newAdmissionLimiter(1, 1))
	if l.Addr() == nil {
		t.Fatal("Addr() = nil, want delegated address")
	}
	if l.Close() != nil {
		t.Fatal("Close() errored")
	}
}

type fakeListener struct {
	addr net.Addr
}

func (f *fakeListener) Accept() (net.Conn, error) { return nil, io.EOF }
func (f *fakeListener) Close() error              { return nil }
func (f *fakeListener) Addr() net.Addr            { return f.addr }

// TestFrameNext_MalformedBERFailsClosed exercises the BER framing guards:
// every malformed prefix is rejected with an error and never dispatched.
func TestFrameNext_MalformedBERFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		wire []byte
	}{
		{"wrong tag", []byte{0x31, 0x02, 0x02, 0x01}},
		{"EOF after tag", []byte{0x30}},
		{"indefinite length form", []byte{0x30, 0x80}},
		{"overlong length form", []byte{0x30, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00}},
		{"EOF mid length", []byte{0x30, 0x82, 0x01}},
		{"declared length out of range", []byte{0x30, 0x84, 0x7F, 0xFF, 0xFF, 0xFF}},
		{"EOF mid body", []byte{0x30, 0x10, 0x02, 0x01, 0x01}},
		{"body without messageID TLV", []byte{0x30, 0x04, 0x04, 0x02, 0x61, 0x62}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &admissionConn{
				Conn:         &fakeBERConn{Reader: *bytes.NewReader(tc.wire)},
				writeTimeout: time.Second,
				state:        newAdmissionLimiter(1, 1).newConnState(),
			}
			if err := c.frameNext(); err == nil {
				t.Fatal("frameNext accepted malformed wire bytes, want error")
			}
		})
	}
}

// TestLDAPProtocolOpTag_TLVForms pins the messageID TLV parsing: definite and
// long-form lengths parse; degenerate and out-of-bounds forms are rejected.
func TestLDAPProtocolOpTag_TLVForms(t *testing.T) {
	cases := []struct {
		name    string
		body    []byte
		wantTag byte
		wantErr bool
	}{
		{"body too short", []byte{0x02}, 0, true},
		{"not an INTEGER TLV", []byte{0x04, 0x02, 0x61, 0x62}, 0, true},
		{"long form zero length", []byte{0x02, 0x80, 0x60}, 0, true},
		{"long form over 4 bytes", []byte{0x02, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00, 0x60}, 0, true},
		{"long form truncated", []byte{0x02, 0x83, 0x01}, 0, true},
		{"long form wellformed", []byte{0x02, 0x82, 0x00, 0x01, 0x2A, 0x60}, 0x60, false},
		{"id length out of bounds", []byte{0x02, 0x01, 0x05}, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tag, err := ldapProtocolOpTag(tc.body)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ldapProtocolOpTag(% x) = %#x, nil; want error", tc.body, tag)
				}
				return
			}
			if err != nil {
				t.Fatalf("ldapProtocolOpTag(% x): %v", tc.body, err)
			}
			if tag != tc.wantTag {
				t.Errorf("tag = %#x, want %#x", tag, tc.wantTag)
			}
		})
	}
}

// TestFrameNext_ReadDeliversFramedSegments end-to-end checks the framing
// contract: a wellformed Unbind frame passes admission untouched (no grant
// consumed) and reads back as header-then-body segments.
func TestFrameNext_ReadDeliversFramedSegments(t *testing.T) {
	// Unbind: [0x30 len][0x02 0x01 msgid][0x42 0x00] — op tag 0x42.
	wire := []byte{0x30, 0x05, 0x02, 0x01, 0x01, 0x42, 0x00}
	c := &admissionConn{
		Conn:         &fakeBERConn{Reader: *bytes.NewReader(wire)},
		writeTimeout: time.Second,
		state:        newAdmissionLimiter(1, 1).newConnState(),
	}
	var got []byte
	buf := make([]byte, 64)
	for len(got) < len(wire) {
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("read at %d: %v", len(got), err)
		}
		got = append(got, buf[:n]...)
	}
	if !bytes.Equal(got, wire) {
		t.Fatalf("framed read = %x, want %x", got, wire)
	}
	if _, err := c.Read(buf); !errors.Is(err, io.EOF) && err == nil {
		t.Fatalf("read past frame: want EOF, got %v", err)
	}
}
