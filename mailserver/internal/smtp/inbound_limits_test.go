package smtp

import (
	"net"
	"testing"
	"time"
)

func TestMaxRecipientsConstant(t *testing.T) {
	// RFC 5321 §4.5.3.1.8 requires supporting at least 100 recipients.
	if maxRecipients < 100 {
		t.Errorf("maxRecipients = %d, must be >= 100 per RFC 5321 §4.5.3.1.8", maxRecipients)
	}
	if maxRecipients > 100000 {
		t.Errorf("maxRecipients = %d, unreasonably high", maxRecipients)
	}
}

func TestInConnStateHandleRcptEnforcesCap(t *testing.T) {
	// Fill c.to up to maxRecipients, then verify the next RCPT is rejected.
	c := &inConnState{
		state: phaseRcpt,
		from:  "sender@example.com",
	}
	c.to = make([]string, maxRecipients)
	for i := range c.to {
		c.to[i] = "rcpt@example.com"
	}

	// At capacity, handleRcpt should reject BEFORE any DB call, so nil srv is ok.
	// Use a buffered conn so reply() doesn't panic on a nil net.Conn.
	c.conn = &testConn{buf: make([]byte, 0, 1024)}
	c.handleRcpt(nil, "TO:<overflow@example.com>")

	// Verify c.to was NOT appended to.
	if len(c.to) != maxRecipients {
		t.Errorf("handleRcpt should reject at capacity %d, but c.to grew to %d", maxRecipients, len(c.to))
	}
}

// testConn implements net.Conn with minimal buffering for reply().
type testConn struct {
	buf []byte
}

func (tc *testConn) Read(b []byte) (n int, err error) { return 0, nil }
func (tc *testConn) Write(b []byte) (n int, err error) {
	tc.buf = append(tc.buf, b...)
	return len(b), nil
}
func (tc *testConn) Close() error                       { return nil }
func (tc *testConn) LocalAddr() net.Addr                { return nil }
func (tc *testConn) RemoteAddr() net.Addr               { return nil }
func (tc *testConn) SetDeadline(t time.Time) error      { return nil }
func (tc *testConn) SetReadDeadline(t time.Time) error  { return nil }
func (tc *testConn) SetWriteDeadline(t time.Time) error { return nil }
