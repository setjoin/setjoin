package smtp

import (
	"net"
	"testing"
	"time"

	"setjoin.com/shared/threat"
)

func TestAuthenticatedSubmissionConnectionClosesOnAllSessionRevocation(t *testing.T) {
	t.Parallel()
	registry := threat.NewProtocolSessionRegistry()
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		_ = serverConn.Close()
		_ = clientConn.Close()
	})
	state := &subConnState{
		srv:  &SubmissionServer{sessionRegistry: registry},
		conn: serverConn,
	}
	state.trackProtocolSession(84, time.Now().UTC())

	registry.Apply(threat.RevocationRow{
		UserID: 84, Scope: threat.ScopeAll, NotBefore: time.Now().UTC().Add(time.Second),
	})
	_ = clientConn.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	if _, err := clientConn.Read(one[:]); err == nil {
		t.Fatal("revoked SMTP submission connection remained open")
	}
	state.sessionRelease()
}
