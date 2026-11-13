package imap

import (
	"net"
	"testing"
	"time"

	"setjoin.com/shared/threat"
)

func TestAuthenticatedIMAPConnectionClosesOnAllSessionRevocation(t *testing.T) {
	t.Parallel()
	registry := threat.NewProtocolSessionRegistry()
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		_ = serverConn.Close()
		_ = clientConn.Close()
	})
	state := &connState{
		srv:  &Server{sessionRegistry: registry},
		conn: serverConn,
	}
	state.trackProtocolSession(42, time.Now().UTC())

	registry.Apply(threat.RevocationRow{
		UserID: 42, Scope: threat.ScopeAll, NotBefore: time.Now().UTC().Add(time.Second),
	})
	_ = clientConn.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	if _, err := clientConn.Read(one[:]); err == nil {
		t.Fatal("revoked IMAP connection remained open")
	}
	state.sessionRelease()
}
