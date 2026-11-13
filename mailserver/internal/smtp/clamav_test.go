package smtp

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type scriptedClamConn struct {
	commands  chan string
	responses chan []byte
	closed    atomic.Bool
}

func (c *scriptedClamConn) Read(p []byte) (int, error) {
	response, ok := <-c.responses
	if !ok {
		return 0, io.EOF
	}
	return copy(p, response), nil
}

func (c *scriptedClamConn) Write(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	command := string(p)
	if command == "nINSTREAM\n" || command == "nPING\n" || command == "nVERSION\n" {
		c.commands <- command
	}
	return len(p), nil
}

func (c *scriptedClamConn) Close() error                     { c.closed.Store(true); return nil }
func (c *scriptedClamConn) LocalAddr() net.Addr              { return clamAddr("local") }
func (c *scriptedClamConn) RemoteAddr() net.Addr             { return clamAddr("remote") }
func (c *scriptedClamConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptedClamConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedClamConn) SetWriteDeadline(time.Time) error { return nil }

type clamAddr string

func (a clamAddr) Network() string { return "test" }
func (a clamAddr) String() string  { return string(a) }

func cachedClamClient(conn net.Conn) *ClamAVClient {
	return &ClamAVClient{
		timeout: time.Second, cachedConn: conn, cachedAt: time.Now(),
	}
}

func TestClamAVClientSerializesSharedConnectionExchanges(t *testing.T) {
	conn := &scriptedClamConn{
		commands: make(chan string, 4), responses: make(chan []byte, 4),
	}
	client := cachedClamClient(conn)
	type result struct {
		virus string
		err   error
	}
	results := make(chan result, 2)
	go func() {
		virus, err := client.Scan([]byte("first"))
		results <- result{virus: virus, err: err}
	}()
	if command := <-conn.commands; command != "nINSTREAM\n" {
		t.Fatalf("first command = %q", command)
	}
	go func() {
		virus, err := client.Scan([]byte("second"))
		results <- result{virus: virus, err: err}
	}()
	select {
	case command := <-conn.commands:
		t.Fatalf("second exchange interleaved before first response: %q", command)
	case <-time.After(50 * time.Millisecond):
	}

	conn.responses <- []byte("stream: OK\n")
	select {
	case command := <-conn.commands:
		if command != "nINSTREAM\n" {
			t.Fatalf("second command = %q", command)
		}
	case <-time.After(time.Second):
		t.Fatal("second exchange did not start after first completed")
	}
	conn.responses <- []byte("stream: OK\n")
	for range 2 {
		select {
		case got := <-results:
			if got.err != nil || got.virus != "" {
				t.Fatalf("scan = (%q, %v)", got.virus, got.err)
			}
		case <-time.After(time.Second):
			t.Fatal("scan did not complete")
		}
	}
}

func TestClamAVClientSerializesPingAndVersion(t *testing.T) {
	conn := &scriptedClamConn{
		commands: make(chan string, 4), responses: make(chan []byte, 4),
	}
	client := cachedClamClient(conn)
	pingDone := make(chan error, 1)
	versionDone := make(chan error, 1)
	go func() { pingDone <- client.Ping() }()
	if command := <-conn.commands; command != "nPING\n" {
		t.Fatalf("first command = %q", command)
	}
	go func() {
		_, err := client.Version()
		versionDone <- err
	}()
	select {
	case command := <-conn.commands:
		t.Fatalf("version interleaved with ping: %q", command)
	case <-time.After(50 * time.Millisecond):
	}
	conn.responses <- []byte("PONG\n")
	if err := <-pingDone; err != nil {
		t.Fatalf("ping: %v", err)
	}
	select {
	case command := <-conn.commands:
		if command != "nVERSION\n" {
			t.Fatalf("version command = %q", command)
		}
	case <-time.After(time.Second):
		t.Fatal("version did not start after ping completed")
	}
	conn.responses <- []byte("ClamAV 1.4.3\n")
	if err := <-versionDone; err != nil {
		t.Fatalf("version: %v", err)
	}
}

func TestClamAVClientInvalidatesConnectionAfterProtocolError(t *testing.T) {
	conn := &scriptedClamConn{
		commands: make(chan string, 1), responses: make(chan []byte, 1),
	}
	client := cachedClamClient(conn)
	conn.responses <- []byte("not-a-clamd-response\n")
	_, err := client.Scan([]byte("message"))
	if err == nil {
		t.Fatal("unexpected response accepted")
	}
	if !conn.closed.Load() {
		t.Fatal("failed exchange did not close cached connection")
	}
	client.mu.Lock()
	cached := client.cachedConn
	client.mu.Unlock()
	if cached != nil {
		t.Fatal("failed exchange remained cached")
	}
}

func TestClamAVClientInvalidatesConnectionAfterReadError(t *testing.T) {
	conn := &scriptedClamConn{
		commands: make(chan string, 1), responses: make(chan []byte),
	}
	close(conn.responses)
	client := cachedClamClient(conn)
	_, err := client.Scan([]byte("message"))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("read error = %v, want EOF", err)
	}
	if !conn.closed.Load() {
		t.Fatal("read failure did not close cached connection")
	}
}
