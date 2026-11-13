package smtp

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// ClamAVClient connects to clamd for virus scanning.
type ClamAVClient struct {
	addr       string
	timeout    time.Duration
	mu         sync.Mutex
	exchangeMu sync.Mutex
	cachedConn net.Conn
	cachedAt   time.Time
}

// NewClamAVClient creates a clamd client.
// addr can be a TCP address like "127.0.0.1:3310" or a Unix socket path.
func NewClamAVClient(addr string) *ClamAVClient {
	return &ClamAVClient{addr: addr, timeout: 30 * time.Second}
}

func (c *ClamAVClient) network() string {
	if strings.HasPrefix(c.addr, "/") || strings.HasPrefix(c.addr, ".") {
		return "unix"
	}
	return "tcp"
}

func (c *ClamAVClient) dial() (net.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cachedConn != nil {
		if time.Since(c.cachedAt) < 30*time.Second {
			return c.cachedConn, nil
		}
		_ = c.cachedConn.Close()
		c.cachedConn = nil
		c.cachedAt = time.Time{}
	}
	conn, err := net.DialTimeout(c.network(), c.addr, c.timeout)
	if err != nil {
		return nil, err
	}
	c.cachedConn = conn
	c.cachedAt = time.Now()
	return conn, nil
}

func (c *ClamAVClient) invalidate(conn net.Conn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cachedConn == conn {
		_ = c.cachedConn.Close()
		c.cachedConn = nil
		c.cachedAt = time.Time{}
	}
}

// Scan scans data and returns the virus name if found, or empty string if clean.
func (c *ClamAVClient) Scan(data []byte) (virus string, err error) {
	c.exchangeMu.Lock()
	defer c.exchangeMu.Unlock()
	conn, err := c.dial()
	if err != nil {
		return "", fmt.Errorf("clamd connect: %w", err)
	}
	defer func() {
		if err != nil {
			c.invalidate(conn)
		}
	}()

	if err := conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return "", err
	}

	// Prefix commands with "n" so modern clamd treats the newline as an
	// explicit frame delimiter. Bare legacy commands are rejected by ClamAV
	// 1.5 with UNKNOWN COMMAND.
	if _, err := conn.Write([]byte("nINSTREAM\n")); err != nil {
		return "", err
	}

	// Send data in chunks
	chunkSize := 4096
	for offset := 0; offset < len(data); offset += chunkSize {
		end := offset + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[offset:end]
		//nolint:gosec // G115: len(chunk) is bounded by chunkSize (4096) and non-negative
		if err := binary.Write(conn, binary.BigEndian, uint32(len(chunk))); err != nil {
			return "", err
		}
		if _, err := conn.Write(chunk); err != nil {
			return "", err
		}
	}

	// Send zero-length chunk to terminate
	if err := binary.Write(conn, binary.BigEndian, uint32(0)); err != nil {
		return "", err
	}

	// Read response
	reader := bufio.NewReader(conn)
	resp, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	resp = strings.TrimSpace(resp)

	if strings.HasSuffix(resp, "OK") {
		return "", nil
	}
	if strings.Contains(resp, "FOUND") {
		parts := strings.Split(resp, " ")
		if len(parts) >= 3 {
			return parts[len(parts)-2], nil
		}
	}
	if strings.Contains(resp, "ERROR") {
		return "", fmt.Errorf("clamd error: %s", resp)
	}
	return "", fmt.Errorf("clamd unexpected response: %s", resp)
}

// Ping checks if clamd is reachable.
func (c *ClamAVClient) Ping() (err error) {
	c.exchangeMu.Lock()
	defer c.exchangeMu.Unlock()
	conn, err := c.dial()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			c.invalidate(conn)
		}
	}()

	if err := conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return err
	}

	if _, err := conn.Write([]byte("nPING\n")); err != nil {
		return err
	}

	reader := bufio.NewReader(conn)
	resp, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.Contains(resp, "PONG") {
		return fmt.Errorf("clamd ping failed: %s", resp)
	}
	return nil
}

// Version returns the ClamAV engine version and signature age.
func (c *ClamAVClient) Version() (version string, err error) {
	c.exchangeMu.Lock()
	defer c.exchangeMu.Unlock()
	conn, err := c.dial()
	if err != nil {
		return "", err
	}
	defer func() {
		if err != nil {
			c.invalidate(conn)
		}
	}()

	if err := conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return "", err
	}

	if _, err := conn.Write([]byte("nVERSION\n")); err != nil {
		return "", err
	}

	reader := bufio.NewReader(conn)
	resp, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(resp), nil
}
