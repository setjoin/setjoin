package updater

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap"
)

func writeProbeCredential(t *testing.T, raw string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "probe.json")
	if err := os.WriteFile(path, []byte(raw), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadProbeCredentialStrictPrivateJSON(t *testing.T) {
	path := writeProbeCredential(t, `{"email":"probe@example.test","password":"Probe-Password-123!"}`, 0o600)
	credential, err := ReadProbeCredential(path)
	if err != nil || credential.Email != "probe@example.test" || credential.Password == "" {
		t.Fatalf("credential=%#v err=%v", credential, err)
	}
	for name, raw := range map[string]string{
		"unknown":  `{"email":"probe@example.test","password":"Probe-Password-123!","path":"/tmp"}`,
		"trailing": `{"email":"probe@example.test","password":"Probe-Password-123!"}{}`,
		"email":    `{"email":"bad","password":"Probe-Password-123!"}`,
		"password": `{"email":"probe@example.test","password":"short"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadProbeCredential(writeProbeCredential(t, raw, 0o600)); err == nil {
				t.Fatal("invalid probe credential accepted")
			}
		})
	}
	if _, err := ReadProbeCredential(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing probe credential accepted")
	}
	insecure := writeProbeCredential(t, `{"email":"probe@example.test","password":"Probe-Password-123!"}`, 0o644)
	if _, err := ReadProbeCredential(insecure); err == nil {
		t.Fatal("group/world-readable probe credential accepted")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProbeCredential(link); err == nil {
		t.Fatal("symlink probe credential accepted")
	}
}

func startProbeSMTP(t *testing.T, certificate tls.Certificate) (string, func() string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	var body string
	var mutex sync.Mutex
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		writer := bufio.NewWriter(conn)
		write := func(value string) { _, _ = writer.WriteString(value); _ = writer.Flush() }
		read := func() string { value, _ := reader.ReadString('\n'); return strings.TrimSpace(value) }
		write("220 probe ESMTP\r\n")
		if !strings.HasPrefix(read(), "EHLO ") {
			return
		}
		write("250-probe\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n")
		if read() != "STARTTLS" {
			return
		}
		write("220 ready\r\n")
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		reader = bufio.NewReader(tlsConn)
		writer = bufio.NewWriter(tlsConn)
		if !strings.HasPrefix(read(), "EHLO ") {
			return
		}
		write("250-probe\r\n250 AUTH PLAIN\r\n")
		if !strings.HasPrefix(read(), "AUTH PLAIN ") {
			return
		}
		write("235 authenticated\r\n")
		if !strings.HasPrefix(read(), "MAIL FROM:") {
			return
		}
		write("250 sender ok\r\n")
		if !strings.HasPrefix(read(), "RCPT TO:") {
			return
		}
		write("250 recipient ok\r\n")
		if read() != "DATA" {
			return
		}
		write("354 continue\r\n")
		var lines []string
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				return
			}
			if line == ".\r\n" {
				break
			}
			lines = append(lines, line)
		}
		mutex.Lock()
		body = strings.Join(lines, "")
		mutex.Unlock()
		write("250 queued\r\n")
		if read() == "QUIT" {
			write("221 bye\r\n")
		}
	}()
	return listener.Addr().String(), func() string {
		mutex.Lock()
		defer mutex.Unlock()
		return body
	}
}

func startRejectingProbeSMTP(t *testing.T, certificate tls.Certificate, rejectAt string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		writer := bufio.NewWriter(conn)
		write := func(value string) { _, _ = writer.WriteString(value); _ = writer.Flush() }
		read := func() string { value, _ := reader.ReadString('\n'); return strings.TrimSpace(value) }
		if rejectAt == "greeting" {
			write("invalid greeting\r\n")
			return
		}
		write("220 probe ESMTP\r\n")
		_ = read()
		write("250-probe\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n")
		_ = read()
		if rejectAt == "starttls" {
			write("454 TLS unavailable\r\n")
			return
		}
		write("220 ready\r\n")
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
		if handshakeErr := tlsConn.Handshake(); handshakeErr != nil {
			return
		}
		reader = bufio.NewReader(tlsConn)
		writer = bufio.NewWriter(tlsConn)
		_ = read()
		write("250-probe\r\n250 AUTH PLAIN\r\n")
		_ = read()
		if rejectAt == "auth" {
			write("535 rejected\r\n")
			return
		}
		write("235 authenticated\r\n")
		_ = read()
		if rejectAt == "mail" {
			write("550 rejected\r\n")
			return
		}
		write("250 sender ok\r\n")
		_ = read()
		if rejectAt == "rcpt" {
			write("550 rejected\r\n")
			return
		}
		write("250 recipient ok\r\n")
		_ = read()
		write("554 data rejected\r\n")
	}()
	return listener.Addr().String()
}

func startProbeIMAP(t *testing.T, certificate tls.Certificate) string {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				writer := bufio.NewWriter(conn)
				_, _ = writer.WriteString("* OK probe IMAP4rev1\r\n")
				_ = writer.Flush()
				for {
					line, readErr := reader.ReadString('\n')
					if readErr != nil {
						return
					}
					fields := strings.Fields(line)
					if len(fields) < 2 {
						return
					}
					tag, command := fields[0], strings.ToUpper(fields[1])
					switch command {
					case "CAPABILITY":
						_, _ = fmt.Fprintf(writer, "* CAPABILITY IMAP4rev1\r\n%s OK capability\r\n", tag)
					case "LOGIN":
						_, _ = fmt.Fprintf(writer, "%s OK login\r\n", tag)
					case "SELECT", "EXAMINE":
						_, _ = fmt.Fprintf(writer, "* 1 EXISTS\r\n* OK [UIDVALIDITY 1]\r\n%s OK selected\r\n", tag)
					case "SEARCH":
						if strings.Contains(line, "never-matches") {
							_, _ = fmt.Fprintf(writer, "* ESEARCH (TAG %q)\r\n", tag)
						} else {
							_, _ = fmt.Fprintf(writer, "* ESEARCH (TAG %q) ALL 1\r\n", tag)
						}
						_, _ = fmt.Fprintf(writer, "%s OK search\r\n", tag)
					case "LOGOUT":
						_, _ = fmt.Fprintf(writer, "* BYE logout\r\n%s OK logout\r\n", tag)
						_ = writer.Flush()
						return
					default:
						_, _ = fmt.Fprintf(writer, "%s BAD unsupported\r\n", tag)
					}
					_ = writer.Flush()
				}
			}(conn)
		}
	}()
	return listener.Addr().String()
}

func startProbeIMAPWithResponses(t *testing.T, certificate tls.Certificate, responses map[string][]string) string {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				writer := bufio.NewWriter(conn)
				_, _ = writer.WriteString("* OK probe IMAP4rev1\r\n")
				_ = writer.Flush()
				for {
					line, readErr := reader.ReadString('\n')
					if readErr != nil {
						return
					}
					fields := strings.Fields(line)
					if len(fields) < 2 {
						return
					}
					tag, command := fields[0], strings.ToUpper(fields[1])
					configured, ok := responses[command]
					if !ok {
						configured = []string{"%s OK completed\r\n"}
					}
					for _, response := range configured {
						if strings.Contains(response, "%s") {
							_, _ = fmt.Fprintf(writer, response, tag)
						} else {
							_, _ = writer.WriteString(response)
						}
					}
					_ = writer.Flush()
					if command == "LOGOUT" {
						return
					}
				}
			}(conn)
		}
	}()
	return listener.Addr().String()
}

func TestApplicationProbeRunsFixedLoginSendAndFetchContracts(t *testing.T) {
	login := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/auth/login" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected login request %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"mfa_required","mfa_required":true,"mfa_token":"sensitive-not-logged"}`))
	}))
	defer login.Close()
	certificate := login.TLS.Certificates[0]
	smtpAddr, smtpBody := startProbeSMTP(t, certificate)
	imapAddr := startProbeIMAP(t, certificate)
	probe, err := newApplicationProbe(ProbeCredential{
		Email: "probe@example.test", Password: "Probe-Password-123!",
	}, applicationProbeEndpoints{
		loginURL: login.URL + "/auth/login", smtpAddr: smtpAddr,
		imapAddr: imapAddr, tlsName: "localhost",
	})
	if err != nil {
		t.Fatal(err)
	}
	probe.timeout = 2 * time.Second
	probe.deliveryWait = time.Second
	probe.sleep = func(context.Context, time.Duration) error { return nil }
	if err := probe.DataContract(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := probe.PostCommit(context.Background()); err != nil {
		t.Fatal(err)
	}
	body := smtpBody()
	if !strings.Contains(body, "Message-ID: <setjoin-updater-") || !strings.Contains(body, "Auto-Submitted: auto-generated") {
		t.Fatalf("SMTP probe message=%q", body)
	}
}

func TestApplicationProbeDeliveryPollingStaysBelowAuthRateLimit(t *testing.T) {
	if applicationDeliveryPoll < 5*time.Second {
		t.Fatalf("delivery poll %s can exhaust the normal per-minute IMAP auth budget", applicationDeliveryPoll)
	}
	if attempts := int((30*time.Second)/applicationDeliveryPoll) + 1; attempts > 7 {
		t.Fatalf("delivery probe can open %d IMAP sessions in 30s", attempts)
	}
}

func TestApplicationProbeAcceptsOnlyExactEnrollmentPendingResponse(t *testing.T) {
	for name, response := range map[string]struct {
		status int
		body   string
		want   bool
	}{
		"exact":   {http.StatusForbidden, `{"status":"mfa_enrollment_required","mfa_required":true,"mfa_token":"pending","reason":"enrollment_required"}`, true},
		"missing": {http.StatusForbidden, `{"status":"mfa_enrollment_required","mfa_required":true,"reason":"enrollment_required"}`, false},
		"denied":  {http.StatusForbidden, `{"status":"denied"}`, false},
		"bad-202": {http.StatusAccepted, `{"status":"mfa_required","mfa_required":false,"mfa_token":"pending"}`, false},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(response.status)
				_, _ = w.Write([]byte(response.body))
			}))
			defer server.Close()
			probe, err := newApplicationProbe(ProbeCredential{Email: "probe@example.test", Password: "Probe-Password-123!"}, applicationProbeEndpoints{
				loginURL: server.URL, smtpAddr: "127.0.0.1:1", imapAddr: "127.0.0.1:1", tlsName: "localhost",
			})
			if err != nil {
				t.Fatal(err)
			}
			err = probe.login(context.Background())
			if (err == nil) != response.want {
				t.Fatalf("login err=%v wantAccepted=%t", err, response.want)
			}
		})
	}
}

func TestApplicationProbeFailsClosedAndHonorsCancellation(t *testing.T) {
	if _, err := NewApplicationProbe(ProbeCredential{}); err == nil {
		t.Fatal("empty application credential accepted")
	}
	var nilProbe *ApplicationProbe
	if err := nilProbe.DataContract(context.Background()); err == nil {
		t.Fatal("nil data-contract probe accepted")
	}
	if err := nilProbe.PostCommit(context.Background()); err == nil {
		t.Fatal("nil post-commit probe accepted")
	}
	probe, err := newApplicationProbe(ProbeCredential{
		Email: "probe@example.test", Password: "Probe-Password-123!",
	}, applicationProbeEndpoints{loginURL: "https://127.0.0.1:1/auth/login", smtpAddr: "127.0.0.1:1", imapAddr: "127.0.0.1:1", tlsName: "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	probe.timeout = 10 * time.Millisecond
	if err := probe.DataContract(context.Background()); err == nil || !strings.Contains(err.Error(), "login") {
		t.Fatalf("unreachable login err=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := probe.searchInbox(ctx, "message"); err == nil {
		t.Fatal("cancelled IMAP search accepted")
	}
	if err := probe.sendSelf(ctx, "<message@localhost>"); err == nil {
		t.Fatal("cancelled SMTP send accepted")
	}
}

func TestApplicationProbeFailureStagesAndDefaultSleep(t *testing.T) {
	credential := ProbeCredential{Email: "probe@example.test", Password: "Probe-Password-123!"}
	if _, err := newApplicationProbe(credential, applicationProbeEndpoints{loginURL: "https://127.0.0.1"}); err == nil {
		t.Fatal("incomplete fixed endpoints accepted")
	}
	probe, err := NewApplicationProbe(credential)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := probe.sleep(ctx, time.Hour); err == nil {
		t.Fatal("default sleep ignored cancellation")
	}
	if err := probe.sleep(context.Background(), time.Nanosecond); err != nil {
		t.Fatalf("default sleep timer: %v", err)
	}
	presence := &eSearchPresence{}
	if err := presence.Handle(imap.NewUntaggedResp([]interface{}{"SEARCH", uint32(1)})); err == nil {
		t.Fatal("non-ESEARCH response handled")
	}

	login := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer login.Close()
	certificate := login.TLS.Certificates[0]
	baseEndpoints := applicationProbeEndpoints{loginURL: login.URL, smtpAddr: "127.0.0.1:1", imapAddr: "127.0.0.1:1", tlsName: "localhost"}
	probe, err = newApplicationProbe(credential, baseEndpoints)
	if err != nil {
		t.Fatal(err)
	}
	probe.timeout = 100 * time.Millisecond
	if err := probe.DataContract(context.Background()); err == nil || !strings.Contains(err.Error(), "IMAP") {
		t.Fatalf("unreachable IMAP data contract err=%v", err)
	}
	if err := probe.PostCommit(context.Background()); err == nil || !strings.Contains(err.Error(), "SMTP") {
		t.Fatalf("unreachable SMTP post-commit err=%v", err)
	}

	for name, responses := range map[string]map[string][]string{
		"login": {
			"CAPABILITY": {"* CAPABILITY IMAP4rev1\r\n", "%s OK capability\r\n"},
			"LOGIN":      {"%s NO rejected\r\n"},
		},
		"select": {
			"CAPABILITY": {"* CAPABILITY IMAP4rev1\r\n", "%s OK capability\r\n"},
			"LOGIN":      {"%s OK login\r\n"},
			"SELECT":     {"%s NO rejected\r\n"},
			"EXAMINE":    {"%s NO rejected\r\n"},
		},
		"search status": {
			"CAPABILITY": {"* CAPABILITY IMAP4rev1\r\n", "%s OK capability\r\n"},
			"LOGIN":      {"%s OK login\r\n"},
			"SELECT":     {"* 0 EXISTS\r\n", "%s OK selected\r\n"},
			"EXAMINE":    {"* 0 EXISTS\r\n", "%s OK selected\r\n"},
			"SEARCH":     {"* ESEARCH (TAG \"probe\")\r\n", "%s NO rejected\r\n"},
		},
		"missing esearch": {
			"CAPABILITY": {"* CAPABILITY IMAP4rev1\r\n", "%s OK capability\r\n"},
			"LOGIN":      {"%s OK login\r\n"},
			"SELECT":     {"* 0 EXISTS\r\n", "%s OK selected\r\n"},
			"EXAMINE":    {"* 0 EXISTS\r\n", "%s OK selected\r\n"},
			"SEARCH":     {"%s OK search\r\n"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			endpoints := baseEndpoints
			endpoints.imapAddr = startProbeIMAPWithResponses(t, certificate, responses)
			candidate, buildErr := newApplicationProbe(credential, endpoints)
			if buildErr != nil {
				t.Fatal(buildErr)
			}
			candidate.timeout = time.Second
			if _, searchErr := candidate.searchInbox(context.Background(), "<message@localhost>"); searchErr == nil {
				t.Fatal("invalid IMAP stage accepted")
			}
		})
	}
}

func TestApplicationProbeLoginAndDeliveryLimits(t *testing.T) {
	credential := ProbeCredential{Email: "probe@example.test", Password: "Probe-Password-123!"}
	for name, response := range map[string]struct {
		status int
		body   string
	}{
		"oversize": {http.StatusUnauthorized, strings.Repeat("x", (64<<10)+1)},
		"bad json": {http.StatusUnauthorized, "not-json"},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(response.status)
				_, _ = w.Write([]byte(response.body))
			}))
			defer server.Close()
			probe, err := newApplicationProbe(credential, applicationProbeEndpoints{loginURL: server.URL, smtpAddr: "127.0.0.1:1", imapAddr: "127.0.0.1:1", tlsName: "localhost"})
			if err != nil {
				t.Fatal(err)
			}
			if err := probe.login(context.Background()); err == nil {
				t.Fatal("invalid login response accepted")
			}
		})
	}
	invalidURL, err := newApplicationProbe(credential, applicationProbeEndpoints{loginURL: "://bad", smtpAddr: "127.0.0.1:1", imapAddr: "127.0.0.1:1", tlsName: "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	if err := invalidURL.login(context.Background()); err == nil {
		t.Fatal("invalid login URL accepted")
	}

	login := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer login.Close()
	certificate := login.TLS.Certificates[0]
	smtpAddr, _ := startProbeSMTP(t, certificate)
	missingResponses := map[string][]string{
		"CAPABILITY": {"* CAPABILITY IMAP4rev1\r\n", "%s OK capability\r\n"},
		"LOGIN":      {"%s OK login\r\n"},
		"SELECT":     {"* 0 EXISTS\r\n", "%s OK selected\r\n"},
		"EXAMINE":    {"* 0 EXISTS\r\n", "%s OK selected\r\n"},
		"SEARCH":     {"* ESEARCH (TAG \"probe\")\r\n", "%s OK search\r\n"},
	}
	probe, err := newApplicationProbe(credential, applicationProbeEndpoints{loginURL: login.URL, smtpAddr: smtpAddr, imapAddr: startProbeIMAPWithResponses(t, certificate, missingResponses), tlsName: "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	probe.timeout = time.Second
	probe.deliveryWait = 0
	if err := probe.PostCommit(context.Background()); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("missing delivery err=%v", err)
	}
}

func TestApplicationProbePostCommitPropagatesSearchAndSleepFailures(t *testing.T) {
	credential := ProbeCredential{Email: "probe@example.test", Password: "Probe-Password-123!"}
	login := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer login.Close()
	certificate := login.TLS.Certificates[0]
	for _, mode := range []string{"search", "sleep"} {
		t.Run(mode, func(t *testing.T) {
			smtpAddr, _ := startProbeSMTP(t, certificate)
			imapAddr := "127.0.0.1:1"
			if mode == "sleep" {
				imapAddr = startProbeIMAPWithResponses(t, certificate, map[string][]string{
					"CAPABILITY": {"* CAPABILITY IMAP4rev1\r\n", "%s OK capability\r\n"},
					"LOGIN":      {"%s OK login\r\n"},
					"SELECT":     {"* 0 EXISTS\r\n", "%s OK selected\r\n"},
					"EXAMINE":    {"* 0 EXISTS\r\n", "%s OK selected\r\n"},
					"SEARCH":     {"* ESEARCH (TAG \"probe\")\r\n", "%s OK search\r\n"},
				})
			}
			probe, err := newApplicationProbe(credential, applicationProbeEndpoints{loginURL: login.URL, smtpAddr: smtpAddr, imapAddr: imapAddr, tlsName: "localhost"})
			if err != nil {
				t.Fatal(err)
			}
			probe.timeout = time.Second
			if mode == "sleep" {
				probe.deliveryWait = time.Hour
				probe.sleep = func(context.Context, time.Duration) error { return errors.New("sleep interrupted") }
			}
			if err := probe.PostCommit(context.Background()); err == nil {
				t.Fatalf("%s failure was ignored", mode)
			}
		})
	}
}

func TestApplicationProbeSMTPRejectsEveryProtocolStage(t *testing.T) {
	login := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer login.Close()
	credential := ProbeCredential{Email: "probe@example.test", Password: "Probe-Password-123!"}
	for _, stage := range []string{"greeting", "starttls", "auth", "mail", "rcpt", "data"} {
		t.Run(stage, func(t *testing.T) {
			probe, err := newApplicationProbe(credential, applicationProbeEndpoints{
				loginURL: login.URL, smtpAddr: startRejectingProbeSMTP(t, login.TLS.Certificates[0], stage),
				imapAddr: "127.0.0.1:1", tlsName: "localhost",
			})
			if err != nil {
				t.Fatal(err)
			}
			probe.timeout = time.Second
			if err := probe.sendSelf(context.Background(), "<message@localhost>"); err == nil {
				t.Fatalf("SMTP %s rejection accepted", stage)
			}
		})
	}
}
