package updater

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"net/textproto"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/emersion/go-imap"
	imapclient "github.com/emersion/go-imap/client"
	"github.com/emersion/go-imap/commands"
	"github.com/emersion/go-imap/responses"
	"github.com/google/uuid"
)

const (
	applicationLoginURL     = "https://127.0.0.1/auth/login"
	applicationSMTPAddr     = "127.0.0.1:587"
	applicationIMAPAddr     = "127.0.0.1:993"
	applicationTLSName      = "localhost"
	applicationDeliveryPoll = 5 * time.Second
)

var probeEmailPattern = regexp.MustCompile(`^[A-Za-z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[A-Za-z0-9.-]+$`)

type ProbeCredential struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// ReadProbeCredential reads one systemd credential containing the dedicated
// synthetic monitor account. The account is used only against fixed loopback
// login, SMTP submission, and IMAP endpoints; no value can select a command,
// path, URL, recipient, or unit.
func ReadProbeCredential(path string) (ProbeCredential, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return ProbeCredential{}, fmt.Errorf("stat application probe credential: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > 16<<10 {
		return ProbeCredential{}, errors.New("application probe credential must be a non-empty private regular file")
	}
	// The systemd credential path is fixed by the root-owned unit and was just
	// checked as a bounded non-symlink private file.
	//nolint:gosec // G304: not request-controlled; fixed LoadCredential path.
	raw, err := os.ReadFile(path)
	if err != nil {
		return ProbeCredential{}, fmt.Errorf("read application probe credential: %w", err)
	}
	var credential ProbeCredential
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&credential); err != nil {
		return ProbeCredential{}, errors.New("invalid application probe credential JSON")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ProbeCredential{}, errors.New("invalid trailing application probe credential JSON")
	}
	if err := credential.validate(); err != nil {
		return ProbeCredential{}, err
	}
	return credential, nil
}

func (credential ProbeCredential) validate() error {
	if len(credential.Email) < 3 || len(credential.Email) > 254 || !probeEmailPattern.MatchString(credential.Email) ||
		strings.Contains(credential.Email, "..") || len(credential.Password) < 12 || len(credential.Password) > 1024 ||
		strings.ContainsAny(credential.Password, "\r\n\x00") {
		return errors.New("application probe credential is invalid")
	}
	return nil
}

type applicationProbeEndpoints struct {
	loginURL string
	smtpAddr string
	imapAddr string
	tlsName  string
}

type ApplicationProbe struct {
	credential   ProbeCredential
	endpoints    applicationProbeEndpoints
	timeout      time.Duration
	deliveryWait time.Duration
	now          func() time.Time
	newID        func() string
	sleep        func(context.Context, time.Duration) error
}

type eSearchPresence struct {
	seen  bool
	found bool
}

func (result *eSearchPresence) Handle(response imap.Resp) error {
	name, fields, ok := imap.ParseNamedResp(response)
	if !ok || name != "ESEARCH" {
		return responses.ErrUnhandled
	}
	result.seen = true
	for index, field := range fields {
		atom, ok := field.(string)
		if ok && strings.EqualFold(atom, "ALL") && index+1 < len(fields) {
			result.found = true
		}
	}
	return nil
}

func NewApplicationProbe(credential ProbeCredential) (*ApplicationProbe, error) {
	return newApplicationProbe(credential, applicationProbeEndpoints{
		loginURL: applicationLoginURL, smtpAddr: applicationSMTPAddr,
		imapAddr: applicationIMAPAddr, tlsName: applicationTLSName,
	})
}

func newApplicationProbe(credential ProbeCredential, endpoints applicationProbeEndpoints) (*ApplicationProbe, error) {
	if err := credential.validate(); err != nil {
		return nil, err
	}
	if endpoints.loginURL == "" || endpoints.smtpAddr == "" || endpoints.imapAddr == "" || endpoints.tlsName == "" {
		return nil, errors.New("application probe endpoints are incomplete")
	}
	return &ApplicationProbe{
		credential: credential, endpoints: endpoints, timeout: 10 * time.Second,
		deliveryWait: 30 * time.Second, now: time.Now, newID: uuid.NewString,
		sleep: func(ctx context.Context, delay time.Duration) error {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		},
	}, nil
}

func (probe *ApplicationProbe) DataContract(ctx context.Context) error {
	if probe == nil {
		return errors.New("application probe is unavailable")
	}
	if err := probe.login(ctx); err != nil {
		return fmt.Errorf("fixed login contract: %w", err)
	}
	if _, err := probe.searchInbox(ctx, "setjoin-updater-connectivity-check-never-matches"); err != nil {
		return fmt.Errorf("fixed IMAP fetch contract: %w", err)
	}
	return nil
}

func (probe *ApplicationProbe) PostCommit(ctx context.Context) error {
	if probe == nil {
		return errors.New("application probe is unavailable")
	}
	messageID := fmt.Sprintf("<setjoin-updater-%s@localhost>", probe.newID())
	if err := probe.sendSelf(ctx, messageID); err != nil {
		return fmt.Errorf("fixed SMTP send contract: %w", err)
	}
	deadline := probe.now().Add(probe.deliveryWait)
	for {
		found, err := probe.searchInbox(ctx, messageID)
		if err != nil {
			return fmt.Errorf("fixed IMAP delivery contract: %w", err)
		}
		if found {
			return nil
		}
		if !probe.now().Before(deadline) {
			return errors.New("fixed mail send/fetch contract timed out")
		}
		// Each search opens one fixed loopback IMAP session. Poll slowly enough
		// that the complete success + deliberate-failure rehearsal remains below
		// the normal per-IP/per-protocol authentication rate limit.
		if err := probe.sleep(ctx, applicationDeliveryPoll); err != nil {
			return err
		}
	}
}

func (probe *ApplicationProbe) login(ctx context.Context) error {
	body, err := json.Marshal(map[string]string{"email": probe.credential.Email, "password": probe.credential.Password})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, probe.endpoints.loginURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{
		Timeout:       probe.timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{TLSClientConfig: loopbackTLSConfig(probe.endpoints.tlsName)},
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (64<<10)+1))
	if err != nil {
		return err
	}
	if len(raw) > 64<<10 {
		return errors.New("login response exceeds fixed probe limit")
	}
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	var pending struct {
		Status      string `json:"status"`
		MFARequired bool   `json:"mfa_required"`
		MFAToken    string `json:"mfa_token"`
		Reason      string `json:"reason"`
	}
	if err := json.Unmarshal(raw, &pending); err != nil {
		return fmt.Errorf("login returned HTTP %d with invalid JSON", resp.StatusCode)
	}
	switch resp.StatusCode {
	case http.StatusAccepted:
		if pending.Status == "mfa_required" && pending.MFARequired && pending.MFAToken != "" {
			return nil
		}
	case http.StatusForbidden:
		if pending.Status == "mfa_enrollment_required" && pending.MFARequired &&
			pending.MFAToken != "" && pending.Reason == "enrollment_required" {
			return nil
		}
	}
	return fmt.Errorf("login returned HTTP %d", resp.StatusCode)
}

func (probe *ApplicationProbe) sendSelf(ctx context.Context, messageID string) error {
	dialer := &net.Dialer{Timeout: probe.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", probe.endpoints.smtpAddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(probe.timeout)); err != nil {
		return err
	}
	client, err := smtp.NewClient(conn, probe.endpoints.tlsName)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	if err := client.StartTLS(loopbackTLSConfig(probe.endpoints.tlsName)); err != nil {
		return err
	}
	auth := smtp.PlainAuth("", probe.credential.Email, probe.credential.Password, probe.endpoints.tlsName)
	if err := client.Auth(auth); err != nil {
		return err
	}
	if err := client.Mail(probe.credential.Email); err != nil {
		return err
	}
	if err := client.Rcpt(probe.credential.Email); err != nil {
		return err
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	message := "From: " + probe.credential.Email + "\r\nTo: " + probe.credential.Email +
		"\r\nMessage-ID: " + messageID + "\r\nSubject: Setjoin transactional updater probe" +
		"\r\nAuto-Submitted: auto-generated\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
		"Synthetic post-upgrade delivery contract.\r\n"
	if _, err := io.WriteString(writer, message); err != nil {
		_ = writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func (probe *ApplicationProbe) searchInbox(ctx context.Context, messageID string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	dialer := &net.Dialer{Timeout: probe.timeout}
	client, err := imapclient.DialWithDialerTLS(dialer, probe.endpoints.imapAddr, loopbackTLSConfig(probe.endpoints.tlsName))
	if err != nil {
		return false, err
	}
	client.Timeout = probe.timeout
	defer func() { _ = client.Logout() }()
	if err := client.Login(probe.credential.Email, probe.credential.Password); err != nil {
		return false, err
	}
	if _, err := client.Select("INBOX", true); err != nil {
		return false, err
	}
	criteria := imap.NewSearchCriteria()
	criteria.Header = make(textproto.MIMEHeader)
	criteria.Header.Set("Message-ID", messageID)
	result := &eSearchPresence{}
	status, err := client.Execute(&commands.Search{Charset: "UTF-8", Criteria: criteria}, result)
	if err != nil {
		return false, err
	}
	if status == nil {
		return false, errors.New("IMAP search omitted its completion status")
	}
	if err := status.Err(); err != nil {
		return false, err
	}
	if !result.seen {
		return false, errors.New("IMAP search omitted its ESEARCH result")
	}
	return result.found, nil
}

func loopbackTLSConfig(serverName string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12, ServerName: serverName,
		// These endpoints are fixed loopback listeners. Their production
		// certificates name the public host, so normal hostname validation cannot
		// succeed on 127.0.0.1. No remote address is caller-selectable.
		InsecureSkipVerify: true, //nolint:gosec // fixed loopback-only contract.
	}
}
