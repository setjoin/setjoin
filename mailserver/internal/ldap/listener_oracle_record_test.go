//go:build gofree_record

package ldap

// Recording adapter only: all responses come from the unmodified production
// listener over TCP/TLS. Rust replays the immutable bytes without Go present.
import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"setjoin.com/shared/pwhash"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/threat"
	"setjoin.com/shared/toggle"
	"testing"
	"time"
)

type oracleStep struct {
	Request   string   `json:"request"`
	Responses []string `json:"responses"`
}
type oracleEffects struct {
	PasswordRehashed bool `json:"password_rehashed"`
	AuthEvents       int  `json:"auth_events"`
}
type oracleSession struct {
	Threat       string         `json:"threat,omitempty"`
	Name         string         `json:"name"`
	Transport    string         `json:"transport"`
	Steps        []oracleStep   `json:"steps"`
	PasswordHash string         `json:"password_hash,omitempty"`
	Effects      *oracleEffects `json:"effects,omitempty"`
}

func oracleFrame(c net.Conn) ([]byte, error) {
	h := make([]byte, 2)
	if _, e := io.ReadFull(c, h); e != nil {
		return nil, e
	}
	n := int(h[1])
	if n > 127 {
		k := n & 127
		b := make([]byte, k)
		if _, e := io.ReadFull(c, b); e != nil {
			return nil, e
		}
		h = append(h, b...)
		n = 0
		for _, x := range b {
			n = n*256 + int(x)
		}
	}
	b := make([]byte, n)
	_, e := io.ReadFull(c, b)
	return append(h, b...), e
}
func TestRecordLDAPListener(t *testing.T) {
	variant := os.Getenv("LDAP_ORACLE_VARIANT")
	root := os.Getenv("LDAP_ORACLE_DIR")
	if root == "" {
		t.Fatal("LDAP_ORACLE_DIR required")
	}
	if _, e := os.Stat(filepath.Join(root, variant+"go-sessions.json")); e == nil {
		t.Fatal("golden exists: add a new corpus instead of overwriting it")
	}
	pool := testsupport.OpenTestPool(t)
	if variant != "" {
		cleanup, e := os.ReadFile(filepath.Join(root, "cleanup.sql"))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = pool.Exec(context.Background(), string(cleanup)); e != nil {
			t.Fatal(e)
		}
	}
	seed, e := os.ReadFile(filepath.Join(root, "seed.sql"))
	if e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	if _, e = pool.Exec(ctx, string(seed)); e != nil {
		t.Fatal(e)
	}
	if variant != "" {
		extra, e := os.ReadFile(filepath.Join(root, "seed-extra.sql"))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = pool.Exec(ctx, string(extra)); e != nil {
			t.Fatal(e)
		}
	}
	hash, e := pwhash.HashPassword("LDAP1-correct-password!")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = pool.Exec(ctx, `UPDATE users SET password_hash=$1 WHERE email LIKE '%@ldap1.test'`, hash); e != nil {
		t.Fatal(e)
	}
	if variant != "" {
		raw, e := os.ReadFile(filepath.Join(root, "password-hash.txt"))
		if e != nil {
			t.Fatal(e)
		}
		hash = string(raw)
		if _, e = pool.Exec(ctx, `UPDATE users SET password_hash=$1 WHERE email LIKE '%@ldap1.test'`, hash); e != nil {
			t.Fatal(e)
		}
	} else {
		if e = os.WriteFile(filepath.Join(root, "password-hash.txt"), []byte(hash), 0600); e != nil {
			t.Fatal(e)
		}
	}
	raw, e := os.ReadFile(filepath.Join(root, variant+"requests.json"))
	if e != nil {
		t.Fatal(e)
	}
	var sessions []oracleSession
	if e = json.Unmarshal(raw, &sessions); e != nil {
		t.Fatal(e)
	}
	cert, key := genSelfSignedCert(t)
	for i := range sessions {
		session := &sessions[i]
		srvCtx, cancel := context.WithCancel(ctx)
		beforeHash := hash
		if variant == "edges-" {
			if session.PasswordHash == "generate-sm3" {
				session.PasswordHash, e = pwhash.HashPasswordSM3("LDAP1-correct-password!")
				if e != nil {
					t.Fatal(e)
				}
			}
			if session.PasswordHash != "" {
				beforeHash = session.PasswordHash
			}
			if _, e = pool.Exec(ctx, `UPDATE users SET password_hash=$1 WHERE id=9342011`, beforeHash); e != nil {
				t.Fatal(e)
			}
			if _, e = pool.Exec(ctx, `DELETE FROM auth_event_log WHERE user_id BETWEEN 9342011 AND 9342014 OR email LIKE '%@ldap1.test'`); e != nil {
				t.Fatal(e)
			}
		}
		var gate *threat.ThreatInterceptor
		if session.Threat != "" {
			reset, e := os.ReadFile(filepath.Join(root, "threat/reset.sql"))
			if e != nil {
				t.Fatal(e)
			}
			if _, e = pool.Exec(ctx, string(reset)); e != nil {
				t.Fatal(e)
			}
			q := "SELECT 1"
			switch session.Threat {
			case "feed":
				q = "INSERT INTO threat_feed_blocks(cidr,source) VALUES('127.0.0.1/32','authrt-ldap')"
			case "ip":
				q = "INSERT INTO ip_rules(cidr,action,description) VALUES('127.0.0.1/32','block','authrt-ldap')"
			case "lockout":
				q = "INSERT INTO auth_lockouts(lockout_key,locked_until) VALUES('user:alice@ldap1.test',now()+interval '800 milliseconds')"
			case "policy":
				q = `INSERT INTO conditional_access_policies(id,name,priority,state,scope_type,scope_target,conditions,actions) VALUES(9420422,'authrt-ldap',9422,'on','user','9342011','{}','{"action":"block"}')`
			}
			if _, e = pool.Exec(ctx, q); e != nil {
				t.Fatal(e)
			}
			flags := toggle.NewStatic(map[string]bool{toggle.FeatureThreatFeed: true, toggle.FeatureGeoBlock: false, toggle.FeatureSprayDetect: false, toggle.FeatureCaptcha: false, toggle.FeatureTarpit: false, toggle.FeatureRateLimit: false, toggle.FeatureConditionalAccess: session.Threat == "policy"})
			engine := threat.NewPolicyEngine(threat.NewPolicyStore(pool, testsupport.TestLogger()), flags, nil, nil, testsupport.TestLogger(), false)
			gate = threat.New(pool, pool, flags, nil, threat.ThreatConfig{}, testsupport.TestLogger(), engine)
		}
		addr := net.JoinHostPort("127.0.0.1", freePortString(t))
		s := NewServer(pool, addr, "ldap1.test", testsupport.TestLogger(), gate)
		if session.Transport == "starttls" {
			if e = s.EnableStartTLS(cert, key); e != nil {
				t.Fatal(e)
			}
		}
		if session.Transport == "tls" {
			if e = s.SetTLS(cert, key); e != nil {
				t.Fatal(e)
			}
		}
		done := make(chan error, 1)
		go func() { done <- s.Start(srvCtx) }()
		var conn net.Conn
		for until := time.Now().Add(4 * time.Second); time.Now().Before(until); time.Sleep(10 * time.Millisecond) {
			if session.Transport == "tls" {
				conn, e = tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
			} else {
				conn, e = net.DialTimeout("tcp", addr, time.Second)
			}
			if e == nil {
				break
			}
		}
		if e != nil {
			cancel()
			t.Fatal(e)
		}
		for j := range session.Steps {
			step := &session.Steps[j]
			b, e := hex.DecodeString(step.Request)
			if e != nil {
				t.Fatal(e)
			}
			conn.SetDeadline(time.Now().Add(4 * time.Second))
			if _, e = conn.Write(b); e != nil {
				t.Fatal(e)
			}
			for {
				b, e = oracleFrame(conn)
				if e != nil {
					t.Fatal(session.Name, e)
				}
				step.Responses = append(step.Responses, hex.EncodeToString(b))
				// Entry [APPLICATION 4] precedes the terminal result.
				at := 2
				if b[1] > 127 {
					at += int(b[1] & 127)
				}
				at += 2 + int(b[at+1])
				if b[at] != 0x64 {
					break
				}
			}
		}
		conn.Close()
		cancel()
		<-done
		if variant == "edges-" {
			var afterHash string
			var count int
			if e = pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE id=9342011`).Scan(&afterHash); e != nil {
				t.Fatal(e)
			}
			if e = pool.QueryRow(ctx, `SELECT count(*) FROM auth_event_log WHERE user_id BETWEEN 9342011 AND 9342014 OR email LIKE '%@ldap1.test'`).Scan(&count); e != nil {
				t.Fatal(e)
			}
			session.Effects = &oracleEffects{PasswordRehashed: afterHash != beforeHash, AuthEvents: count}
		}
	}
	if variant == "threat-" || variant == "threat-policy-" {
		reset, e := os.ReadFile(filepath.Join(root, "threat/reset.sql"))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = pool.Exec(ctx, string(reset)); e != nil {
			t.Fatal(e)
		}
		raw, e := os.ReadFile(filepath.Join(root, "cleanup.sql"))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = pool.Exec(ctx, string(raw)); e != nil {
			t.Fatal(e)
		}
	}
	out, e := json.MarshalIndent(sessions, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(root, variant+"go-sessions.json"), append(out, '\n'), 0644); e != nil {
		t.Fatal(e)
	}
}
func freePortString(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	_, p, e := net.SplitHostPort(l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	return p
}

// Record the frozen admission bug too: standard primitive Abandon is granted
// a slot, while the handler's early return never releases it. The final read
// stalls after sixteen such operations. Go's blocked grant cannot be drained;
// this isolated recorder process exits after writing the observation.
func TestRecordLDAPAbandonAdmission(t *testing.T) {
	root := os.Getenv("LDAP_ORACLE_DIR")
	if root == "" {
		t.Fatal("LDAP_ORACLE_DIR required")
	}
	path := filepath.Join(root, "go-abandon-admission.json")
	if _, e := os.Stat(path); e == nil {
		t.Fatal("golden exists")
	}
	addr := net.JoinHostPort("127.0.0.1", freePortString(t))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := NewServer(nil, addr, "ldap1.test", testsupport.TestLogger(), nil)
	go func() { _ = server.Start(ctx) }()
	var conn net.Conn
	var err error
	for until := time.Now().Add(3 * time.Second); time.Now().Before(until); time.Sleep(10 * time.Millisecond) {
		conn, err = net.Dial("tcp", addr)
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	bind, _ := hex.DecodeString("300c020101600702010304008000")
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = conn.Write(bind); err != nil {
		t.Fatal(err)
	}
	if _, err = oracleFrame(conn); err != nil {
		t.Fatal(err)
	}
	requests := []string{}
	for id := byte(2); id < 18; id++ {
		frame := []byte{0x30, 6, 2, 1, id, 0x50, 1, 1}
		requests = append(requests, hex.EncodeToString(frame))
		if _, err = conn.Write(frame); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = conn.Write(bind); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, err = oracleFrame(conn)
	timeout, ok := err.(net.Error)
	if !ok || !timeout.Timeout() {
		t.Fatalf("expected frozen Go grant stall, got %v", err)
	}
	raw, err := json.MarshalIndent(map[string]any{"requests": requests, "final_request": hex.EncodeToString(bind), "response_timeout": true}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, append(raw, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
}
