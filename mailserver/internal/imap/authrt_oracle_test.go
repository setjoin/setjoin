//go:build gofree_record

package imap

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"setjoin.com/mailserver/internal/webhook"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/threat"
	"setjoin.com/shared/toggle"
	"testing"
	"time"
)

func TestRecordAuthRuntimeIMAP(t *testing.T) {
	root := os.Getenv("IMAP_ORACLE_DIR")
	if root == "" {
		t.Fatal("IMAP_ORACLE_DIR required")
	}
	out := filepath.Join(root, "threat/go-complete.json")
	if os.Getenv("AUTHRT_IMAP_EFFECTS_ONLY") == "1" {
		out = filepath.Join(root, "threat/go-effects.json")
	}
	if os.Getenv("AUTHRT_IMAP_DEVICE_NULL") == "1" {
		out = filepath.Join(root, "threat/go-device-null.json")
	}
	if _, e := os.Stat(out); e == nil {
		t.Fatal("refuse overwrite")
	}
	ctx := context.Background()
	owner := testsupport.OpenTestPool(t)
	pool, e := pgxpool.New(ctx, os.Getenv("DB_APP_DSN"))
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	exec := func(path string) {
		b, e := os.ReadFile(filepath.Join(root, path))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = owner.Exec(ctx, string(b)); e != nil {
			t.Fatal(e)
		}
	}
	exec("cleanup.sql")
	exec("seed.sql")
	defer exec("cleanup.sql")
	defer exec("threat/reset.sql")
	b, e := os.ReadFile(filepath.Join(root, "password-hashes.json"))
	if e != nil {
		t.Fatal(e)
	}
	var hashes map[string]string
	json.Unmarshal(b, &hashes)
	if _, e = owner.Exec(ctx, "UPDATE users SET password_hash=$1 WHERE id=9343011", hashes["standard"]); e != nil {
		t.Fatal(e)
	}
	cert, key := writeIMAPTestCertificate(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cases := []map[string]any{}
	names := []string{"allow", "feed", "ip", "lockout", "rate", "policy", "wrong_password"}
	if os.Getenv("AUTHRT_IMAP_DEVICE_NULL") == "1" {
		names = []string{"device_country_null"}
	}
	for _, name := range names {
		for _, method := range []string{"LOGIN", "AUTHENTICATE"} {
			exec("threat/reset.sql")
			sql := "SELECT 1"
			switch name {
			case "feed":
				sql = "INSERT INTO threat_feed_blocks(cidr,source) VALUES('127.0.0.1/32','authrt')"
			case "ip":
				sql = "INSERT INTO ip_rules(cidr,action,description) VALUES('127.0.0.1/32','block','authrt')"
			case "lockout":
				sql = "INSERT INTO auth_lockouts(lockout_key,locked_until) VALUES('user:alice@imap1.test',now()+interval '800 milliseconds')"
			case "device_country_null":
				sql = "INSERT INTO device_registry(user_id,device_hash,user_agent,ip_prefix,country,auth_count) VALUES(9343011,encode(sha256('|127.0.0.0'::bytea),'hex'),'','127.0.0.0',NULL,1)"
			case "rate":
				sql = "INSERT INTO rate_limit_counters(key,count,window_start) VALUES('auth:imap:127.0.0.1',20,now())"
			case "policy":
				sql = `INSERT INTO conditional_access_policies(id,name,priority,state,scope_type,scope_target,conditions,actions) VALUES(9420420,'authrt',9420,'on','user','9343011','{}','{"action":"block"}')`
			}
			if _, e = owner.Exec(ctx, sql); e != nil {
				t.Fatal(e)
			}
			flags := toggle.NewStatic(map[string]bool{toggle.FeatureThreatFeed: true, toggle.FeatureGeoBlock: false, toggle.FeatureSprayDetect: false, toggle.FeatureCaptcha: false, toggle.FeatureTarpit: false, toggle.FeatureRateLimit: name == "rate", toggle.FeatureConditionalAccess: name == "policy"})
			engine := threat.NewPolicyEngine(threat.NewPolicyStore(pool, logger), flags, nil, nil, logger, false)
			gate := threat.New(pool, owner, flags, nil, threat.ThreatConfig{RateLimitPerMin: 20}, logger, engine)
			addr := "127.0.0.1:" + freePortString(t)
			run, cancel := context.WithCancel(ctx)
			server := NewServer(pool, addr, nil, logger, webhook.NewDispatcher(pool, logger), gate)
			server.SetTLS(cert, key)
			if e = server.Start(run); e != nil {
				t.Fatal(e)
			}
			conn, e := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
			if e != nil {
				t.Fatal(e)
			}
			client := &oracleConn{conn: conn, r: bufio.NewReader(conn)}
			greeting := oracleRead(t, client, "*")
			password := oracleStdPassword
			if name == "wrong_password" {
				password = "wrong"
			}
			request := "a LOGIN alice@imap1.test " + password + "\r\n"
			if method == "AUTHENTICATE" {
				request = "a AUTHENTICATE PLAIN " + base64.StdEncoding.EncodeToString([]byte("\x00alice@imap1.test\x00"+password)) + "\r\n"
			}
			continuation := ""
			payload := ""
			if method == "AUTHENTICATE" {
				payload = base64.StdEncoding.EncodeToString([]byte("\x00alice@imap1.test\x00"+password)) + "\r\n"
				request = "a AUTHENTICATE PLAIN\r\n"
				conn.Write([]byte(request))
				continuation = oracleRead(t, client, "+")
				conn.Write([]byte(payload))
			} else {
				conn.Write([]byte(request))
			}
			reply := oracleRead(t, client, "a")
			conn.Close()
			cancel()
			time.Sleep(50 * time.Millisecond)
			rows, e := owner.Query(ctx, "SELECT outcome||'|'||protocol||'|'||coalesce(geo_country,'')||'|'||coalesce(device_fingerprint,'') FROM auth_attempts WHERE target_username='alice@imap1.test' ORDER BY id")
			if e != nil {
				t.Fatal(e)
			}
			attempts := []string{}
			for rows.Next() {
				var s string
				rows.Scan(&s)
				attempts = append(attempts, s)
			}
			rows.Close()
			var signin, devices int
			owner.QueryRow(ctx, "SELECT count(*) FROM login_events WHERE user_id=9343011").Scan(&signin)
			owner.QueryRow(ctx, "SELECT coalesce(sum(auth_count),0) FROM device_registry WHERE user_id=9343011").Scan(&devices)
			effects := map[string]any{}
			queries := map[string]string{
				"attempts": `SELECT (to_jsonb(t)-'id'-'occurred_at')::text FROM auth_attempts t WHERE target_username='alice@imap1.test' ORDER BY id`,
				"signins":  `SELECT (to_jsonb(t)-'id'-'occurred_at')::text FROM login_events t WHERE user_id=9343011 OR (user_id IS NULL AND client='imap' AND source_ip='127.0.0.1') ORDER BY id`,
				"devices":  `SELECT (to_jsonb(t)-'id'-'first_seen'-'last_seen')::text FROM device_registry t WHERE user_id=9343011 ORDER BY device_hash`,
				"audit":    `SELECT (to_jsonb(t)-'id'-'occurred_at')::text FROM audit_log t WHERE user_id=9343011 AND event_type IN ('device_new','device_country_changed') ORDER BY id`,
				"lockouts": `SELECT jsonb_build_object('key',lockout_key,'failed_count',failed_count,'escalation_level',escalation_level)::text FROM auth_lockouts WHERE lockout_key IN ('ip:127.0.0.1','user:alice@imap1.test','ip_user:127.0.0.1:alice@imap1.test') ORDER BY lockout_key`,
			}
			for key, q := range queries {
				rows, e := owner.Query(ctx, q)
				if e != nil {
					t.Fatal(e)
				}
				data := []json.RawMessage{}
				for rows.Next() {
					var text string
					if e = rows.Scan(&text); e != nil {
						t.Fatal(e)
					}
					data = append(data, json.RawMessage(text))
				}
				rows.Close()
				effects[key] = data
			}
			cases = append(cases, map[string]any{"name": name, "method": method, "request": request, "continuation": continuation, "payload": payload, "greeting": greeting, "reply": reply, "attempts": attempts, "signins": signin, "device_auths": devices, "effects": effects})
		}
	}
	b, e = json.MarshalIndent(cases, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(out, append(b, '\n'), 0644); e != nil {
		t.Fatal(e)
	}
}
