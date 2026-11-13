//go:build gofree_record

package main

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"setjoin.com/shared/threat"
	"setjoin.com/shared/toggle"
	"testing"
	"time"
)

func TestRecordAuthRuntimeListeners(t *testing.T) {
	dir := os.Getenv("AUTHRT_ORACLE_DIR")
	out := filepath.Join(dir, "listeners-go.json")
	if dir == "" {
		t.Fatal("AUTHRT_ORACLE_DIR required")
	}
	if _, e := os.Stat(out); e == nil {
		t.Fatal("refuse overwrite")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dsn := os.Getenv("TEST_DB_DSN")
	db, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	exec := func(q string) {
		if _, e := db.Exec(ctx, q); e != nil {
			t.Fatal(e)
		}
	}
	// All global edits are confined to the assigned disposable database and restored.
	var old bool
	if e = db.QueryRow(ctx, "SELECT enabled FROM feature_toggles WHERE key='feature.threat_feed'").Scan(&old); e != nil {
		t.Fatal(e)
	}
	defer db.Exec(context.Background(), "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.threat_feed'", old)
	exec("DELETE FROM threat_feed_blocks WHERE source='authrt-listeners'; INSERT INTO threat_feed_blocks(cidr,source) VALUES('192.0.2.42/32','authrt-listeners'); UPDATE feature_toggles SET enabled=false WHERE key='feature.threat_feed'")
	defer db.Exec(context.Background(), "DELETE FROM threat_feed_blocks WHERE source='authrt-listeners'; DELETE FROM conditional_access_policies WHERE id=9420421")
	flags, e := toggle.New(ctx, db, map[string]bool{toggle.FeatureGeoBlock: false, toggle.FeatureSprayDetect: false, toggle.FeatureCaptcha: false, toggle.FeatureTarpit: false, toggle.FeatureRateLimit: false, toggle.FeatureConditionalAccess: true})
	if e != nil {
		t.Fatal(e)
	}
	featureDSN := dsn + "?application_name=gofree-authrt-go-flags"
	policyDSN := dsn + "?application_name=gofree-authrt-go-policy"
	fl, e := openConfigListener(ctx, featureDSN, dsn, "feature_toggles", logger)
	if e != nil {
		t.Fatal(e)
	}
	if e = toggle.BindNotifications(ctx, fl, flags, nil, logger); e != nil {
		t.Fatal(e)
	}
	store := threat.NewPolicyStore(db, logger)
	engine := threat.NewPolicyEngine(store, flags, nil, nil, logger, false)
	pl, e := openConfigListener(ctx, policyDSN, dsn, "conditional_access", logger)
	if e != nil {
		t.Fatal(e)
	}
	if e = configureConditionalAccessListener(ctx, pl, newConditionalAccessReloader(engine, store.LoadBreakGlass), logger); e != nil {
		t.Fatal(e)
	}
	gate := threat.New(db, db, flags, nil, threat.ThreatConfig{}, logger, engine)
	meta := threat.ConnectionMeta{SourceIP: "192.0.2.42", Username: "authrt-listener", Protocol: "imap"}
	observations := []string{}
	pre := func() string { a, reason, _ := gate.Intercept(ctx, &meta); return a.String() + "|" + reason }
	await := func(want string) {
		until := time.Now().Add(12 * time.Second)
		for time.Now().Before(until) {
			if pre() == want {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("listener timeout want %q got %q", want, pre())
	}
	observations = append(observations, pre())
	exec(`UPDATE feature_toggles SET enabled=true WHERE key='feature.threat_feed'; SELECT pg_notify('config_changed','{"key":"feature.threat_feed","enabled":false}')`)
	await("reject|threat_blocked")
	observations = append(observations, pre())
	exec("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=current_database() AND application_name='gofree-authrt-go-flags'; UPDATE feature_toggles SET enabled=false WHERE key='feature.threat_feed'")
	await("proceed|")
	observations = append(observations, pre())
	// A policy change without NOTIFY during a disconnected interval is reconciled.
	postMeta := threat.ConnectionMeta{SourceIP: "192.0.2.43", UserID: 9420011, Protocol: "imap"}
	post := func() string { a, r := gate.EvaluatePostAuth(ctx, &postMeta); return a.String() + "|" + r }
	observations = append(observations, post())
	exec(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=current_database() AND application_name='gofree-authrt-go-policy'; INSERT INTO conditional_access_policies(id,name,priority,state,scope_type,scope_target,conditions,actions) VALUES(9420421,'authrt-listeners',9421,'on','user','9420011','{}','{"action":"block"}')`)
	until := time.Now().Add(12 * time.Second)
	for post() != "reject|conditional_access_blocked" && time.Now().Before(until) {
		time.Sleep(20 * time.Millisecond)
	}
	if post() != "reject|conditional_access_blocked" {
		t.Fatal("policy gap did not reconcile", post())
	}
	observations = append(observations, post())
	cancel()
	b, _ := json.MarshalIndent(observations, "", "  ")
	if e = os.WriteFile(out, append(b, '\n'), 0644); e != nil {
		t.Fatal(e)
	}
}
