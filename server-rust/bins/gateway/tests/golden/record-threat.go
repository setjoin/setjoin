// Disposable recording server: frozen shared/threat behind the Rust front door.
// Run this explicit file with Go; it is not part of a shipped Go program.
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/threat"
	"setjoin.com/shared/toggle"
)

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("TEST_DB_DSN"))
	if err != nil {
		return err
	}
	defer pool.Close()
	var db string
	if err = pool.QueryRow(ctx, `SELECT current_database()`).Scan(&db); err != nil {
		return err
	}
	if !strings.HasPrefix(db, "gofree_") && !strings.HasSuffix(db, "_test") {
		return fmt.Errorf("refusing non-disposable database %q", db)
	}
	// Refuse rather than overwrite any existing fixture or overlapping rule.
	var count int
	err = pool.QueryRow(ctx, `SELECT
      (SELECT count(*) FROM threat_feed_blocks WHERE cidr >>= '198.51.100.72'::inet OR cidr >>= '198.51.100.73'::inet OR cidr >>= '198.51.100.74'::inet) +
      (SELECT count(*) FROM ip_rules WHERE cidr >>= '198.51.100.72'::inet OR cidr >>= '198.51.100.73'::inet OR cidr >>= '198.51.100.74'::inet) +
      (SELECT count(*) FROM auth_attempts WHERE source_ip <<= '198.51.100.0/24') +
      (SELECT count(*) FROM auth_lockouts WHERE lockout_key LIKE 'ip:198.51.100.%' OR lockout_key LIKE 'ip_user:198.51.100.%' OR lockout_key='user:gofree-t7@example.invalid')`).Scan(&count)
	if err != nil {
		return err
	}
	if count != 0 {
		return fmt.Errorf("recording fixtures overlap %d existing rows", count)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO threat_feed_blocks (cidr, source) VALUES ('198.51.100.72/32', 'gofree-t7-recorder')`); err != nil {
		return err
	}
	defer clean(pool, `DELETE FROM threat_feed_blocks WHERE source='gofree-t7-recorder'`)
	if _, err = pool.Exec(ctx, `INSERT INTO ip_rules (cidr, action, description) VALUES ('198.51.100.73/32', 'block', 'gofree-t7-recorder')`); err != nil {
		return err
	}
	defer clean(pool, `DELETE FROM ip_rules WHERE description='gofree-t7-recorder'`)
	defer clean(pool, `DELETE FROM auth_attempts WHERE source_ip <<= '198.51.100.0/24' AND target_username='gofree-t7@example.invalid'`)

	flags := toggle.NewStatic(map[string]bool{
		toggle.FeatureThreatFeed: true, toggle.FeatureGeoBlock: false,
		toggle.FeatureSprayDetect: false, toggle.FeatureCaptcha: false,
		toggle.FeatureTarpit: false, toggle.FeatureRateLimit: false,
	})
	interceptor := threat.New(pool, nil, flags, nil, threat.ThreatConfig{}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	mux := http.NewServeMux()
	mux.Handle("/auth/login", interceptor.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	server := &http.Server{Handler: mux}
	fmt.Println(listener.Addr().String())
	go server.Serve(listener)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sig)
	<-sig
	return server.Shutdown(ctx)
}

func clean(pool *pgxpool.Pool, statement string) {
	if _, err := pool.Exec(context.Background(), statement); err != nil {
		log.Printf("recording cleanup failed: %v", err)
	}
}
