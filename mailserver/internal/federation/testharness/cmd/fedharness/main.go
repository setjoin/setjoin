// Command fedharness is the Pillar C0 spike's functional federation
// instance — NOT mailserverd. One binary = one federation domain (alpha,
// bravo, or charlie — see README.md). It wires the federation package's
// Dial/Listen/Sender/Receiver against a real database and a real per-domain
// TLS cert to prove the risky mechanisms (anchor-pinned mutual auth,
// commit-ordered exactly-once delivery, NOTIFY-woken drain, crash/reconnect
// resume, hub-per-room fan-out) end to end, and exposes a loopback-only HTTP
// control surface the Phase B experiment scripts drive (README.md's E2/E3
// curl sequences).
//
// DES-011 holds here unchanged: this daemon holds no authority of its own.
// Every decision (sequencing, dedup, allow-list, ingress) is a reducer call
// (mailserver/sql/reducers/federation_*.sql) — this file is wiring: flags in,
// goroutines started, HTTP handlers registered.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"setjoin.com/mailserver/internal/db"
	"setjoin.com/mailserver/internal/federation"
	"setjoin.com/mailserver/internal/federation/testharness"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("fedharness: fatal", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	var (
		localDomain  = flag.String("local-domain", "", "this instance's federation domain, e.g. alpha.test (required)")
		listenAddr   = flag.String("listen", ":7443", "federation s2s TLS listen address")
		controlAddr  = flag.String("control", "127.0.0.1:8080", "loopback control HTTP address")
		certFile     = flag.String("cert", "", "this domain's leaf certificate (gen-certs.sh's <domain>.crt) (required)")
		keyFile      = flag.String("key", "", "this domain's leaf private key (gen-certs.sh's <domain>.key) (required)")
		dbDSN        = flag.String("db", "", "app DB_DSN — must be able to bypass RLS on federation_* tables (required, see README.md)")
		directDBDSN  = flag.String("direct-db", "", "DB_DIRECT_DSN for the LISTEN/NOTIFY dispatcher (defaults to --db)")
		peersCSV     = flag.String("peers", "", "comma-separated peer domains this instance federates with, e.g. bravo.test,charlie.test")
		srvStub      = flag.String("srv-stub", "127.0.0.1:8600", "loopback address of the DNS SRV stub used to resolve peers")
		stubARecords = flag.String("stub-a-records", "", "optional: domain=host:port,... — if set, THIS instance also runs the SRV stub on --srv-stub, answering these records")
	)
	flag.Parse()

	if *localDomain == "" || *certFile == "" || *keyFile == "" || *dbDSN == "" {
		flag.Usage()
		return errors.New("fedharness: --local-domain, --cert, --key, and --db are required")
	}
	directDSN := *directDBDSN
	if directDSN == "" {
		directDSN = *dbDSN // ponytail: single-instance-dev fallback, matching mailserverd's default-to-DB_DSN posture for the direct-conn DSN.
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	leafCert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		return fmt.Errorf("fedharness: load leaf cert/key: %w", err)
	}

	rawPool, err := pgxutil.OpenPool(ctx, *dbDSN, 10, "", "")
	if err != nil {
		return fmt.Errorf("fedharness: open db pool: %w", err)
	}
	defer rawPool.Close()
	workerPool := pgxutil.WorkerPool{Pool: rawPool}

	featureFlags, err := toggle.New(ctx, rawPool, nil)
	if err != nil {
		return fmt.Errorf("fedharness: load feature toggles: %w", err)
	}
	if !featureFlags.IsEnabled(toggle.FeatureFederation) {
		return fmt.Errorf("fedharness: feature.federation is OFF in this database — " +
			"UPDATE feature_toggles SET enabled=true WHERE key='feature.federation' before starting the harness")
	}

	directConn, err := pgx.Connect(ctx, directDSN)
	if err != nil {
		return fmt.Errorf("fedharness: direct LISTEN connect: %w", err)
	}
	listener := db.NewListener(directConn, logger)
	listener.SetDSN(directDSN)
	go listener.Run(ctx)

	var peers []string
	for _, p := range strings.Split(*peersCSV, ",") {
		if p = strings.TrimSpace(p); p != "" {
			peers = append(peers, p)
		}
	}

	// Only the designated stub host runs the SRV server itself; every other
	// instance's --srv-stub just points at it (README.md).
	if *stubARecords != "" {
		recs, err := parseStubARecords(*stubARecords)
		if err != nil {
			return err
		}
		stub, err := testharness.NewStubSRVServer(*srvStub, recs)
		if err != nil {
			return fmt.Errorf("fedharness: start SRV stub: %w", err)
		}
		defer stub.Shutdown() //nolint:errcheck
		logger.Info("fedharness: running SRV stub", "addr", *srvStub, "records", len(recs))
	}
	resolver := federation.NetResolver{R: srvResolver(*srvStub)}

	deps := &appDeps{
		pool:        workerPool,
		flags:       featureFlags,
		localDomain: *localDomain,
		leafCert:    leafCert,
		resolver:    resolver,
		anchorLU:    newAnchorLookup(workerPool),
		senders:     newSenderRegistry(),
		logger:      logger,
	}

	// Wake the right sender for every peer's outbox NOTIFY — subscribed for
	// ALL peers regardless of dial/accept role, since a stream carries
	// traffic in both directions once established (sender.go's Wake doc).
	for _, peer := range peers {
		p := peer
		if _, err := listener.Subscribe(ctx, "federation_outbox:"+p, func(*pgconn.Notification) {
			deps.senders.wake(p)
		}); err != nil {
			return fmt.Errorf("fedharness: subscribe federation_outbox:%s: %w", p, err)
		}
	}

	// Acceptor side: federation.Listen's own Accept loop runs until ctx is
	// cancelled and hands every authenticated+authorized stream to onStream;
	// a peer that redials after a break is picked up here automatically, no
	// extra reconnect loop needed on this side (README.md).
	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		return fmt.Errorf("fedharness: listen %s: %w", *listenAddr, err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{leafCert}}
	go func() {
		hello := federation.Hello{FromDomain: *localDomain, Ver: 1}
		// scope="room" is a deliberate simplification: scope='room' covers
		// both 'dm' and 'room' requests (federation_peer_authorize.sql), and
		// the wiring contract is exactly ONE stream per pair — there is no
		// second, dm-scoped stream to authorize separately in this harness.
		err := federation.Listen(ctx, featureFlags, ln, tlsCfg, deps.anchorLU, hello, workerPool, "room", logger,
			func(stream *federation.PeerStream) {
				logger.Info("fedharness: accepted inbound stream", "peer", stream.Domain)
				go func() {
					err := wireAndRun(ctx, deps, stream)
					if ctx.Err() == nil {
						logger.Warn("fedharness: accepted stream ended", "peer", stream.Domain, "error", err)
					}
				}()
			})
		if err != nil && ctx.Err() == nil {
			logger.Error("fedharness: Listen exited", "error", err)
		}
	}()

	// Dialer side: exactly the peers this domain is lexicographically smaller
	// than (dialsFirst, gaps.go) — the other side accepts, per the wiring rule.
	for _, peer := range peers {
		if dialsFirst(*localDomain, peer) {
			go runDialer(ctx, deps, peer)
		} else {
			logger.Info("fedharness: peer will connect to us (accept side)", "peer", peer)
		}
	}

	cs := &controlServer{pool: workerPool, localDomain: *localDomain, logger: logger}
	controlSrv := &http.Server{
		Addr:              *controlAddr,
		Handler:           cs.mux(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		if err := controlSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("fedharness: control server failed", "error", err)
		}
	}()

	logger.Info("fedharness up", "domain", *localDomain, "listen", *listenAddr, "control", *controlAddr, "peers", peers)
	<-ctx.Done()
	logger.Info("fedharness shutting down", "domain", *localDomain)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	controlSrv.Shutdown(shutdownCtx) //nolint:errcheck
	ln.Close()                       //nolint:errcheck
	return nil
}
