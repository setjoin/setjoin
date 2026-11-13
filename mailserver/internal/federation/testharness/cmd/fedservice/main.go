// fedservice runs the PRODUCTION federation.Service (service.go — the C1
// Task 5 component mailserverd starts) against a real database and a real
// per-domain leaf cert, without the rest of the mailserverd stack (S3,
// auth chain, SMTP/IMAP). It exists for exactly one purpose: the C1 Task 9
// live 2-instance gate, where the thing under test must be the production
// Service's own reconcile loop / dial-vs-accept split / NOTIFY wake /
// dynamic allow-list+toggle gate — NOT fedharness's C0-era hand-rolled
// dial loop (which predates the Service and stays untouched as the C0
// artifact).
//
// Differences from fedharness, all deliberate:
//   - no --peers flag: the Service derives its peer set dynamically from
//     the enabled federation_allowlist rows (that dynamism IS a gate leg);
//   - no control HTTP surface: the gate drives state via psql (reducers)
//     and observes via the Service's own structured logs;
//   - the SRV stub is injected through federation.Config.Resolver — the
//     one seam this harness needed the production Config to expose.
//
// Non-production, testharness genre (README.md).
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/db"
	"setjoin.com/mailserver/internal/federation"
	"setjoin.com/mailserver/internal/federation/testharness"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("fedservice: fatal", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	var (
		localDomain  = flag.String("local-domain", "", "this instance's federation domain, e.g. alpha.test (required)")
		listenAddr   = flag.String("listen", ":7443", "federation s2s TLS listen address")
		certFile     = flag.String("cert", "", "this domain's leaf certificate (gen-certs.sh's <domain>.crt) (required)")
		keyFile      = flag.String("key", "", "this domain's leaf private key (gen-certs.sh's <domain>.key) (required)")
		dbDSN        = flag.String("db", "", "app DB_DSN — must be able to bypass RLS on federation_* tables (required, see ../README.md)")
		directDBDSN  = flag.String("direct-db", "", "DB_DIRECT_DSN for the LISTEN/NOTIFY dispatcher (defaults to --db)")
		srvStub      = flag.String("srv-stub", "127.0.0.1:8600", "loopback address of the DNS SRV stub used to resolve peers")
		stubARecords = flag.String("stub-a-records", "", "optional: domain=host:port,... — if set, THIS instance also runs the SRV stub on --srv-stub")
	)
	flag.Parse()

	if *localDomain == "" || *certFile == "" || *keyFile == "" || *dbDSN == "" {
		flag.Usage()
		return errors.New("fedservice: --local-domain, --cert, --key, and --db are required")
	}
	directDSN := *directDBDSN
	if directDSN == "" {
		directDSN = *dbDSN
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	leafCert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		return fmt.Errorf("fedservice: load leaf cert/key: %w", err)
	}

	rawPool, err := pgxutil.OpenPool(ctx, *dbDSN, 10, "", "")
	if err != nil {
		return fmt.Errorf("fedservice: open db pool: %w", err)
	}
	defer rawPool.Close()
	workerPool := pgxutil.WorkerPool{Pool: rawPool}

	featureFlags, err := toggle.New(ctx, rawPool, nil)
	if err != nil {
		return fmt.Errorf("fedservice: load feature toggles: %w", err)
	}

	directConn, err := pgx.Connect(ctx, directDSN)
	if err != nil {
		return fmt.Errorf("fedservice: direct LISTEN connect: %w", err)
	}
	listener := db.NewListener(directConn, logger)
	listener.SetDSN(directDSN)
	go listener.Run(ctx)

	if *stubARecords != "" {
		recs, err := testharness.ParseStubARecords(*stubARecords)
		if err != nil {
			return err
		}
		stub, err := testharness.NewStubSRVServer(*srvStub, recs)
		if err != nil {
			return fmt.Errorf("fedservice: start SRV stub: %w", err)
		}
		defer stub.Shutdown() //nolint:errcheck
		logger.Info("fedservice: running SRV stub", "addr", *srvStub, "records", len(recs))
	}

	svc := federation.NewService(
		federation.Config{
			LocalDomain: *localDomain,
			ListenAddr:  *listenAddr,
			Resolver:    federation.NetResolver{R: testharness.SRVResolver(*srvStub)},
		},
		workerPool, featureFlags, listener, leafCert, logger,
	)
	if svc == nil {
		return errors.New("fedservice: NewService returned nil (empty --local-domain?)")
	}

	logger.Info("fedservice: running production federation.Service",
		"local_domain", *localDomain, "listen", *listenAddr)
	svc.Run(ctx) // blocks until SIGINT/SIGTERM
	return nil
}
