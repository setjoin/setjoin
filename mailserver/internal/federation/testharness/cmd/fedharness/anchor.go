package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"

	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/federation"
	"setjoin.com/mailserver/internal/federation/testharness"
	"setjoin.com/shared/pgxutil"
)

// newAnchorLookup builds a federation.AnchorLookup backed by
// federation_allowlist.peer_anchor. federation_allowlist is FORCE RLS with
// ZERO policies (deny-all to setjoin_app — V138's disposition, same shape as
// chat_audit_log); a plain SELECT only succeeds if the harness's --db
// credential can bypass RLS on it (e.g. the bootstrapping role, or a role
// granted setjoin_worker — see README.md's DB setup step). This is a
// narrower read than federation_peer_authorize (Task 3): it returns the
// anchor for ANY row that exists, enabled or not — local policy (enabled +
// scope) is a separate, later check the reducer performs during the
// handshake (stream.go's authorizePeer), matching the production-shape
// split the V138 migration's own comments describe.
func newAnchorLookup(pool pgxutil.WorkerPool) federation.AnchorLookup {
	return func(ctx context.Context, domain string) (federation.Anchor, bool, error) {
		var pemStr string
		err := pool.QueryRow(ctx,
			`SELECT peer_anchor FROM federation_allowlist WHERE peer_domain = $1`, domain,
		).Scan(&pemStr)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return federation.Anchor{}, false, nil
			}
			return federation.Anchor{}, false, fmt.Errorf("fedharness: read anchor for %s: %w", domain, err)
		}
		cert, err := parseAnchorPEM(pemStr)
		if err != nil {
			return federation.Anchor{}, false, fmt.Errorf("fedharness: parse anchor for %s: %w", domain, err)
		}
		return federation.Anchor{CACert: cert}, true, nil
	}
}

// parseAnchorPEM decodes a single PEM-encoded CA certificate — the shape
// gen-certs.sh writes to <domain>.ca.crt and the shape README.md's seed SQL
// inserts as federation_allowlist.peer_anchor.
func parseAnchorPEM(s string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

// srvResolver / parseStubARecords hoisted to package testharness
// (srvhelpers.go) so cmd/fedservice shares them; thin aliases kept so this
// file's callers read unchanged.
func srvResolver(stubAddr string) *net.Resolver { return testharness.SRVResolver(stubAddr) }

func parseStubARecords(s string) ([]testharness.SRVRecord, error) {
	return testharness.ParseStubARecords(s)
}
