package ldap

// End-to-end paged-results-cap test (er5-s15, sealed anchor
// ldap-paging-cap-bypass): a real RFC 2696 paging control with a hostile
// pageSize (2^31-1) rides the SAME effectivePageSize clamp as the SizeLimit
// field, so the search completes normally instead of lifting the enforced
// maxLDAPSearchSizeLimit cap. The clamp matrix itself is pinned by
// TestEffectivePageSize_* (search_page_bounds_test.go); this test covers the
// handler branch that applies it on the wire.

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"testing"
	"time"

	ldapclient "github.com/go-ldap/ldap/v3"
	"setjoin.com/shared/pwhash"
	"setjoin.com/shared/testsupport"
)

func TestSearch_PagedControlPageSizeCannotExceedServerCap(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	logger := testsupport.TestLogger()
	ctx := context.Background()

	suffix := fmt.Sprintf("%08x", time.Now().UnixNano()&0xffffffff)
	domainName := "ldappg-" + suffix + ".internal"
	email := "pgcap-" + suffix + "@" + domainName
	const password = "correct-horse-battery-staple-1!"
	hash, err := pwhash.HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	var domainID, userID int64
	if err := pool.QueryRow(ctx, `INSERT INTO domains (name) VALUES ($1) RETURNING id`, domainName).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM domains WHERE id = $1`, domainID) }) //nolint:errcheck
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, password_hash)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		"pgcap-"+suffix, email, "Paging Cap", domainID, hash,
	).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	cleanupLDAPFixtureUser(t, pool, userID)
	createLDAPTestPrimaryMailbox(t, pool, ctx, userID, domainID, email)

	certFile, keyFile := genSelfSignedCert(t)
	port := freeTCPPort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	srv := NewServer(pool, addr, domainName, logger, nil)
	if err := srv.SetTLS(certFile, keyFile); err != nil {
		t.Fatalf("SetTLS: %v", err)
	}
	srvCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(srvCtx) }()

	deadline := time.Now().Add(5 * time.Second)
	var conn *ldapclient.Conn
	for {
		conn, err = ldapclient.DialURL(fmt.Sprintf("ldaps://%s", addr),
			ldapclient.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true})) //nolint:gosec // test-only, self-signed
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server never accepted connections: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer conn.Close()

	base := "ou=People"
	for _, part := range strings.Split(domainName, ".") {
		base += ",dc=" + part
	}

	if err := conn.Bind(email, password); err != nil {
		t.Fatalf("bind: %v", err)
	}

	// A hostile paging control demanding the full int32 range must not lift
	// the server cap: the search completes normally over the clamped limit.
	paging := ldapclient.NewControlPaging(uint32(1<<31 - 1))
	req := ldapclient.NewSearchRequest(base, ldapclient.ScopeWholeSubtree,
		ldapclient.NeverDerefAliases, 0, 0, false, "(cn=Paging Cap)",
		[]string{"mail", "cn"}, []ldapclient.Control{paging})
	res, err := conn.Search(req)
	if err != nil {
		t.Fatalf("paged search with hostile pageSize failed: %v", err)
	}
	if res == nil {
		t.Fatal("paged search returned no result")
	}

	cancel()
	<-errCh
}
