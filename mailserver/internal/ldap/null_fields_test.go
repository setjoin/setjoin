package ldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"testing"
	"time"

	ldapclient "github.com/go-ldap/ldap/v3"

	"setjoin.com/shared/pwhash"
	"setjoin.com/shared/testsupport"
)

// TestSearchAndCompare_NullOptionalFields is the regression test for a bug
// found while fixing A1 (unrelated to bound-state): searchPeople/
// searchContacts scanned nullable columns (first_name, last_name, phone,
// job_title, department, avatar_sha256 — none NOT NULL in the schema) into
// plain (non-pointer) Go strings. rows.Scan on a NULL column into a *string
// errors, so pagedSearch/singleEntrySearch silently dropped the row (logged,
// no entry written) — the user vanished from the GAL entirely. Since most of
// these columns are commonly left blank (only 6 of 245 `INSERT INTO users`
// call sites in the repo set first_name), most real directories would
// silently vanish from GAL search. Fix: COALESCE(col, '') in the SQL.
//
// (handleCompare has the same COALESCE fix applied for consistency — same
// scan, same columns — but isn't exercised here: a live Compare against a
// real leaf DN hits a separate, pre-existing dnToFilter bug (prefix-only
// "ou=people" matching, which a "cn=...,ou=People,..." entry DN never
// satisfies) that's out of scope for A1 and untouched by this fix.)
func TestSearchAndCompare_NullOptionalFields(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	logger := testsupport.TestLogger()
	ctx := context.Background()

	suffix := fmt.Sprintf("%08x", time.Now().UnixNano()&0xffffffff)
	domainName := "ldapnull-" + suffix + ".internal"
	email := "nulltest-" + suffix + "@" + domainName
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

	// Deliberately omit first_name/last_name/phone/job_title/avatar_sha256 —
	// all nullable, all left NULL here, matching the common real-world case.
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, password_hash)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		"nulltest-"+suffix, email, "Null Test", domainID, hash,
	).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	createLDAPTestPrimaryMailbox(t, pool, ctx, userID, domainID, email)
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID) }) //nolint:errcheck

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

	if err := conn.Bind(email, password); err != nil {
		t.Fatalf("bind: %v", err)
	}

	baseDN := buildBaseDN(domainName)
	peopleDN := "ou=People," + baseDN
	filter := fmt.Sprintf("(mail=%s)", email)

	req := ldapclient.NewSearchRequest(peopleDN, ldapclient.ScopeWholeSubtree, ldapclient.NeverDerefAliases,
		0, 0, false, filter, []string{"cn", "mail"}, nil)
	res, err := conn.Search(req)
	if err != nil {
		t.Fatalf("search with NULL optional fields: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("search with NULL optional fields: got %d entries, want 1 (user silently dropped by a NULL-column scan error)", len(res.Entries))
	}

	cancel()
	<-errCh
}
