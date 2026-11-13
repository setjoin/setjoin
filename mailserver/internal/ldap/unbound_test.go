package ldap

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

// TestUnboundSearchAndCompare_Rejected is the regression test for A1 (GAL
// directory disclosure): handleSearch/handleCompare used to have no
// per-connection bound-state check at all, so a client that sends a
// SearchRequest (or CompareRequest) as its very first PDU — never issuing a
// Bind — got a full GAL dump back, silently bypassing handleBind's anonymous-
// bind rejection.
//
// This drives the real handlers through a live LDAPS listener (same harness
// as TestHandleBind_AuthPath): an unbound connection must get
// LDAPResultInsufficientAccessRights and zero entries for both Search and
// Compare; the SAME connection, after a successful Bind, must then succeed
// and see the seeded GAL entry.
func TestUnboundSearchAndCompare_Rejected(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	logger := testsupport.TestLogger()
	ctx := context.Background()

	suffix := fmt.Sprintf("%08x", time.Now().UnixNano()&0xffffffff)
	domainName := "ldapunbound-" + suffix + ".internal"
	email := "unboundtest-" + suffix + "@" + domainName
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
		"unboundtest-"+suffix, email, "Unbound Test", domainID, hash,
	).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	mailboxID := createLDAPTestPrimaryMailbox(t, pool, ctx, userID, domainID, email)
	aliasEmail := "alias-" + suffix + "@" + domainName
	upn := "upn-" + suffix + "@identity.internal"
	if _, err := pool.Exec(ctx, `UPDATE users SET ad_upn=$1 WHERE id=$2`, upn, userID); err != nil {
		t.Fatalf("set UPN: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO aliases (mailbox_id, email, domain_id) VALUES ($1,$2,$3)`, mailboxID, aliasEmail, domainID); err != nil {
		t.Fatalf("insert alias: %v", err)
	}

	seedExcluded := func(label string, hidden, guest bool) (int64, string) {
		excludedEmail := label + "-" + suffix + "@" + domainName
		var excludedID int64
		if err := pool.QueryRow(ctx,
			`INSERT INTO users (username, email, display_name, domain_id) VALUES ($1,$2,$1,$3) RETURNING id`,
			label+"-"+suffix, excludedEmail, domainID,
		).Scan(&excludedID); err != nil {
			t.Fatalf("insert excluded user: %v", err)
		}
		var excludedMailboxID int64
		if err := pool.QueryRow(ctx,
			`INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary, hidden_from_gal)
			 VALUES ($1,$2,$3,$3,'personal',TRUE,$4) RETURNING id`,
			excludedID, domainID, excludedEmail, hidden,
		).Scan(&excludedMailboxID); err != nil {
			t.Fatalf("insert excluded mailbox: %v", err)
		}
		if guest {
			if _, err := pool.Exec(ctx,
				`INSERT INTO guest_accounts (user_id, invited_email, invited_by_email, host_domain_id, status)
				 VALUES ($1,$2,$2,$3,'active')`, excludedID, excludedEmail, domainID); err != nil {
				t.Fatalf("insert guest account: %v", err)
			}
		}
		_ = excludedMailboxID
		return excludedID, excludedEmail
	}
	hiddenID, hiddenEmail := seedExcluded("ldap-hidden", true, false)
	guestID, guestEmail := seedExcluded("ldap-guest", false, true)
	t.Cleanup(func() {
		tx, err := pool.Begin(context.Background())
		if err != nil {
			return
		}
		_, _ = tx.Exec(context.Background(), `DELETE FROM guest_accounts WHERE user_id = ANY($1)`, []int64{hiddenID, guestID})
		_, _ = tx.Exec(context.Background(), `DELETE FROM mailboxes WHERE user_id = ANY($1)`, []int64{hiddenID, guestID})
		_, _ = tx.Exec(context.Background(), `DELETE FROM users WHERE id = ANY($1)`, []int64{hiddenID, guestID})
		_ = tx.Commit(context.Background())
	})
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

	baseDN := buildBaseDN(domainName)
	peopleDN := "ou=People," + baseDN
	filter := fmt.Sprintf("(mail=%s)", email)

	// --- Unbound Search: must be rejected, no rows. ---
	req := ldapclient.NewSearchRequest(peopleDN, ldapclient.ScopeWholeSubtree, ldapclient.NeverDerefAliases,
		0, 0, false, filter, []string{"cn", "mail"}, nil)
	res, err := conn.Search(req)
	if err == nil {
		t.Fatalf("unbound search: got %d entries with no error, want InsufficientAccessRights", len(res.Entries))
	}
	if !ldapclient.IsErrorWithCode(err, ldapclient.LDAPResultInsufficientAccessRights) {
		t.Errorf("unbound search: got %v, want LDAPResultInsufficientAccessRights", err)
	}
	if res != nil && len(res.Entries) > 0 {
		t.Errorf("unbound search: leaked %d GAL entries before any bind", len(res.Entries))
	}

	// --- Unbound Compare: must be rejected too. ---
	cn := extractRDNValue(userToDN(userID, email, "", baseDN), "cn")
	compareDN := fmt.Sprintf("cn=%s,%s", cn, peopleDN)
	same, err := conn.Compare(compareDN, "mail", email)
	if err == nil {
		t.Fatalf("unbound compare: got result=%v with no error, want InsufficientAccessRights", same)
	}
	if !ldapclient.IsErrorWithCode(err, ldapclient.LDAPResultInsufficientAccessRights) {
		t.Errorf("unbound compare: got %v, want LDAPResultInsufficientAccessRights", err)
	}

	// --- Now Bind, and the SAME connection must be able to search. ---
	if err := conn.Bind(email, password); err != nil {
		t.Fatalf("bind after unbound attempts: %v", err)
	}
	res, err = conn.Search(req)
	if err != nil {
		t.Fatalf("bound search: %v", err)
	}
	if len(res.Entries) == 0 {
		t.Errorf("bound search: got 0 entries, want the seeded GAL user")
	}
	for _, entry := range res.Entries {
		gotMail := entry.GetAttributeValue("mail")
		if gotMail == hiddenEmail || gotMail == guestEmail {
			t.Errorf("bound search leaked excluded directory principal %q", gotMail)
		}
	}

	for name, address := range map[string]string{"alias": aliasEmail, "upn": upn} {
		addressReq := ldapclient.NewSearchRequest(peopleDN, ldapclient.ScopeWholeSubtree, ldapclient.NeverDerefAliases,
			0, 0, false, fmt.Sprintf("(mail=%s)", address), []string{"cn", "mail"}, nil)
		addressRes, searchErr := conn.Search(addressReq)
		if searchErr != nil || len(addressRes.Entries) != 1 {
			t.Errorf("%s address search: entries=%d err=%v, want canonical person", name, len(addressRes.Entries), searchErr)
		}
		addressCN := strings.Split(address, "@")[0]
		baseReq := ldapclient.NewSearchRequest("cn="+addressCN+","+peopleDN, ldapclient.ScopeBaseObject, ldapclient.NeverDerefAliases,
			0, 0, false, "(objectClass=*)", []string{"cn", "mail"}, nil)
		baseRes, baseErr := conn.Search(baseReq)
		if baseErr != nil || len(baseRes.Entries) != 1 {
			t.Errorf("%s address base search: entries=%d err=%v, want canonical person", name, len(baseRes.Entries), baseErr)
		}
		compareDN := userToDN(userID, email, "", baseDN)
		same, compareErr := conn.Compare(compareDN, "mail", address)
		if compareErr != nil || !same {
			t.Errorf("%s address compare: same=%v err=%v, want true", name, same, compareErr)
		}
	}

	cancel()
	<-errCh
}
