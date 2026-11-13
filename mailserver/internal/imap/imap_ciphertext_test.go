package imap

// SP1 Phase 5 Task 5.6 — IMAP serves encrypted blobs VERBATIM (no server decrypt).
//
// The IMAP read path must NEVER decrypt S/MIME EnvelopedData: an encrypted message
// reaches the IMAP client as the stored ciphertext so the CLIENT's own key opens
// it (spec C3). These are GUARD tests that lock that invariant in place:
//   - TestIMAP_NoDecryptImported: a source scan asserting the imap package never
//     references smime.Decrypt / smime.DecryptMulti / smime.DecryptKey. If a future
//     edit wires hosted decryption into IMAP, this fails at origin.
//   - TestIMAP_SearchExcludesEncryptedBody: SEARCH TEXT keys on body_text, which is
//     NULL for encrypted mail, so a plaintext-only substring must NOT match an
//     encrypted message (its ciphertext is never indexed/searched).

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestIMAP_NoDecryptImported scans every non-test .go file in the imap package and
// asserts none references the smime decrypt primitives. IMAP never decrypts.
func TestIMAP_NoDecryptImported(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	banned := []string{
		"smime.Decrypt",
		"smime.DecryptMulti",
		"smime.DecryptKey",
		"DecodeEnvelopedDER",
	}
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		scanned++
		src := string(data)
		for _, b := range banned {
			if strings.Contains(src, b) {
				t.Errorf("%s references %q — IMAP must NEVER decrypt; serve the ciphertext blob verbatim", name, b)
			}
		}
	}
	if scanned == 0 {
		t.Fatal("scanned 0 source files — the guard is vacuous")
	}
}

// TestIMAP_SearchExcludesEncryptedBody seeds an encrypted message (crypto_type=
// 'smime-encrypted', body_text NULL) and proves a SEARCH TEXT on a plaintext-only
// substring does NOT match it (ciphertext is never full-text searched) while a
// SEARCH on its retained subject DOES match. DB-gated via the isolation harness.
func TestIMAP_SearchExcludesEncryptedBody(t *testing.T) {
	env := setupIMAPIso(t)
	ctx := context.Background()

	// Seed an encrypted message in A's Inbox: body_text NULL, crypto_type set,
	// subject retained. The plaintext substring "topsecretplaintext" exists ONLY in
	// the (unindexed) ciphertext — it must never surface via SEARCH.
	recv := time.Now()
	var encID int64
	if err := env.superPool.QueryRow(ctx,
		`INSERT INTO messages
		   (mailbox_id, folder_id, imap_uid, message_id, subject, from_addr,
		    to_addrs, cc_addrs, size_bytes, thread_id, raw_ref, received_at,
		    is_read, body_text, crypto_type)
		 VALUES ($1, $2, 99, 'imapEnc1', 'Encrypted subject token', 'sender@ext.com',
		         '[]'::jsonb, '[]'::jsonb, 10, 'thr-enc', 'raw-enc', $3,
		         FALSE, NULL, 'smime-encrypted')
		 RETURNING id`,
		env.mbA, env.tagA, recv,
	).Scan(&encID); err != nil {
		t.Fatalf("insert encrypted message: %v", err)
	}
	if _, err := env.superPool.Exec(ctx,
		`SELECT tag_message($1, $2, 'Inbox', $3, 'deliver', TRUE)`,
		encID, recv, env.mbA,
	); err != nil {
		t.Fatalf("tag encrypted message: %v", err)
	}
	t.Cleanup(func() {
		conn, err := env.superPool.Acquire(ctx)
		if err != nil {
			return
		}
		defer conn.Release()
		_, _ = conn.Exec(ctx, `SET session_replication_role = 'replica'`)
		_, _ = conn.Exec(ctx, `DELETE FROM message_tags WHERE message_id = $1`, encID)
		_, _ = conn.Exec(ctx, `DELETE FROM messages WHERE id = $1`, encID)
		_, _ = conn.Exec(ctx, `SET session_replication_role = 'origin'`)
	})

	// SEARCH TEXT on the body-only plaintext substring → must NOT return the
	// encrypted message (body_text is NULL; ciphertext is not searched).
	cA, bcA := env.connFor(env.mbA, env.tagA)
	cA.handleSearch(ctx, "s1", true, `TEXT "topsecretplaintext"`)
	bodyHit := bcA.String()
	if strings.Contains(bodyHit, "ALL 99") {
		t.Errorf("SEARCH TEXT on a body-only plaintext substring must NOT match the encrypted message (ciphertext is not indexed):\n%s", bodyHit)
	}

	// Control: SEARCH on the retained SUBJECT token DOES match → proves the harness
	// and the encrypted row are actually searchable by their cleartext headers, so
	// the body-exclusion above is a real exclusion, not a dead query.
	cB, bcB := env.connFor(env.mbA, env.tagA)
	cB.handleSearch(ctx, "s2", true, `TEXT "subject token"`)
	subjectHit := bcB.String()
	if !strings.Contains(subjectHit, "ALL 99") {
		t.Errorf("SEARCH on the retained subject token SHOULD match the encrypted message (subject stays searchable):\n%s", subjectHit)
	}
}
