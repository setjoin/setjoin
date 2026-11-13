package identity

import (
	"context"
	"strings"
	"testing"
)

// fold_stored_address(text) is a ONE-TIME BACKFILL helper, NOT a live twin of
// Go's CanonicalizeAddress. As of the AD/LDAP-writer-canonical wave
// (2026-06-18), every address WRITER routes through identity.CanonicalizeAddress
// (the CanonicalAddress newtype makes a raw-string write fail to compile), so
// nothing live writes a non-canonical row that the SQL fold would have to stay
// byte-equal to. fold_stored_address exists only to canonicalize the FINITE set
// of pre-canonical rows that V089 targets on a legacy prod DB.
//
// The test below is therefore a PINNED-CORPUS REGRESSION, not the old
// "byte-equal to Go forever" drift guard: it asserts the DOCUMENTED outputs for
// the V089 backfill corpus. The corpus's documented outputs HAPPEN to equal
// CanonicalizeAddress(x).String() for these no-display-name inputs (that is what
// made the original backfill provably behavior-preserving), and we still assert
// that equivalence as documentation of the backfill's intent — but the load-
// bearing assertion is now "fold_stored_address reproduces these pinned outputs,"
// which can't drift even after the Go canonicalizer evolves, because the corpus
// is the frozen V089 input set. The live "no writer bypasses the canonicalizer"
// invariant is enforced by the CanonicalAddress newtype + scripts/
// check-identity-writer.sh, not by this corpus.

// foldStoredAddressGo is the Go reference fold the V089 backfill was derived
// from: the casing/whitespace half of CanonicalizeAddress — trim + ASCII-A-Z
// fold — WITHOUT the RFC-5322 display-name strip. The display-name strip is
// INPUT-only (a SAML NameID may arrive as `"Name" <a@b>`); a STORED value
// (users.email, aliases.email, users.ad_upn) never carries a display-name
// wrapper, so applying the strip to one is data loss, not canonicalization (it
// would turn a Kerberos principal `host/server.corp@REALM <x@y>` into `x@y`).
// Kept as the documented derivation of each pinned output below.
func foldStoredAddressGo(s string) string {
	return asciiFoldLower(strings.TrimSpace(s))
}

// storedAddressCorpus is the V089 backfill input set: realistic NO-DISPLAY-NAME
// stored values — ASCII mixed-case, surrounding whitespace across every axis of
// Go's strings.TrimSpace / unicode.IsSpace set (each as a leading AND trailing
// affix), a bare UPN, Kerberos principals (with and without a trailing
// <...>-looking token a blind strip would have stolen), and a non-ASCII local
// (İstanbul) that lower() would have mis-folded. This is FROZEN — it is the
// pinned corpus, not a growing set.
const (
	wsTab     = "\t" // U+0009 HT
	wsLF      = "\n" // U+000A LF
	wsVT      = "\v" // U+000B VT
	wsFF      = "\f" // U+000C FF
	wsCR      = "\r" // U+000D CR
	wsSpace   = " "  // U+0020 SPACE
	wsNEL     = ""  // U+0085 NEL
	wsNBSP    = " "  // U+00A0 NBSP
	wsEmSpace = " "  // U+2003 EM SPACE  (U+2000-200A axis)
	wsIdeoSpc = "　"  // U+3000 IDEOGRAPHIC SPACE
)

var storedAddressCorpus = func() []string {
	base := []string{
		"Alice.Smith@Example.Com",
		"  alice@example.com  ",
		"  Alice.Smith@Example.Com  ",
		"ALICE@corp",                   // bare UPN, no dot
		"alice@CORP.EXAMPLE.COM",       // Kerberos principal / UPN
		"alice/admin@CORP.EXAMPLE.COM", // Kerberos principal with instance
		"host/server.corp@REALM <x@y>", // trailing <...> the blind strip would have stolen
		"alice@corp.local <weird>",     // a UPN with a trailing token — must NOT be reduced to "weird"
		"İstanbul@Example.Com",         // non-ASCII local: İ must survive, only the ASCII tail folds
		"",
		"   ",
	}
	for _, ws := range []string{wsTab, wsLF, wsVT, wsFF, wsCR, wsSpace, wsNEL, wsNBSP, wsEmSpace, wsIdeoSpc} {
		base = append(base,
			ws+"HOST@REALM",           // leading
			"HOST@REALM"+ws,           // trailing
			ws+"Alice@Example.Com"+ws, // both ends, with ASCII fold
		)
	}
	return base
}()

// TestFoldStoredAddress_PinnedCorpus is the BACKFILL regression (formerly the
// "byte-equal to Go forever" drift guard TestFoldStoredAddress_MatchesGo). It
// pins fold_stored_address(text) to the DOCUMENTED output for every value in the
// frozen V089 corpus. Because the corpus is no-display-name, each documented
// output also equals CanonicalizeAddress(x).String() — asserted here as the
// recorded derivation — but the corpus is FROZEN, so a future evolution of the
// Go canonicalizer cannot "drift" this test: the writer is now Go-canonical, so
// fold_stored_address has no live twin to chase. If the SQL backfill ever
// re-introduces the display-name strip or switches translate()→lower(), a case
// in this corpus diverges from its pinned output and the test fails.
//
// DB-gated: skipped when DB_DSN is unset (same convention as the rest of the
// package's DB tests).
//
//	DB_DSN=postgres://mail@127.0.0.1:5432/mailserver_test?sslmode=disable go test ./identity/...
func TestFoldStoredAddress_PinnedCorpus(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	for _, in := range storedAddressCorpus {
		in := in
		t.Run(in, func(t *testing.T) {
			// The pinned output for this corpus value: the display-strip-free
			// fold the backfill was derived from. (Recorded derivation, frozen
			// with the corpus.)
			want := foldStoredAddressGo(in)

			// Documentation assertion: for a no-display-name input the full
			// input canonicalizer agrees with the display-strip-free fold, so
			// the backfill is behavior-preserving against the Go matcher. This
			// is no longer the load-bearing guard — the writer is Go-canonical —
			// but it records WHY each pinned output is what it is. A corpus value
			// that grew a display-name case (making them disagree) is a corpus
			// authoring error, caught here.
			if canon := CanonicalizeAddress(in).String(); canon != want {
				t.Fatalf("corpus value %q is not display-name-free: CanonicalizeAddress=%q != foldStoredAddressGo=%q "+
					"(the backfill corpus must carry only no-display-name inputs)", in, canon, want)
			}

			var sqlFold string
			if err := pool.QueryRow(ctx, `SELECT fold_stored_address($1)`, in).Scan(&sqlFold); err != nil {
				t.Fatalf("fold_stored_address(%q): %v", in, err)
			}
			if sqlFold != want {
				t.Errorf("fold_stored_address(%q) = %q, want pinned %q", in, sqlFold, want)
			}
		})
	}
}

// TestFoldStoredAddress_NoDisplayStrip is the explicit corruption regression:
// the SQL stored fold must NOT extract a trailing <...> token. These two inputs
// are the exact data-loss cases the migration-safety lens found — a Kerberos
// principal and a UPN whose trailing token the old blind strip stole. They must
// survive intact (modulo ASCII fold). Kept unchanged across the demotion.
func TestFoldStoredAddress_NoDisplayStrip(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	cases := []struct{ in, want string }{
		{"host/server.corp@REALM <x@y>", "host/server.corp@realm <x@y>"},
		{"alice@corp.local <weird>", "alice@corp.local <weird>"},
		{"İstanbul@corp.com", "İstanbul@corp.com"}, // lower() would have folded İ→i; translate() must not
	}
	for _, tc := range cases {
		var got string
		if err := pool.QueryRow(ctx, `SELECT fold_stored_address($1)`, tc.in).Scan(&got); err != nil {
			t.Fatalf("fold_stored_address(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("fold_stored_address(%q) = %q, want %q (no display-name strip, ASCII-A-Z fold only)", tc.in, got, tc.want)
		}
	}
}
