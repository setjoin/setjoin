package imap

import (
	"testing"
)

// FuzzBuildSearchClause tests the IMAP SEARCH key builder.
func FuzzBuildSearchClause(f *testing.F) {
	f.Add("ALL")
	f.Add("UNSEEN")
	f.Add("FROM \"user@example.com\"")
	f.Add("SUBJECT \"test\" BEFORE 01-Jan-2026")
	f.Add("OR SEEN FLAGGED")
	f.Add("NOT DELETED")

	f.Fuzz(func(t *testing.T, input string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("buildSearchClause panicked on %q: %v", input, r)
			}
		}()
		buildSearchClause(input)
	})
}

// FuzzParseAddrTuple tests the IMAP address parser.
func FuzzParseAddrTuple(f *testing.F) {
	f.Add("((\"Sender\" NIL \"sender\" \"example.com\"))")
	f.Add("((NIL NIL \"user\" \"host\"))")
	f.Add("NIL")

	f.Fuzz(func(t *testing.T, input string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("parseAddrTuple panicked on %q: %v", input, r)
			}
		}()
		parseAddrTuple(input)
	})
}
