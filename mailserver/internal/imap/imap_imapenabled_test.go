package imap

import "testing"

func TestImapDenied(t *testing.T) {
	if !imapDenied(false) {
		t.Fatal("imap_enabled=false must deny")
	}
	if imapDenied(true) {
		t.Fatal("imap_enabled=true must allow")
	}
}
