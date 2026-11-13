package main

import "testing"

func TestListenerEnabledHonoursGoListenersOff(t *testing.T) {
	cases := []struct {
		env, name string
		want      bool
	}{
		{"", "imap", true},
		{"imap", "imap", false},
		{" imap , smtp", "imap", false},
		{"IMAP", "imap", true},
		{"imaps", "imap", true},
		{",,", "imap", true},
		{"imap", "", true},
		{"smtp,submission", "smtp", false},
		{"smtp,submission", "submission", false},
		{"smtp", "submission", true},
		{"submission", "smtp", true},
		{"smtps", "smtp", true},
	}
	for _, c := range cases {
		t.Setenv("GO_LISTENERS_OFF", c.env)
		if got := listenerEnabled(c.name); got != c.want {
			t.Errorf("GO_LISTENERS_OFF=%q name=%q: got %v want %v", c.env, c.name, got, c.want)
		}
	}
}
