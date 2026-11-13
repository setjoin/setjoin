package validate

import "testing"

// med-shard2-008 (D-SHARED-VALIDATE-001): the RFC 2142 reserved-name set must be
// reachable from provisioning paths as an address-level gate, including against
// quoted-local and display-name decorated inputs that would otherwise bypass a
// naive exact-string comparison.
func TestIsReservedEmailAddress(t *testing.T) {
	reserved := []string{
		"postmaster@corp.example",
		"POSTMASTER@CORP.EXAMPLE",
		"abuse@corp.example",
		"Webmaster@corp.example",
		"HOSTMASTER@corp.example",
		"mailer-daemon@corp.example",
		"nobody@corp.example",
		// Quoted-string local-part: same local-part sequence per RFC 5321
		// 4.1.2, so quoting must not bypass the gate.
		`"postmaster"@corp.example`,
		`"Abuse"@corp.example`,
		// Display-name / trailing-comment decoration resolves to the bare
		// address. (A comment INSIDE the local-part — abuse(comment)@x — does
		// not parse at all and is rejected by ValidateEmail, fail-closed.)
		"Ops Team <abuse@corp.example>",
		`"Helpdesk" <postmaster@corp.example>`,
		"abuse@corp.example (Abuse Desk)",
	}
	for _, email := range reserved {
		if !IsReservedEmailAddress(email) {
			t.Errorf("IsReservedEmailAddress(%q) = false, want true", email)
		}
	}

	allowed := []string{
		"alice@corp.example",
		"",
		"not-an-address",
		"@corp.example",
		// Prefixes and suffixed variants are ordinary local-parts.
		"postmaster2@corp.example",
		"theabuse@corp.example",
		"postmaster.corp@example.com",
		`"postmaster2"@corp.example`,
		// A reserved DOMAIN label is not a reserved local-part.
		"alice@postmaster.example",
	}
	for _, email := range allowed {
		if IsReservedEmailAddress(email) {
			t.Errorf("IsReservedEmailAddress(%q) = true, want false", email)
		}
	}
}

func TestIsReservedEmailLocalPart(t *testing.T) {
	cases := []struct {
		local string
		want  bool
	}{
		{"postmaster", true},
		{"PostMaster", true},
		{`"postmaster"`, true},
		{`"ABUSE"`, true},
		{"postmaster2", false},
		{"alice", false},
		{"", false},
	}
	for _, c := range cases {
		if got := IsReservedEmailLocalPart(c.local); got != c.want {
			t.Errorf("IsReservedEmailLocalPart(%q) = %v, want %v", c.local, got, c.want)
		}
	}
}

// med-shard2-008 (D-SHARED-VALIDATE-002): the value-returning primitive must
// hand back exactly the canonical address that passed validation, so writers
// persist it instead of the raw (display-name/comment/whitespace-decorated)
// request string the error-only validator inspected.
func TestCanonicalEmail(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		want   string
		wanErr bool
	}{
		{"plain", "alice@corp.example", "alice@corp.example", false},
		{"display name stripped", `"Alice A" <alice@corp.example>`, "alice@corp.example", false},
		{"trailing comment stripped", "alice@corp.example (Alice)", "alice@corp.example", false},
		{"space padding stripped", "  alice@corp.example  ", "alice@corp.example", false},
		{"case preserved", "Alice@Corp.Example", "Alice@Corp.Example", false},
		// net/mail canonicalizes an unnecessary quoted-string local-part to its
		// dot-atom form, so the persisted value carries no quoting at all.
		{"quoted local canonicalized unquoted", `"bob"@corp.example`, "bob@corp.example", false},
		// med-shard2-008 r2: parsing strips quoting that the bare form REQUIRES
		// (`"first last"@example.com` de-quotes to `first last@example.com`,
		// which fails this same validator). The canonical must preserve the
		// required quoting rather than hand writers an invalid address.
		{"quoted local with space preserved", `"first last"@corp.example`, `"first last"@corp.example`, false},
		{"decorated quoted local preserved", `Ops Desk <"first last"@corp.example>`, `"first last"@corp.example`, false},
		{"quoted at-sign local preserved", `"bo@b"@corp.example`, `"bo@b"@corp.example`, false},
		{"quoted escaped-quote local preserved", `"a\"b"@corp.example`, `"a\"b"@corp.example`, false},
		{"quoted backslash local preserved", `"a\\b"@corp.example`, `"a\\b"@corp.example`, false},
		{"quoted leading-dot local preserved", `".lead"@corp.example`, `".lead"@corp.example`, false},
		{"quoted trailing-dot local preserved", `"trail."@corp.example`, `"trail."@corp.example`, false},
		{"control char rejected", "alice\x01@corp.example", "", true},
		{"tab rejected", "\talice@corp.example", "", true},
		{"newline rejected", "alice@corp.example\nBCC: x@y.z", "", true},
		{"comment inside local-part rejected", "alice(comment)@corp.example", "", true},
		{"empty rejected", "", "", true},
		{"no domain dot rejected", "alice@corp", "", true},
	}
	for _, c := range cases {
		got, err := CanonicalEmail(c.in)
		if c.wanErr {
			if err == nil {
				t.Errorf("%s: CanonicalEmail(%q) accepted, want rejection", c.name, c.in)
			}
			if got != "" {
				t.Errorf("%s: CanonicalEmail(%q) = %q with error, want empty", c.name, c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: CanonicalEmail(%q) error: %v", c.name, c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: CanonicalEmail(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

// med-shard2-008 r2: pin the two properties the Astra HOLD demands of the
// value-returning primitive. For every accepted input — plain, decorated, and
// quoted-local forms — the returned canonical must
//  1. itself pass ValidateEmail with the same options (returned-value
//     validity: the pre-fix code returned the de-quoted
//     `first last@example.com`, which fails the same validator), and
//  2. canonicalize to itself (canonicalization idempotence).
func TestCanonicalEmailReturnedValueValidAndIdempotent(t *testing.T) {
	accepted := []struct {
		name string
		in   string
		opts []EmailOption
	}{
		{"plain", "alice@corp.example", nil},
		{"case preserved", "Alice@Corp.Example", nil},
		{"display name stripped", `"Alice A" <alice@corp.example>`, nil},
		{"trailing comment stripped", "alice@corp.example (Alice)", nil},
		{"angle addr", "<alice@corp.example>", nil},
		{"space padding stripped", "  alice@corp.example  ", nil},
		{"unnecessary quotes stripped", `"bob"@corp.example`, nil},
		{"required quotes preserved", `"first last"@corp.example`, nil},
		{"decorated required quotes preserved", `Ops Desk <"first last"@corp.example>`, nil},
		{"quoted at-sign local", `"bo@b"@corp.example`, nil},
		{"quoted escaped quote", `"a\"b"@corp.example`, nil},
		{"quoted escaped backslash", `"a\\b"@corp.example`, nil},
		{"quoted leading dot", `".lead"@corp.example`, nil},
		{"quoted trailing dot", `"trail."@corp.example`, nil},
		{"smtputf8 quoted local", `"ünïcode"@corp.example`, []EmailOption{WithSMTPUTF8(true)}},
		{"smtputf8 bare local", "ünïcode@corp.example", []EmailOption{WithSMTPUTF8(true)}},
	}
	for _, c := range accepted {
		t.Run(c.name, func(t *testing.T) {
			got, err := CanonicalEmail(c.in, c.opts...)
			if err != nil {
				t.Fatalf("CanonicalEmail(%q) rejected: %v", c.in, err)
			}
			if ve := ValidateEmail(got, c.opts...); ve != nil {
				t.Fatalf("CanonicalEmail(%q) = %q, which fails the same validator: %v", c.in, got, ve)
			}
			again, err := CanonicalEmail(got, c.opts...)
			if err != nil {
				t.Fatalf("CanonicalEmail of its own output %q rejected: %v", got, err)
			}
			if again != got {
				t.Fatalf("CanonicalEmail not idempotent: CanonicalEmail(%q) = %q", got, again)
			}
		})
	}
}

// med-shard2-008 (D-SHARED-VALIDATE-003): quoted-local forms must not defeat
// password-contains-email. The pre-fix implementation split on the FIRST '@'
// and compared the raw caller string, so provisioning stored bob@corp.example
// while the policy token was the never-matching `"bob"` literal.
func TestPasswordContainsEmailQuotedLocalCannotDefeat(t *testing.T) {
	cases := []struct {
		name     string
		password string
		email    string
		want     bool
	}{
		// The reported inert end-to-end case: quoted-local input, plain password.
		{"quoted local vs plain password", "Corpbob-XYZ-99", `"bob"@corp.example`, true},
		{"quoted local vs literal token", `x"bob"y-99`, `"bob"@corp.example`, true},
		// First-'@' mis-split case: local-part contains '@'.
		{"at-sign local unquoted content", "bo@b-Strong-99", `"bo@b"@corp.example`, true},
		// Display-name decoration must resolve to the real address.
		{"display name form", "Corpbob-XYZ-99", "Bob <bob@corp.example>", true},
		// Plain forms keep working (regression guard).
		{"plain local containment", "Corpbob-XYZ-99", "bob@corp.example", true},
		{"plain domain containment", "x-CORP.EXAMPLE-y", "bob@corp.example", true},
		{"mixed case email", "Corpbob-XYZ-99", "BOB@CORP.EXAMPLE", true},
		// Non-containment must stay false.
		{"unrelated local", "Corpalice-XYZ-99", "bob@corp.example", false},
		{"no at sign at all", "Corpbob-XYZ-99", "not-an-address", false},
	}
	for _, c := range cases {
		if got := passwordContainsEmail(c.password, c.email); got != c.want {
			t.Errorf("%s: passwordContainsEmail(%q, %q) = %v, want %v", c.name, c.password, c.email, got, c.want)
		}
	}
}

// Policy-level pin of the same control: DisallowEmail carrying a quoted-local
// address rejects a password that merely contains the unquoted local-part.
func TestValidatePasswordDisallowEmailQuotedLocal(t *testing.T) {
	policy := PasswordPolicy{MinLength: 8, DisallowEmail: `"bob"@corp.example`}
	if err := ValidatePassword("Corpbob-XYZ-99", policy); err == nil {
		t.Fatal("ValidatePassword accepted password containing the quoted-local email's local-part")
	}
	if err := ValidatePassword("Corpalice-XYZ-99", policy); err != nil {
		t.Fatalf("ValidatePassword rejected unrelated password: %v", err)
	}
}
