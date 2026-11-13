package carddav

import (
	"strings"
	"testing"
	"time"
)

func strp(s string) *string { return &s }

func fullGalRow() *galUserRow {
	return &galUserRow{
		ID:          42,
		Email:       "zhang.alice@example.com",
		DisplayName: "Zhang Alice",
		FirstName:   strp("Alice"),
		LastName:    strp("Zhang"),
		Phone:       strp("+1 555 0100"),
		JobTitle:    strp("Engineer"),
		DeptName:    strp("Platform"),
		AvatarSHA:   strp("abc123"),
		ManagerName: strp("Dana Manager"),
		Addresses: []galAddress{
			{Email: "zhang.alice@example.com", Type: "primary", IsPrimary: true},
			{Email: "alice.zhang@example.com", Type: "alias", IsPrimary: false},
			{Email: "alice@upn.example.com", Type: "upn", IsPrimary: false},
		},
		UpdatedAt: time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC),
	}
}

func TestGalUserToVCard_FullRow(t *testing.T) {
	vc := galUserToVCard(fullGalRow())

	wantLines := []string{
		"BEGIN:VCARD",
		"VERSION:3.0",
		"UID:setjoin-gal-u42",
		"FN:Zhang Alice",
		"N:Zhang;Alice;;;",
		"EMAIL;TYPE=INTERNET,WORK,PREF:zhang.alice@example.com",
		"EMAIL;TYPE=INTERNET,WORK:alice.zhang@example.com",
		"EMAIL;TYPE=INTERNET,WORK:alice@upn.example.com",
		"TEL;TYPE=WORK:+1 555 0100",
		"TITLE:Engineer",
		"ORG:Platform",
		"X-MANAGER:Dana Manager",
		"PHOTO;VALUE=URI:/blobs/abc123",
		"KIND:individual",
		"REV:20260708T120000Z",
		"END:VCARD",
	}
	for _, line := range wantLines {
		if !strings.Contains(vc, line) {
			t.Errorf("vCard missing line %q:\n%s", line, vc)
		}
	}
	if !strings.Contains(vc, "\r\n") {
		t.Error("vCard must use CRLF line endings")
	}
}

func TestGalUserToVCard_MinimalRow(t *testing.T) {
	row := &galUserRow{
		ID:          7,
		Email:       "min@example.com",
		DisplayName: "Min Person",
		Addresses:   []galAddress{{Email: "min@example.com", Type: "primary", IsPrimary: true}},
		UpdatedAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	vc := galUserToVCard(row)

	for _, absent := range []string{"TEL;", "TITLE:", "ORG:", "X-MANAGER:", "PHOTO;"} {
		if strings.Contains(vc, absent) {
			t.Errorf("minimal row must not emit %q:\n%s", absent, vc)
		}
	}
	if !strings.Contains(vc, "UID:setjoin-gal-u7") || !strings.Contains(vc, "FN:Min Person") {
		t.Errorf("minimal row missing required fields:\n%s", vc)
	}
}

func TestGalUserToVCard_Escaping(t *testing.T) {
	row := fullGalRow()
	row.DisplayName = `Zhang, Alice; "A"`
	vc := galUserToVCard(row)
	if !strings.Contains(vc, `FN:Zhang\, Alice\; "A"`) {
		t.Errorf("display name not escaped per RFC 6350: %s", vc)
	}
}

func TestGalUserToVCard_StableAndRevBumps(t *testing.T) {
	row := fullGalRow()
	vc1 := galUserToVCard(row)
	vc2 := galUserToVCard(row)
	if vc1 != vc2 {
		t.Error("same row must serialize identically")
	}

	row2 := fullGalRow()
	row2.UpdatedAt = row2.UpdatedAt.Add(time.Hour)
	vc3 := galUserToVCard(row2)
	if vc1 == vc3 {
		t.Error("bumped updated_at must change the output (REV/etag)")
	}
	// Only REV should differ — everything else byte-identical.
	strip := func(s string) string {
		lines := strings.Split(s, "\r\n")
		var out []string
		for _, l := range lines {
			if !strings.HasPrefix(l, "REV:") {
				out = append(out, l)
			}
		}
		return strings.Join(out, "\r\n")
	}
	if strip(vc1) != strip(vc3) {
		t.Error("only REV should change when only updated_at bumps")
	}
}

func TestGalUserRow_ETag(t *testing.T) {
	row := fullGalRow()
	got := row.etag()
	if !strings.HasPrefix(got, "u42-") {
		t.Errorf("etag %q must start with u42-", got)
	}
}

func TestGalUID(t *testing.T) {
	if got := galUID(42); got != "setjoin-gal-u42" {
		t.Errorf("galUID(42) = %q, want setjoin-gal-u42", got)
	}
}
