package main

import "testing"

// TestValidateReading pins the codegen-output-injection guard: only ASCII
// lowercase readings may be interpolated into the generated SQL literal.
func TestValidateReading(t *testing.T) {
	cases := []struct {
		name    string
		cp      int
		py      string
		wantErr bool
	}{
		{name: "plain lowercase", cp: 0x4E2D, py: "zhong"},
		{name: "single letter", cp: 0x4E00, py: "yi"},
		{name: "empty reading", cp: 0x4E01, py: "", wantErr: true},
		{name: "uppercase", cp: 0x4E02, py: "Zhong", wantErr: true},
		{name: "quote injection", cp: 0x4E03, py: "z'); DROP TABLE cjk_pinyin;--", wantErr: true},
		{name: "apostrophe", cp: 0x4E04, py: "z'h", wantErr: true},
		{name: "semicolon", cp: 0x4E05, py: "zh;h", wantErr: true},
		{name: "newline", cp: 0x4E06, py: "zh\nong", wantErr: true},
		{name: "non-ascii", cp: 0x4E07, py: "zhōng", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateReading(tc.cp, tc.py)
			if tc.wantErr && err == nil {
				t.Fatalf("U+%04X reading %q: expected error, got nil", tc.cp, tc.py)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("U+%04X reading %q: unexpected error %v", tc.cp, tc.py, err)
			}
		})
	}
}
