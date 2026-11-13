package validate

import (
	"testing"
)

func TestValidateResourceName_Valid(t *testing.T) {
	tests := []string{
		"Sales",
		"My Folder",
		"project-2024",
		"Department (HQ)",
		"Team Alpha_Beta",
		"A",
		"财务部",
	}
	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			if err := ValidateResourceName(name); err != nil {
				t.Errorf("ValidateResourceName(%q) = %v, want nil", name, err)
			}
		})
	}
}

func TestValidateResourceName_Invalid(t *testing.T) {
	tests := []struct {
		name string
		code string
	}{
		{"", "EMPTY_RESOURCE_NAME"},
		{"   ", "EMPTY_RESOURCE_NAME"},
		{"/", "FORBIDDEN_CHAR"},
		{"path/traversal", "FORBIDDEN_CHAR"},
		{"back\\slash", "FORBIDDEN_CHAR"},
		{"null\x00byte", "FORBIDDEN_CHAR"},
		{".", "RESERVED_NAME"},
		{"..", "RESERVED_NAME"},
		{"bad\x01ctrl", "CONTROL_CHAR"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateResourceName(tt.name)
			if err == nil {
				t.Errorf("ValidateResourceName(%q) = nil, want error", tt.name)
				return
			}
			ve, ok := err.(*ValidationError)
			if !ok {
				t.Errorf("expected *ValidationError, got %T", err)
				return
			}
			if ve.Code != tt.code {
				t.Errorf("code = %q, want %q", ve.Code, tt.code)
			}
		})
	}
}

// TestValidateResourceName_FilesystemSafety pins the future-sink hardening and
// the accurate safety claim (D-SHARED-VALIDATE-006): Windows reserved device
// names, trailing dots, and invalid UTF-8 are rejected; the doc comment no
// longer overclaims a filesystem-safety guarantee the checks cannot deliver.
func TestValidateResourceName_FilesystemSafety(t *testing.T) {
	rejected := []struct {
		name string
		code string
	}{
		{"con", "RESERVED_NAME"},
		{"CON", "RESERVED_NAME"},
		{"Con.txt", "RESERVED_NAME"},
		{"aux", "RESERVED_NAME"},
		{"nul", "RESERVED_NAME"},
		{"com1", "RESERVED_NAME"},
		{"LPT9", "RESERVED_NAME"},
		{"report.", "TRAILING_DOT_OR_SPACE"},
		{"bad\xffutf8", "INVALID_UTF8"},
	}
	for _, tt := range rejected {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateResourceName(tt.name)
			if err == nil {
				t.Errorf("ValidateResourceName(%q) = nil, want error", tt.name)
				return
			}
			ve, ok := err.(*ValidationError)
			if !ok {
				t.Errorf("expected *ValidationError, got %T", err)
				return
			}
			if ve.Code != tt.code {
				t.Errorf("code = %q, want %q", ve.Code, tt.code)
			}
		})
	}

	// Shell-significant names remain accepted: the accurate contract documents
	// that quoting/escaping belongs to any future shell/CLI sink, not here.
	for _, name := range []string{"-archived", "~templates", "财务部", "project-2024"} {
		if err := ValidateResourceName(name); err != nil {
			t.Errorf("ValidateResourceName(%q) = %v, want nil", name, err)
		}
	}
}
