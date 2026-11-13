package handlerutil

import (
	"errors"
	"strings"
	"testing"
)

func TestUpdateBuilder_SetStr_SetsValue(t *testing.T) {
	b := &UpdateBuilder{}
	b.SetStr("name", stringPtr("Alice"))
	if len(b.updates) != 1 {
		t.Fatalf("expected 1 update, got %d", len(b.updates))
	}
	if b.updates[0].Column != "name" || b.updates[0].Value != "Alice" {
		t.Fatalf("unexpected update: %+v", b.updates[0])
	}
}

func TestUpdateBuilder_SetStr_Nil(t *testing.T) {
	b := &UpdateBuilder{}
	b.SetStr("name", nil)
	if len(b.updates) != 0 {
		t.Fatal("expected no update for nil pointer")
	}
}

func TestUpdateBuilder_SetStr_Empty(t *testing.T) {
	b := &UpdateBuilder{}
	b.SetStr("name", stringPtr(""))
	if len(b.updates) != 0 {
		t.Fatal("expected no update for empty string")
	}
}

func TestUpdateBuilder_SetInt(t *testing.T) {
	b := &UpdateBuilder{}
	v := int64(42)
	b.SetInt("quota_bytes", &v)
	if len(b.updates) != 1 {
		t.Fatal("expected update")
	}
}

func TestUpdateBuilder_SetBool(t *testing.T) {
	b := &UpdateBuilder{}
	v := true
	b.SetBool("enabled", &v)
	if len(b.updates) != 1 {
		t.Fatal("expected update")
	}
}

func TestBuild_NoFields(t *testing.T) {
	b := &UpdateBuilder{}
	_, _, err := b.Build("users", "id", 1, false, "")
	if err != ErrNoFields {
		t.Fatalf("expected ErrNoFields, got %v", err)
	}
}

func TestBuild_InvalidTable(t *testing.T) {
	b := &UpdateBuilder{}
	b.SetStr("display_name", stringPtr("foo"))
	_, _, err := b.Build("nonexistent_table", "id", 1, false, "")
	if err == nil {
		t.Fatal("expected error for invalid table")
	}
	if !errors.Is(err, ErrInvalidTable) {
		t.Fatalf("expected ErrInvalidTable, got %v", err)
	}
}

func TestBuild_InvalidColumn(t *testing.T) {
	b := &UpdateBuilder{}
	b.SetStr("not_a_real_column", stringPtr("foo"))
	_, _, err := b.Build("users", "id", 1, false, "")
	if err == nil {
		t.Fatal("expected error for invalid column")
	}
	if !errors.Is(err, ErrInvalidColumn) {
		t.Fatalf("expected ErrInvalidColumn, got %v", err)
	}
}

func TestBuild_ValidColumns(t *testing.T) {
	b := &UpdateBuilder{}
	b.SetStr("display_name", stringPtr("Alice"))
	b.SetBool("enabled", boolPtr(true))
	query, args, err := b.Build("users", "id", 1, false, "")
	if err != nil {
		t.Fatalf("expected nil error for valid columns, got: %v", err)
	}
	if !strings.Contains(query, "display_name") {
		t.Fatalf("expected query to contain column, got: %s", query)
	}
	if !strings.Contains(query, "enabled") {
		t.Fatalf("expected query to contain column, got: %s", query)
	}
	if len(args) != 3 {
		t.Fatalf("expected 3 args (display_name, enabled, id), got %d", len(args))
	}
}

func TestBuild_InvalidIDColumn(t *testing.T) {
	b := &UpdateBuilder{}
	b.SetStr("display_name", stringPtr("Alice"))
	_, _, err := b.Build("users", "not_a_column", 1, false, "")
	if err == nil {
		t.Fatal("expected error for invalid idCol")
	}
	if !errors.Is(err, ErrInvalidColumn) {
		t.Fatalf("expected ErrInvalidColumn, got %v", err)
	}
}

func TestBuild_AddUpdatedAt(t *testing.T) {
	b := &UpdateBuilder{}
	b.SetStr("display_name", stringPtr("Alice"))
	query, _, err := b.Build("users", "id", 1, true, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(query, "updated_at = now()") {
		t.Fatalf("expected updated_at clause, got: %s", query)
	}
}

func TestBuild_ExtraWhere(t *testing.T) {
	b := &UpdateBuilder{}
	b.SetStr("display_name", stringPtr("Alice"))
	// One update ($1) plus the id ($2) means the extraWhere arg is $3.
	query, args, err := b.Build("users", "id", 1, false, "domain_id = $3", int64(42))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(query, "AND domain_id = $3") {
		t.Fatalf("expected extra WHERE clause, got: %s", query)
	}
	if len(args) != 3 {
		t.Fatalf("expected 3 args (display_name, id, domain_id), got %d", len(args))
	}
	if args[2] != int64(42) {
		t.Fatalf("expected domain_id arg bound to $3, got args: %#v", args)
	}
}

func TestBuild_ExtraWhere_MisboundIndexFailsClosed(t *testing.T) {
	// The historically codified wrong binding: $2 re-uses the id placeholder's
	// index, so the ownership filter would bind the row id instead of the
	// caller's value. Build must refuse instead of returning a misbound query.
	b := &UpdateBuilder{}
	b.SetStr("display_name", stringPtr("Alice"))
	_, _, err := b.Build("users", "id", 1, false, "domain_id = $2", int64(42))
	if !errors.Is(err, ErrExtraWhereMisbound) {
		t.Fatalf("expected ErrExtraWhereMisbound, got: %v", err)
	}
}

func TestBuild_ExtraWhere_OutOfRangePlaceholderFailsClosed(t *testing.T) {
	b := &UpdateBuilder{}
	b.SetStr("display_name", stringPtr("Alice"))
	_, _, err := b.Build("users", "id", 1, false, "domain_id = $9", int64(42))
	if !errors.Is(err, ErrExtraWhereMisbound) {
		t.Fatalf("expected ErrExtraWhereMisbound, got: %v", err)
	}
}

func TestBuild_ExtraArgsWithoutExtraWhereFailsClosed(t *testing.T) {
	b := &UpdateBuilder{}
	b.SetStr("display_name", stringPtr("Alice"))
	_, _, err := b.Build("users", "id", 1, false, "", int64(42))
	if !errors.Is(err, ErrExtraWhereMisbound) {
		t.Fatalf("expected ErrExtraWhereMisbound, got: %v", err)
	}
}

func TestBuild_ExtraWhere_ConstantClauseAllowed(t *testing.T) {
	b := &UpdateBuilder{}
	b.SetStr("display_name", stringPtr("Alice"))
	query, args, err := b.Build("users", "id", 1, false, "enabled")
	if err != nil {
		t.Fatalf("unexpected error for constant extraWhere: %v", err)
	}
	if !strings.Contains(query, "AND enabled") {
		t.Fatalf("expected constant extra WHERE clause, got: %s", query)
	}
	if len(args) != 2 {
		t.Fatalf("expected 2 args, got %d", len(args))
	}
}

func TestUpdateBuilder_SetStrStrict_RejectsPresentEmptyValue(t *testing.T) {
	b := &UpdateBuilder{}
	empty := ""
	err := b.SetStrStrict("display_name", &empty)
	if !errors.Is(err, ErrRejectedValue) {
		t.Fatalf("expected ErrRejectedValue, got: %v", err)
	}
	if len(b.updates) != 0 {
		t.Fatal("rejected value must not be queued as an update")
	}
	rejected := b.Rejected()
	if len(rejected) != 1 || rejected[0] != "display_name" {
		t.Fatalf("expected display_name in rejected, got: %#v", rejected)
	}
}

func TestUpdateBuilder_SetStrStrict_NilAndValue(t *testing.T) {
	b := &UpdateBuilder{}
	if err := b.SetStrStrict("display_name", nil); err != nil {
		t.Fatalf("nil pointer must stay an absent field, got: %v", err)
	}
	val := "Alice"
	if err := b.SetStrStrict("display_name", &val); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(b.updates) != 1 || b.updates[0].Value != "Alice" {
		t.Fatalf("expected queued update, got: %#v", b.updates)
	}
	if len(b.Rejected()) != 0 {
		t.Fatal("expected no rejected fields")
	}
}

func stringPtr(s string) *string { return &s }
func boolPtr(b bool) *bool       { return &b }
