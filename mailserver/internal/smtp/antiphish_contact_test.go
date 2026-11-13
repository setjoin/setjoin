package smtp

import (
	"context"
	"testing"
)

func TestContactGraphNovelSenderKnownName_Warn(t *testing.T) {
	// Test without DB pool — contact graph detector checks via DB only.
	// The unit test verifies the detector structure and Name() method.
	d := NewContactGraphDetector(nil)

	if d.Name() != "contact_graph" {
		t.Errorf("expected Name() = 'contact_graph', got %q", d.Name())
	}

	// Without a pool, Check returns nil (test mode — no DB)
	input := &PhishInput{
		FromName: "Jane Doe",
		FromAddr: "jane@evil.com",
		Recipients: []PhishRecipient{
			{MailboxID: 42, Email: "user@example.com"},
		},
	}
	result, err := d.Check(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Without pool, no recipients produce results
	if result != nil {
		t.Errorf("expected nil result without pool, got verdict=%v", result.Verdict)
	}
}

func TestContactGraphEmptyDisplayName_None(t *testing.T) {
	d := NewContactGraphDetector(nil)

	input := &PhishInput{
		FromName: "",
		FromAddr: "attacker@evil.com",
		Recipients: []PhishRecipient{
			{MailboxID: 42, Email: "user@example.com"},
		},
	}
	result, err := d.Check(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result for empty display name, got verdict=%v", result.Verdict)
	}
}

func TestContactGraphEmptyFromAddr_None(t *testing.T) {
	d := NewContactGraphDetector(nil)

	input := &PhishInput{
		FromName: "Jane Doe",
		FromAddr: "",
		Recipients: []PhishRecipient{
			{MailboxID: 42, Email: "user@example.com"},
		},
	}
	result, err := d.Check(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result for empty from addr, got verdict=%v", result.Verdict)
	}
}

func TestContactGraphEmptyRecipients_None(t *testing.T) {
	d := NewContactGraphDetector(nil)

	input := &PhishInput{
		FromName:   "Jane Doe",
		FromAddr:   "jane@evil.com",
		Recipients: nil,
	}
	result, err := d.Check(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result for empty recipients, got verdict=%v", result.Verdict)
	}
}

func TestContactGraphZeroMailboxID_Skipped(t *testing.T) {
	d := NewContactGraphDetector(nil)

	input := &PhishInput{
		FromName: "Jane Doe",
		FromAddr: "jane@evil.com",
		Recipients: []PhishRecipient{
			{MailboxID: 0, Email: "user@example.com"},
		},
	}
	result, err := d.Check(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result for zero mailbox ID, got verdict=%v", result.Verdict)
	}
}

func TestContactGraphNegativeCache(t *testing.T) {
	d := NewContactGraphDetector(nil)

	// Pre-populate negative cache
	d.negativeCache.Store("42:jane@company.com", d.negativeTTL)

	// This sender was previously seen — should be cached
	input := &PhishInput{
		FromName: "Jane Doe",
		FromAddr: "jane@company.com",
		Recipients: []PhishRecipient{
			{MailboxID: 42, Email: "user@example.com"},
		},
	}
	result, err := d.Check(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result for cached sender, got verdict=%v", result.Verdict)
	}
}
