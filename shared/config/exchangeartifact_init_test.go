package config

import (
	"math"
	"testing"

	"setjoin.com/shared/exchangeartifact"
)

// TestInitExchangeArtifactMaxEnvelope pins the config→package-global seam:
// unset converges to the shipped 1 GiB default, a configured value overrides
// it, and an invalid value is refused fail-closed without disturbing the
// previously effective ceiling.
func TestInitExchangeArtifactMaxEnvelope(t *testing.T) {
	t.Cleanup(func() { _ = exchangeartifact.SetMaxEnvelope(exchangeartifact.DefaultMaxEnvelope) })

	// Unset (0) converges to the shipped default.
	if err := InitExchangeArtifactMaxEnvelope(0); err != nil {
		t.Fatalf("InitExchangeArtifactMaxEnvelope(0): %v", err)
	}
	if got := exchangeartifact.MaxEnvelope(); got != exchangeartifact.DefaultMaxEnvelope {
		t.Fatalf("after unset-init MaxEnvelope = %d, want %d", got, exchangeartifact.DefaultMaxEnvelope)
	}

	// A configured value overrides the default.
	if err := InitExchangeArtifactMaxEnvelope(512 << 20); err != nil {
		t.Fatalf("InitExchangeArtifactMaxEnvelope(512MiB): %v", err)
	}
	if got := exchangeartifact.MaxEnvelope(); got != 512<<20 {
		t.Fatalf("after override-init MaxEnvelope = %d, want %d", got, 512<<20)
	}

	// Invalid values are refused and leave the override in place.
	if err := InitExchangeArtifactMaxEnvelope(1024); err == nil {
		t.Fatal("InitExchangeArtifactMaxEnvelope accepted a sub-floor value")
	}
	if got := exchangeartifact.MaxEnvelope(); got != 512<<20 {
		t.Fatalf("rejected init changed MaxEnvelope to %d, want %d", got, 512<<20)
	}

	// The r2 overflow guard at the seam: MaxInt-1024 was historically
	// accepted and overflowed the base64 expansion of the ciphertext bound
	// negative; it (and anything beyond MaxSettableEnvelope) must be refused
	// fail-closed here too, without disturbing the effective ceiling.
	if err := InitExchangeArtifactMaxEnvelope(math.MaxInt - 1024); err == nil {
		t.Fatal("InitExchangeArtifactMaxEnvelope accepted MaxInt-1024; want overflow-guard refusal")
	}
	if err := InitExchangeArtifactMaxEnvelope(exchangeartifact.MaxSettableEnvelope + 1); err == nil {
		t.Fatal("InitExchangeArtifactMaxEnvelope accepted MaxSettableEnvelope+1; want refusal")
	}
	if got := exchangeartifact.MaxEnvelope(); got != 512<<20 {
		t.Fatalf("overflow-guard refusals changed MaxEnvelope to %d, want %d", got, 512<<20)
	}

	// The overflow-safe edge itself is accepted by the seam.
	if err := InitExchangeArtifactMaxEnvelope(exchangeartifact.MaxSettableEnvelope); err != nil {
		t.Fatalf("InitExchangeArtifactMaxEnvelope(MaxSettableEnvelope): %v", err)
	}
	if got := exchangeartifact.MaxEnvelope(); got != exchangeartifact.MaxSettableEnvelope {
		t.Fatalf("edge init left MaxEnvelope = %d, want %d", got, exchangeartifact.MaxSettableEnvelope)
	}
}
