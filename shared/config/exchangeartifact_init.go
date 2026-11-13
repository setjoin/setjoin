package config

import (
	"setjoin.com/shared/exchangeartifact"
)

// InitExchangeArtifactMaxEnvelope is the one place a service syncs the
// configured artifact envelope ceiling into the exchangeartifact process
// global, mirroring the InitCryptoProfile config→package-global seam.
//
// limitBytes == 0 means "not configured" and re-applies the shipped
// DefaultMaxEnvelope (1 GiB), so a config reload that drops the key converges
// back to the default instead of keeping a stale ceiling. Configured values go
// through exchangeartifact.SetMaxEnvelope's validation (positive, >=
// exchangeartifact.MinMaxEnvelope, <= exchangeartifact.MaxSettableEnvelope so
// the full downstream bound arithmetic stays overflow-safe), so an invalid
// value that somehow bypassed ValidateBase is still refused here fail-closed.
// Malformed (unparseable) values never reach this seam: ValidateBase refuses
// them from the raw string that parse/merge preserved.
//
// Call this once at startup after config load. Without it the
// exchangeartifact global stays at its shipped 1 GiB default regardless of
// EXCHANGEARTIFACT_MAX_ENVELOPE.
func InitExchangeArtifactMaxEnvelope(limitBytes int) error {
	if limitBytes == 0 {
		return exchangeartifact.SetMaxEnvelope(exchangeartifact.DefaultMaxEnvelope)
	}
	return exchangeartifact.SetMaxEnvelope(int64(limitBytes))
}
