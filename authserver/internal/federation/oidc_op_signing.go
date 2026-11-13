package federation

import (
	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// oidcSigningAdapter adapts the RS256 OIDCKeyManager to the signing/key portion
// of zitadel's op.Storage (Wave 3 split of the OPStorage god-object). It is the
// one place the OP's key material is surfaced, keeping the signing concern out
// of the storage god-object. This is the OIDC OP's own RS256 key
// (OIDC_PROVIDER_PRIVATE_KEY_FILE) — distinct from the ADR-005 first-party ES256
// keystore, which it does not touch.
type oidcSigningAdapter struct {
	keyMgr *OIDCKeyManager
}

func newOIDCSigningAdapter(keyMgr *OIDCKeyManager) *oidcSigningAdapter {
	return &oidcSigningAdapter{keyMgr: keyMgr}
}

func (a *oidcSigningAdapter) signingKey() op.SigningKey {
	return a.keyMgr.SigningKey()
}

func (a *oidcSigningAdapter) signatureAlgorithms() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{jose.RS256}
}

func (a *oidcSigningAdapter) keySet() []op.Key {
	return []op.Key{a.keyMgr.PublicKey()}
}
