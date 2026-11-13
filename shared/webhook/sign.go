package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// MinSecretLen is the minimum signing-secret length Sign accepts. Both secret
// minting paths generate server-side high-entropy secrets at this size; the
// bound here is the fail-closed guard for future callers and hand-edited
// configuration — an empty or guessable key must never silently sign.
const MinSecretLen = 32

// Sign creates the Setjoin webhook signature header:
//
//	v1,t=<unix_timestamp>,sig=<hex_hmac_sha256(timestamp "." body)>
//
// SCHEME NOTE (D-SHARED-WEBHOOK-001): despite the historical doc comment, this
// is NOT the Standard Webhooks v1 wire format. Divergences a conformant
// Standard Webhooks receiver would reject (fail-closed on their side):
//   - the MAC input omits the Standard Webhooks msg_id prefix (it covers only
//     "<timestamp>.<body>"; receivers wanting delivery-identity binding must
//     authenticate the CloudEvent id inside the signed body bytes separately);
//   - id and timestamp ride inside this single header (v1,t=...,sig=...) rather
//     than the separate webhook-id / webhook-timestamp headers;
//   - the MAC is hex-encoded, not base64.
//
// The signature is cryptographically sound on its own terms (HMAC-SHA256 with a
// per-subscription secret and a fresh timestamp), but custom receivers must
// verify THIS scheme; do not advertise it as Standard Webhooks compatible.
//
// A secret shorter than MinSecretLen is rejected (fail-closed): signing with an
// empty or guessable key would mint headers any attacker could forge.
func Sign(body []byte, secret string) (string, error) {
	if len(secret) < MinSecretLen {
		return "", fmt.Errorf("webhook: signing secret must be at least %d bytes (got %d)", MinSecretLen, len(secret))
	}
	ts := time.Now().Unix()
	signed := fmt.Sprintf("%d.%s", ts, string(body))

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signed))
	sig := hex.EncodeToString(mac.Sum(nil))

	return fmt.Sprintf("v1,t=%d,sig=%s", ts, sig), nil
}
