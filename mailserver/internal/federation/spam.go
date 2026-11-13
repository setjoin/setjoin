package federation

import (
	"encoding/json"
	"strings"

	"setjoin.com/shared/spam"
)

// chatStanzaBody is the ONE field spamScanChatBody needs out of a chat
// stanza's payload (federation_apply_chat.sql's own jsonb shape — see
// that file's header) — decoded once here rather than threading the full
// msgEnvelope through.
type chatStanzaBody struct {
	Body string `json:"body"`
}

// spamScanChatBody runs shared/spam's TEXT-APPLICABLE detectors (the #A5
// email-spam engine, ml_detectors.go's established call pattern — see
// mailserver/internal/smtp/ml_detectors.go's detectorSignal) against one
// decoded, plaintext federated chat DM body and returns a quarantine
// verdict + a short machine-readable reason. Reuse, not rebuild (Task 4B):
//
//   - DetectMixedCharset — mixed-script body evasion, a classic
//     spam/phishing signal, applicable to any plaintext.
//   - DetectFakeHTML — hidden-text CSS concealment tricks (font-size:0,
//     display:none, offscreen positioning, …). Gated on the body actually
//     containing a '<' — a chat body is markdown/plaintext, not MIME HTML,
//     so most messages never even reach the regex scan; a message that DOES
//     embed raw HTML is exactly the case the plan calls out ("if the body
//     contains HTML").
//
// Deliberately NOT wired: DetectForgedRecipients, DetectSenderMismatch,
// VerifyContentType, DetectEncryptedArchive, the spamtrap store — all
// SMTP-envelope/MIME-shaped, with no analogue in a plaintext chat DM (see
// the plan's Task 4B "Reuse, do NOT rebuild" note). No new dependency, no
// parallel classifier — this composes shared/spam's existing exported
// entrypoints only.
func spamScanChatBody(body string) (quarantined bool, reason string) {
	var reasons []string

	if mixed, _ := spam.DetectMixedCharset(body); mixed {
		reasons = append(reasons, "mixed-charset")
	}

	if strings.Contains(body, "<") {
		if fake, patterns := spam.DetectFakeHTML(body); fake {
			reasons = append(reasons, patterns...)
		}
	}

	if len(reasons) == 0 {
		return false, ""
	}
	return true, strings.Join(reasons, ",")
}

// decodeChatBody best-effort-decodes a stanza payload's body field for the
// spam scan. A malformed/missing body just yields "" here — that is NOT an
// error for this scan's purposes: federation_apply_chat's own trust
// validation (federation_apply_chat.sql) is what poisons a genuinely
// malformed stanza; this scan is orthogonal (Task 4B) and never blocks or
// alters the apply/poison/dedup outcome.
func decodeChatBody(payload json.RawMessage) string {
	var s chatStanzaBody
	_ = json.Unmarshal(payload, &s)
	return s.Body
}
