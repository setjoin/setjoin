package smtp

import (
	"net/mail"

	"setjoin.com/shared/spam"
	"setjoin.com/shared/toggle"
)

// applyMLDetectorSignal is the sole call site for the shared/spam detector
// suite (arch review #A5). It is a no-op unless feature.spam_ml_detectors is
// on (toggle.FeatureSpamMLDetectors, DEFAULT OFF, V137) — the single gate
// that keeps the live scoring path byte-for-byte unchanged while the toggle
// stays off. When on, it folds detectorSignal's output into spamResult as
// ADDITIVE signal, alongside (never replacing) the RBL/heuristic score and
// the per-user FTRL score computed elsewhere in deliver().
func applyMLDetectorSignal(toggles *toggle.FeatureFlags, spamResult *AntiSpamResult, smtpFrom, headerFrom string, smtpRcpts []string, rawTo, rawCc, bodyText, bodyHTML string, spfPassed, dkimPassed bool) {
	if !toggles.IsEnabled(toggle.FeatureSpamMLDetectors) {
		return
	}
	score, symbols := detectorSignal(smtpFrom, headerFrom, smtpRcpts, rawTo, rawCc, bodyText, bodyHTML, spfPassed, dkimPassed)
	spamResult.DetectorScore = score
	spamResult.Score += score
	spamResult.Symbols = append(spamResult.Symbols, symbols...)
}

// detectorSignal runs the shared/spam deterministic-detector suite over data
// already resolved earlier in deliver() and returns an ADDITIVE score plus
// the symbols that fired. The sole caller (deliver()) gates every call on
// toggle.FeatureSpamMLDetectors (DEFAULT OFF) — this function is otherwise
// never invoked, so the toggle being off leaves the live scoring path
// byte-for-byte what it is today.
//
// Wired (pure, deterministic, need only data deliver() already has in hand):
//   - sender_mismatch.go DetectSenderMismatch — envelope-From vs header-From
//   - forged.go          DetectForgedRecipients — SMTP RCPT TO vs MIME To/Cc
//   - charset.go         DetectMixedCharset — mixed-script body evasion
//   - fakehtml.go        DetectFakeHTMLScore — hidden-text CSS phishing tricks
//
// Gated out — each needs infra this pass does not build (see
// mailserver/internal/AGENTS.md "Spam scoring"):
//   - archive.go DetectEncryptedArchive/DetectPasswordInBody — needs decoded
//     PER-ATTACHMENT bytes; the delivery path only regex-scans Content-Type
//     header strings (helpers.go detectAttachmentTypes), it never extracts
//     attachment payload bytes. DetectPasswordInBody alone (no archive
//     signal to pair with) is a much weaker, higher-false-positive signal
//     than the design intended, so it stays out rather than being wired
//     half-built.
//   - content_verify.go VerifyContentType — same missing attachment-byte
//     extraction as archive.go.
//   - htmlstruct.go IsKnownPhishing — needs a maintained phishing-template
//     hash feed; none exists (spam-enhancement.md's "ship with 50 known
//     templates" was never built).
//   - imagehash.go — needs image decode plus a known-spam-image-hash cache
//     (Redis/in-memory); neither exists.
//   - spamtrap.go — needs an admin-configured spamtrap address list
//     (mailctl commands, config storage); none exists.
//   - tokenizer.go/multiclass.go MultiClassFTRL — a second trained
//     classifier needs its own model store/training pipeline (the
//     internal/spam PGModelStore shape, duplicated); an untrained model's
//     sigmoid(0)=0.5 output is noise, not signal — wiring it live would be
//     the opposite of "zero false-positive risk".
//   - composites.go EvalComposites — needs a YAML rule file
//     (spam_rules.yaml) that was never built.
func detectorSignal(smtpFrom, headerFrom string, smtpRcpts []string, rawTo, rawCc, bodyText, bodyHTML string, spfPassed, dkimPassed bool) (float64, []string) {
	var score float64
	var symbols []string

	if mismatch, s := spam.DetectSenderMismatch(smtpFrom, headerFrom, spfPassed, dkimPassed); mismatch {
		score += s
		symbols = append(symbols, "ML_SENDER_MISMATCH")
	}

	if forged, s := spam.DetectForgedRecipients(smtpRcpts, addrList(rawTo), addrList(rawCc)); forged {
		score += s
		symbols = append(symbols, "ML_FORGED_RECIPIENTS")
	}

	if mixed, s := spam.DetectMixedCharset(bodyText); mixed {
		score += s
		symbols = append(symbols, "ML_MIXED_CHARSET")
	}

	if s := spam.DetectFakeHTMLScore(bodyHTML); s > 0 {
		score += s
		symbols = append(symbols, "ML_FAKE_HTML")
	}

	return score, symbols
}

// addrList parses an RFC 5322 address-list header value into plain email
// addresses. A malformed or empty header yields no addresses (fail open —
// DetectForgedRecipients already treats an empty header address set as
// legitimate BCC-only mail, so this never manufactures a false signal).
func addrList(header string) []string {
	if header == "" {
		return nil
	}
	addrs, err := mail.ParseAddressList(header)
	if err != nil {
		return nil
	}
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.Address
	}
	return out
}
