// redact.go — secret redaction for the deploy wizard's error, log, and
// persistence surfaces (D-MAILSERVER-INTERNAL-DEPLOY-R-001).
//
// Raw SSH remote output previously flowed unredacted into step errors, log
// lines, and the persisted deployment_steps rows: a remote host that echoes a
// heredoc payload, an OpenSSH banner echoing a failed pubkey blob, or any
// verbose shell output carrying the inline private key or the generated pgpool
// health-check password would retain that secret material in memory, logs, and
// the database indefinitely. Every carrier now passes through RedactOutput
// before it leaves the SSH layer, and persistStep/loadState scrub again at the
// persistence boundary as defense in depth.
package deploy

import (
	"regexp"
	"sort"
	"strings"
)

const (
	// redactionSentinel replaces secret material in any output that reaches
	// errors, log lines, or persisted deployment_steps rows.
	redactionSentinel = "[REDACTED]"
	// maxRedactedOutput bounds how much remote output is kept in memory, in
	// logs, and in the deployment_steps table. Raw output is not length-bounded
	// anywhere today; the bound caps the retained-secret surface.
	maxRedactedOutput = 4096
	// withheldRestoreNote replaces the free-form Output/Error body of steps
	// restored from deployment_steps on startup. The wizard holds no node
	// credentials at restore time (NodeConfig is never persisted), so a bare
	// password in a row written before redaction landed cannot be exact-matched
	// — the body is unverifiable and is withheld until scrubbed or reconciled
	// on the target host. Step name/status metadata is retained.
	withheldRestoreNote = "[withheld: persisted step detail removed at restore — pre-redaction rows cannot be verified secret-free; reconcile on the target host]"
)

var (
	// privateKeyBlockRe matches a PEM private-key block (OPENSSH, RSA, EC,
	// PKCS8, ...), including an unterminated BEGIN block at end of output.
	privateKeyBlockRe = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|$)`)
	// pgpoolPasswordLineRe matches the health_check_password assignment inside
	// an echoed pgpool.conf. The generated password is the value between the
	// single quotes; the quoting structure is preserved.
	pgpoolPasswordLineRe = regexp.MustCompile(`(?i)(health_check_password\s*=\s*')[^']*(')`)
)

// RedactOutput scrubs secret material out of remote command output before it
// reaches any error, log line, or persisted step row. extraSecrets are exact
// secret byte strings known to the caller (e.g. the generated pgpool
// health-check password) and are replaced wherever they occur.
//
// Ordering contract: structural redaction runs BEFORE exact replacements. An
// exact replacement can destroy the delimiters structural patterns anchor on —
// e.g. an extra secret equal to "PRIVATE" rewrites a PEM header so
// privateKeyBlockRe no longer matches and the whole key body survives. The
// structural pass removes patterned material first; the exact pass then scrubs
// whatever remains in a single union-of-intervals pass.
func RedactOutput(output string, extraSecrets ...string) string {
	output = privateKeyBlockRe.ReplaceAllString(output, redactionSentinel)
	output = pgpoolPasswordLineRe.ReplaceAllString(output, "${1}"+redactionSentinel+"${2}")
	output = replaceExactSecrets(output, extraSecrets)
	if len(output) > maxRedactedOutput {
		output = output[:maxRedactedOutput] + "\n...[truncated]"
	}
	return output
}

// replaceExactSecrets replaces every occurrence of any exact secret in a
// single union-of-intervals pass over the original text. A combined
// alternation regex alone is NOT sufficient: regex replacement consumes only
// NONOVERLAPPING leftmost matches, so SHIFTED overlaps leak secret tails —
// for secrets "ABCDEF" and "DEFSECRET" against output "ABCDEFSECRET", the
// regex matches only [0,6) and ReplaceAllLiteralString yields
// "[REDACTED]SECRET", leaving the suffix of DEFSECRET behind. Instead, every
// secret is scanned for ALL of its occurrences, the match intervals are merged
// into their union (overlapping AND adjacent intervals coalesce into one
// sentinel), and the union is spliced over the original text — no partial
// region between two overlapping matches can survive.
func replaceExactSecrets(output string, secrets []string) string {
	type interval struct{ start, end int }
	var ivs []interval
	for _, s := range secrets {
		if s == "" {
			continue
		}
		for from := 0; ; {
			i := strings.Index(output[from:], s)
			if i < 0 {
				break
			}
			start := from + i
			ivs = append(ivs, interval{start: start, end: start + len(s)})
			from = start + 1
		}
	}
	if len(ivs) == 0 {
		return output
	}
	sort.Slice(ivs, func(i, j int) bool { return ivs[i].start < ivs[j].start })
	merged := make([]interval, 0, len(ivs))
	for _, iv := range ivs {
		if n := len(merged); n > 0 && iv.start <= merged[n-1].end {
			if iv.end > merged[n-1].end {
				merged[n-1].end = iv.end
			}
			continue
		}
		merged = append(merged, iv)
	}
	var b strings.Builder
	b.Grow(len(output) + len(merged)*(len(redactionSentinel)-1))
	pos := 0
	for _, iv := range merged {
		b.WriteString(output[pos:iv.start])
		b.WriteString(redactionSentinel)
		pos = iv.end
	}
	b.WriteString(output[pos:])
	return b.String()
}

// redactDeploymentStep prepares a step restored from deployment_steps for the
// read surface. Rows written before redaction landed may still carry secret
// material, and at restore time the wizard holds no node credentials
// (NodeConfig is never persisted), so bare secrets cannot be exact-matched —
// only structural patterns are detectable. Structural redaction runs first,
// then the remaining free-form Output/Error body is WITHHELD: it cannot be
// verified secret-free, so it is replaced with withheldRestoreNote until
// scrubbed or reconciled. Step name and status metadata are retained so the
// status surface still shows what ran and how it ended.
func redactDeploymentStep(step DeploymentStep) DeploymentStep {
	step.Output = RedactOutput(step.Output)
	step.Error = RedactOutput(step.Error)
	if step.Output != "" {
		step.Output = withheldRestoreNote
	}
	if step.Error != "" {
		step.Error = withheldRestoreNote
	}
	return step
}

// knownSecrets returns the exact secret strings the wizard currently holds for
// its nodes — inline SSH private-key bodies and node passwords. They are
// scrubbed from every carrier (step errors, log lines, persisted rows) so
// caller-known secrets cannot survive even where no structural pattern exists.
// Call it with w.mu held (failStep/persistStep run under the wizard lock).
func (w *Wizard) knownSecrets() []string {
	if w.state == nil {
		return nil
	}
	secrets := make([]string, 0, 2*len(w.state.Nodes))
	for _, n := range w.state.Nodes {
		if isInlineKeyMaterial(n.SSHKey) {
			secrets = append(secrets, strings.TrimSpace(n.SSHKey))
		}
		if n.Password != "" {
			secrets = append(secrets, n.Password)
		}
	}
	return secrets
}

// scrubStep fully scrubs a step before it is persisted: structural redaction
// first, then every node secret the wizard holds. Called with w.mu held.
func (w *Wizard) scrubStep(step DeploymentStep) DeploymentStep {
	secrets := w.knownSecrets()
	step.Output = RedactOutput(step.Output, secrets...)
	step.Error = RedactOutput(step.Error, secrets...)
	return step
}

// isInlineKeyMaterial reports whether an SSHKey value carries inline PEM key
// bytes rather than a file path. The wizard accepts both input forms; inline
// key bodies are supported as input but are never rendered on the status
// projection.
func isInlineKeyMaterial(key string) bool {
	return strings.HasPrefix(strings.TrimSpace(key), "-----")
}
