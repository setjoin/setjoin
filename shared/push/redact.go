package push

// redact.go implements the D-SHARED-PUSH-001 control (INV3-TOKEN-SECRECY /
// INV4-NO-SECRETS-IN-LOGS): provider transport failures surface as net/http
// *url.Error strings that embed the full request URL — the APNs device token
// IS the URL path, a Web Push endpoint is itself a bearer-capability URL, and
// FCM/HMS paths carry project/app identifiers. Every Dispatcher.Send error
// text flows verbatim into the caller sinks (the worker Warn logs,
// sendOutcome.lastErr, the push_intents and chat_push_intents last_error
// columns, authserver dispatch logs), so the redaction wrapper is applied
// HERE at the transport seam — before every sink — and the sinks keep
// consuming plain err.Error() text unchanged.

import (
	"net/url"
	"regexp"
	"strings"
)

// redactedURLMarker replaces everything past the authority of a provider URL.
const redactedURLMarker = "[redacted]"

// absoluteURLInText matches an absolute http(s) URL embedded in provider error
// text, covering provider libraries that format URLs directly into messages
// instead of returning a structured *url.Error.
var absoluteURLInText = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>]+`)

// redactedError wraps a provider-transport error: msg is the scrubbed text
// every sink (log line, in-memory lastErr, persisted last_error column) sees;
// cause is retained only so errors.Is classification keeps working. Sinks must
// render the error via Error() — formatting the unwrap chain directly would
// bypass the scrub.
type redactedError struct {
	msg   string
	cause error
}

func (e *redactedError) Error() string { return e.msg }

func (e *redactedError) Unwrap() error { return e.cause }

// redactProviderError returns err with every absolute http(s) URL in its text
// reduced to scheme://host/[redacted]: path, query and fragment can carry
// bearer material, while the host is what identifies the failing provider to
// an operator. Transport errors never wrap ErrUnregistered (that comes from
// response-status branches, which are not wrapped here), so pruning and retry
// classification are unchanged. nil passes through.
func redactProviderError(err error) error {
	if err == nil {
		return nil
	}
	return &redactedError{msg: scrubText(err.Error()), cause: err}
}

// redactURL reduces a request URL to scheme://host/[redacted]; anything that
// does not parse as an absolute URL is redacted wholesale.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return redactedURLMarker
	}
	return u.Scheme + "://" + u.Host + "/" + redactedURLMarker
}

// scrubText redacts every absolute URL in an error message, preserving any
// trailing punctuation that belongs to the sentence rather than the URL.
func scrubText(msg string) string {
	return absoluteURLInText.ReplaceAllStringFunc(msg, func(m string) string {
		trimmed := strings.TrimRight(m, ".,;:!?)]}")
		return redactURL(trimmed) + m[len(trimmed):]
	})
}
