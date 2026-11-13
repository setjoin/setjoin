//go:build gofree_record

package smtp

// Recorder-only HTTP transport. The overlay substitutes this factory at the
// existing client-creation boundary; the shipped mtasts.go remains unchanged.
import "setjoin.com/shared/ssrf"

var smtpTransportHTTPClient = ssrf.SafeHTTPClient
