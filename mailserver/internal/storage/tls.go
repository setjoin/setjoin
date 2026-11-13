package storage

import (
	"fmt"
	"net"
	"strings"
)

// Transport-TLS resolution for object-storage endpoints (D-MAILSERVER-INTERNAL-STORAGE-F-001).
//
// Historically every storage-driver construction path except the shared blob
// client hardcoded plaintext transport: the factory passed Secure=false to
// minio-go regardless of endpoint scheme, NewS3HotDriver stripped the scheme
// before it could influence the posture, and the migration SOURCE driver stayed
// plaintext even with S3_SECURE=true. A network attacker positioned between the
// server and an off-loopback object store could read/modify blob traffic with
// no authentication.
//
// ResolveEndpointTLS is the single authority every constructor now routes
// through (NewDriver, NewS3HotDriver, NewBackupS3Driver, NewOSDriver, and the
// shared blob client). Its contract is the caller/provider/operation TLS
// matrix, applied uniformly to every operation (blob hot path, drive retention,
// backup primary/replica, setup restore, WORM/legal-hold, storage migration):
//
//	https://host        → TLS. An explicit Secure=false is a rejected conflict.
//	http://host         → plaintext, but ONLY for loopback peers (the explicit
//	                      local-HTTP compatibility case: S3_ENDPOINT=127.0.0.1:9000
//	                      with S3_SECURE=false). An explicit Secure=true is a
//	                      rejected conflict. Non-loopback http:// is rejected —
//	                      plaintext to a remote peer is exactly the finding.
//	host[:port]         → scheme-less. Loopback peers default to plaintext
//	                      (deployment convention, deploy/config.env.sample);
//	                      Secure=true opts into TLS. NON-LOOPBACK peers are
//	                      REJECTED unless Secure=true is stated explicitly —
//	                      the scheme-less remote default was plaintext, which is
//	                      the fail-closed flip this package exists to make.
//	"" (empty)          → ("", true, nil). Callers decide: the AWS-default
//	                      backup path treats it as TLS-by-default AWS; minio
//	                      paths must reject the empty host themselves.
//
// An explicit *Secure pointer distinguishes "unset" (derive from scheme) from
// an explicit plaintext request (Secure=false), which is what makes the
// https-scheme + Secure=false conflict detectable. The returned host[:port] is
// scheme-stripped and ready for minio-go (which builds the scheme itself from
// its Secure option); callers that need a scheme-ful URL (OSS SDK, aws-sdk-go-v2
// BaseEndpoint) re-prefix the scheme matching the returned posture.
func ResolveEndpointTLS(endpoint string, secure *bool) (hostPort string, useTLS bool, err error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", true, nil
	}

	scheme := ""
	rest := endpoint
	lower := strings.ToLower(endpoint)
	switch {
	case strings.HasPrefix(lower, "https://"):
		scheme, rest = "https", endpoint[len("https://"):]
	case strings.HasPrefix(lower, "http://"):
		scheme, rest = "http", endpoint[len("http://"):]
	}
	if rest == "" {
		return "", false, fmt.Errorf("storage: endpoint %q has a scheme but no host", endpoint)
	}

	loopback := isLoopbackHostPort(rest)
	hostPort = rest

	switch scheme {
	case "https":
		if secure != nil && !*secure {
			return "", false, fmt.Errorf(
				"storage: endpoint %q uses the https:// scheme but Secure=false was explicitly set — "+
					"contradictory transport config, refusing (fail-closed)", endpoint)
		}
		return hostPort, true, nil
	case "http":
		if secure != nil && *secure {
			return "", false, fmt.Errorf(
				"storage: endpoint %q uses the http:// scheme but Secure=true was explicitly set — "+
					"contradictory transport config, refusing (fail-closed)", endpoint)
		}
		if !loopback {
			return "", false, fmt.Errorf(
				"storage: plaintext http:// endpoint %q targets a non-loopback peer — plaintext blob "+
					"transport off the loopback interface is not supported; use https:// (fail-closed)", endpoint)
		}
		return hostPort, false, nil
	default:
		if secure != nil && *secure {
			return hostPort, true, nil
		}
		if loopback {
			// Explicit local-HTTP compatibility case: the deployed convention
			// (S3_ENDPOINT=127.0.0.1:9000, S3_SECURE=false) is loopback plaintext,
			// which never crosses a network an attacker can observe.
			return hostPort, false, nil
		}
		return "", false, fmt.Errorf(
			"storage: scheme-less endpoint %q would default to PLAINTEXT transport — set S3_SECURE=true "+
				"or use an explicit https:// endpoint (http:// is loopback-only); refusing the insecure "+
				"default (fail-closed)", endpoint)
	}
}

// isLoopbackHostPort reports whether host[:port] (or [v6]:port) addresses a
// loopback peer: the "localhost" name, 127.0.0.0/8, or ::1. Anything that is
// not provably loopback is treated as remote (fail-closed).
func isLoopbackHostPort(hostPort string) bool {
	host := hostPort
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// TLSScheme returns the URL scheme matching a resolved posture, for callers
// that must hand a scheme-ful endpoint to an SDK (OSS, aws-sdk-go-v2).
func TLSScheme(useTLS bool) string {
	if useTLS {
		return "https"
	}
	return "http"
}
