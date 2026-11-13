// Package smtp — Advanced Anti-Phishing (Roadmap 2.4)
//
// Three independent detectors evaluated during SMTP inbound delivery:
//  1. Display-name spoofing (fuzzy match against internal user names)
//  2. Lookalike domain detection (homoglyph analysis via Unicode confusables)
//  3. Contact-graph impersonation (novel sender with known display name)
//
// Architecture: pluggable PhishDetector pipeline. Each detector returns a
// PhishVerdict plus evidence symbols. The pipeline aggregates: first Reject
// short-circuits; highest severity wins. Each detector is independently
// toggleable. Unicode homoglyph table compiled at build time from UTR #39.
package smtp

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/config"
	"setjoin.com/mailserver/internal/mimeutil"
	"setjoin.com/shared/toggle"
)

// ErrAntiPhishReject is returned by deliver() when anti-phishing policy
// rejects the message. The caller must reply 550 to the SMTP client.
var ErrAntiPhishReject = errors.New("smtp: message rejected per anti-phishing policy")

// PhishVerdict is the severity level of an anti-phishing detection.
type PhishVerdict int

const (
	PhishNone   PhishVerdict = iota // no detection
	PhishWarn                       // append warning banner + header
	PhishReject                     // reject delivery (550)
)

// String returns the X-AntiPhish header value for this verdict.
func (v PhishVerdict) String() string {
	switch v {
	case PhishWarn:
		return "warn"
	case PhishReject:
		return "reject"
	default:
		return "none"
	}
}

// PhishInput carries the parsed sender information and recipients into
// each detector's Check method.
type PhishInput struct {
	FromName         string           // display name from From header
	FromAddr         string           // email address from From header
	ReturnPathDomain string           // domain from Return-Path (fallback: From domain)
	Recipients       []PhishRecipient // resolved recipients
}

// PhishRecipient identifies a delivery target for contact-graph queries.
type PhishRecipient struct {
	MailboxID int64  // resolved mailbox ID
	Email     string // recipient email address
}

// PhishResult is the output of a single detector check.
type PhishResult struct {
	Verdict  PhishVerdict // severity for this detector
	Detector string       // detector name
	Evidence []string     // human-readable evidence symbols
}

// PhishDetector is the interface for all anti-phishing checkers.
type PhishDetector interface {
	// Name returns a short identifier for this detector (e.g. "display_name").
	Name() string

	// Check evaluates the message against this detector's rules.
	// Returns nil if the detector is not applicable or encounters a non-fatal error.
	Check(ctx context.Context, msg *PhishInput) (*PhishResult, error)
}

// ToggleChecker is the subset of toggle.FeatureFlags used by the anti-phish pipeline.
// This interface enables testing without a database connection.
type ToggleChecker interface {
	IsEnabled(key string) bool
}

// RunPhishPipeline evaluates all enabled detectors against the input.
// First Reject short-circuits. Errors are logged and the detector is skipped
// (fail-open: we never block delivery because of a detector error).
// Returns the aggregate verdict and all evidence from triggered detectors.
func RunPhishPipeline(ctx context.Context, detectors []PhishDetector, toggles ToggleChecker, msg *PhishInput) (PhishVerdict, []string) {
	highest := PhishNone
	var evidence []string

	for _, d := range detectors {
		// Determine toggle key from detector name
		toggleKey := toggleKeyForDetector(d.Name())
		if toggleKey != "" && !toggles.IsEnabled(toggleKey) {
			continue
		}

		result, err := d.Check(ctx, msg)
		if err != nil {
			slog.Warn("antiphish: detector error, skipping (fail-open)",
				"detector", d.Name(), "error", err)
			continue
		}
		if result == nil {
			continue
		}

		// Aggregate evidence
		evidence = append(evidence, result.Evidence...)

		// Reject short-circuits
		if result.Verdict == PhishReject {
			if toggles.IsEnabled(toggle.FeatureAntiphishStrictMode) {
				evidence = append(evidence, "strict_mode:reject")
			}
			return PhishReject, evidence
		}

		if result.Verdict > highest {
			highest = result.Verdict
		}
	}

	// In strict mode, upgrade Warn to Reject
	if highest == PhishWarn && toggles.IsEnabled(toggle.FeatureAntiphishStrictMode) {
		evidence = append(evidence, "strict_mode:upgraded_warn_to_reject")
		return PhishReject, evidence
	}

	return highest, evidence
}

// toggleKeyForDetector maps detector names to feature toggle constants.
func toggleKeyForDetector(name string) string {
	switch name {
	case "display_name":
		return toggle.FeatureAntiphishDisplayName
	case "lookalike":
		return toggle.FeatureAntiphishLookalike
	case "contact_graph":
		return toggle.FeatureAntiphishContactGraph
	default:
		return ""
	}
}

// InjectAntiPhishHeaders prepends an X-AntiPhish header and optionally appends
// a safety banner to text/plain and text/html MIME parts.
//
// The header format is: X-AntiPhish: <verdict>; <evidence1>; <evidence2>
// For Warn verdicts, a safety banner is injected into the message body.
// The banner uses the Prism orange accent (#FF9F0A) for consistency with the
// design system.
func InjectAntiPhishHeaders(data []byte, verdict PhishVerdict, evidence []string) []byte {
	if verdict == PhishNone {
		return data
	}

	headerValue := verdict.String()
	if len(evidence) > 0 {
		headerValue += "; " + strings.Join(evidence, "; ")
	}

	// Find the boundary between headers and body (first blank line).
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		// No proper header/body separation; prepend at the beginning.
		return append([]byte("X-AntiPhish: "+headerValue+"\r\n\r\n"), data...)
	}

	// Insert the X-AntiPhish header at the end of the header block.
	headerBlock := data[:headerEnd]
	bodyBlock := data[headerEnd+4:] // skip \r\n\r\n

	var buf bytes.Buffer
	buf.Write(headerBlock)
	buf.WriteString("\r\nX-AntiPhish: ")
	buf.WriteString(headerValue)

	// For Warn verdicts, inject a safety banner.
	if verdict == PhishWarn {
		buf.WriteString("\r\n")
		bodyBlock = injectSafetyBanner(bodyBlock)
	}

	buf.WriteString("\r\n\r\n")
	buf.Write(bodyBlock)

	return buf.Bytes()
}

// injectSafetyBanner prepends a warning banner to text/plain and text/html
// MIME parts within the message body.
func injectSafetyBanner(body []byte) []byte {
	banner := []byte(
		"[WARNING] This message may be an impersonation attempt. " +
			"The sender's name matches an internal contact but the email address is unfamiliar. " +
			"Do not click links or open attachments unless you verify the sender.\r\n\r\n",
	)

	// If it's a MIME multipart message, inject into each text part.
	if bytes.Contains(body, []byte("Content-Type: multipart/")) {
		ct := mimeutil.ExtractHeader(string(body), "Content-Type")
		if mimeutil.ExtractBoundary(ct) == "" {
			return append(banner, body...)
		}
		modified, err := mimeutil.WalkMIMEParts(ct, body, func(partHeaders []byte, partBody []byte) []byte {
			lower := bytes.ToLower(partHeaders)
			if bytes.Contains(lower, []byte("content-type: text/plain")) ||
				bytes.Contains(lower, []byte("content-type: text/html")) {
				return append(banner, partBody...)
			}
			return nil
		})
		if err == nil {
			return modified
		}
		// Fallback: prepend banner if WalkMIMEParts fails
	}

	// Simple single-part message: prepend the banner.
	return append(banner, body...)
}

// BuildAntiPhishDetectors constructs the anti-phishing detector pipeline.
// Each detector is independently configured; nil detectors are skipped.
func BuildAntiPhishDetectors(cfg *config.Config, pool *pgxpool.Pool, featureToggles *toggle.FeatureFlags) []PhishDetector {
	var detectors []PhishDetector

	// Display-name spoofing detector
	if featureToggles.IsEnabled(toggle.FeatureAntiphishDisplayName) {
		internalDomains := strings.Split(cfg.InternalDomains, ",")
		for i := range internalDomains {
			internalDomains[i] = strings.TrimSpace(internalDomains[i])
		}
		cacheTTL, _ := time.ParseDuration(cfg.AntiphishUserCacheTTL)
		if cacheTTL <= 0 {
			cacheTTL = 5 * time.Minute
		}
		displayDetector := NewDisplayNameDetector(DisplayNameDetectorConfig{
			Pool:            pool,
			Threshold:       cfg.AntiphishNameThreshold,
			CacheTTL:        cacheTTL,
			InternalDomains: internalDomains,
		})
		detectors = append(detectors, displayDetector)
	}

	// Lookalike domain detector
	if featureToggles.IsEnabled(toggle.FeatureAntiphishLookalike) {
		var protectedDomains []string
		if cfg.ProtectedDomains != "" {
			protectedDomains = strings.Split(cfg.ProtectedDomains, ",")
			for i := range protectedDomains {
				protectedDomains[i] = strings.TrimSpace(protectedDomains[i])
			}
		}
		lookalikeDetector := NewLookalikeDetector(protectedDomains)
		detectors = append(detectors, lookalikeDetector)
	}

	// Contact graph impersonation detector
	if featureToggles.IsEnabled(toggle.FeatureAntiphishContactGraph) {
		contactDetector := NewContactGraphDetector(pool)
		detectors = append(detectors, contactDetector)
	}

	return detectors
}
