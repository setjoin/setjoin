// Package smtp delegates to linkprotect for URL threat scanning primitives.
// The Verdict, Scanner, ScanPipeline, SpamhausDBLScanner, and SafeBrowsingScanner
// types are defined in the canonical package linkprotect; smtp re-exports them
// as type aliases so existing callers don't need import changes.
package smtp

import "setjoin.com/mailserver/internal/linkprotect"

// Verdict is a type alias for linkprotect.Verdict.
type Verdict = linkprotect.Verdict

// Scanner is a type alias for linkprotect.Scanner.
type Scanner = linkprotect.Scanner

// ScanPipeline is a type alias for linkprotect.ScanPipeline.
var ScanPipeline = linkprotect.ScanPipeline

// Verdict constants re-exported.
const (
	VerdictSafe      = linkprotect.VerdictSafe
	VerdictMalicious = linkprotect.VerdictMalicious
	VerdictUnknown   = linkprotect.VerdictUnknown
)

// SpamhausDBLScanner is a type alias for linkprotect.SpamhausDBLScanner.
type SpamhausDBLScanner = linkprotect.SpamhausDBLScanner

// SafeBrowsingScanner is a type alias for linkprotect.SafeBrowsingScanner.
type SafeBrowsingScanner = linkprotect.SafeBrowsingScanner

// NewSpamhausDBLScanner delegates to linkprotect.NewSpamhausDBLScanner.
var NewSpamhausDBLScanner = linkprotect.NewSpamhausDBLScanner

// NewSafeBrowsingScanner delegates to linkprotect.NewSafeBrowsingScanner.
var NewSafeBrowsingScanner = linkprotect.NewSafeBrowsingScanner
