package linkprotect

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/toggle"
)

// LinkProtectHandler handles GET /link-protect?token=... requests.
// At click time, it verifies the HMAC-signed token, runs the scanner
// pipeline against the original URL, and returns either a 302 redirect
// (safe), a block interstitial (malicious), or a warn interstitial
// (unknown) with a "Continue" button.
type LinkProtectHandler struct {
	scanners []Scanner
	pool     *pgxpool.Pool
	logger   *slog.Logger
	toggles  *toggle.FeatureFlags
	// keys is the versioned key set used to verify click-time tokens
	// (MAILSERVERD-004 dual-key overlap rotation). The constructor seeds it
	// with the single version-1 key set derived from the configured master
	// secret — byte-identical to the pre-rotation behavior — so an unwired
	// handler rotates nothing. Replaced via SetTokenKeys at startup wiring.
	keys TokenKeys
}

// NewLinkProtectHandler creates a link protect click handler.
func NewLinkProtectHandler(scanners []Scanner, pool *pgxpool.Pool, logger *slog.Logger, toggles *toggle.FeatureFlags, secret []byte) *LinkProtectHandler {
	return &LinkProtectHandler{
		scanners: scanners,
		pool:     pool,
		logger:   logger,
		toggles:  toggles,
		keys:     TokenKeys{Secret: secret},
	}
}

// SetTokenKeys installs the versioned key set for click-time token
// verification (MAILSERVERD-004 dual-key overlap rotation): tokens signed
// under the current key verify first, and — while a PreviousSecret is
// configured — tokens already delivered in live mail under the retiring key
// keep verifying for their 30-day lifetime. Draining (a key set without
// PreviousSecret) ends the window and old-key tokens are rejected again.
//
// Startup wiring: call before the handler begins serving (the field is not
// synchronized). The constructor default needs no call — behavior is OFF
// until the config keys are explicitly wired.
func (h *LinkProtectHandler) SetTokenKeys(keys TokenKeys) {
	h.keys = keys
}

// ServeHTTP handles the link-protect click request.
func (h *LinkProtectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tokenStr := r.URL.Query().Get("token")
	if tokenStr == "" {
		http.Error(w, "link_protect: missing token", http.StatusBadRequest)
		return
	}

	// Rotation-aware verification (MAILSERVERD-004): the normalized key set
	// tries the current key first, then the retiring key during the overlap
	// window. With the constructor default this is byte-identical to the
	// pre-rotation single-key verify.
	claims, err := VerifyTokenN(tokenStr, h.keys)
	if err != nil {
		h.logger.Warn("link_protect: token verification failed", "error", err)
		http.Error(w, "link_protect: invalid or expired token", http.StatusBadRequest)
		return
	}

	// Run the scanner pipeline (third-party HTTP — stays in Go).
	verdict, scannerResults, allErrors := ScanPipeline(r.Context(), h.scanners, claims.URL)
	strict := h.toggles != nil && h.toggles.IsEnabled(toggle.FeatureLinkProtectStrictMode)

	// The verdict rules (all-errors passthrough; strict_mode unknown→malicious) AND
	// the audit insert now happen together in the link_protect_check_and_audit
	// reducer, so the audit row is durable in the SAME transaction BEFORE we decide
	// to redirect. FAIL-CLOSED: if the reducer/audit fails we show the warn
	// interstitial rather than silently redirecting (the old best-effort path is
	// gone — a redirect-without-audit was the integrity gap this closes).
	final, err := h.decideAndAudit(r.Context(), claims, verdict, scannerResults, allErrors, strict, httputil.ClientIP(r))
	if err != nil {
		h.logger.Error("link_protect: decide+audit failed (fail-closed to warn)", "error", err)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(warnInterstitialHTML(claims.URL, tokenStr)))
		return
	}

	serveFinalVerdict(w, r, final, claims, tokenStr)
}

// serveFinalVerdict renders the click outcome for a reducer-CONFIRMED verdict
// ("safe" | "malicious" | "unknown"). It is only reachable after decideAndAudit
// succeeded, i.e. a durable audit row exists — the aggregate contract: a 302
// redirect is emitted ONLY for a confirmed Safe verdict, or for an explicit
// confirm=1 continue on an Unknown verdict; any Malicious verdict blocks
// regardless of other scanners' results (Spamhaus-Safe alone never implies a
// redirect). A failed audit never reaches this switch: the handler fails
// closed to the warn interstitial before it.
func serveFinalVerdict(w http.ResponseWriter, r *http.Request, final string, claims *TokenClaims, tokenStr string) {
	switch final {
	case "safe":
		//nolint:gosec // G710 false positive: claims.URL is the HMAC-verified destination from the token, and redirecting to it after scanner adjudication IS the link-protect product (time-of-click protection).
		http.Redirect(w, r, claims.URL, http.StatusFound)

	case "malicious":
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(blockInterstitialHTML(claims.URL)))

	default: // "unknown"
		if r.URL.Query().Get("confirm") == "1" {
			w.Header().Set("X-LinkProtect-Confirmed", "1")
			//nolint:gosec // G710 false positive: same verified destination, explicit confirm=1 continue on an Unknown verdict.
			http.Redirect(w, r, claims.URL, http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(warnInterstitialHTML(claims.URL, tokenStr)))
	}
}

// decideAndAudit applies the verdict rules and writes the audit row in ONE
// transaction via the link_protect_check_and_audit reducer, returning the final
// verdict string ("safe" | "malicious" | "unknown"). The audit FKs (message_id,
// mailbox_id) come from the VERIFIED token claims, never request input. A non-nil
// error means no durable audit row exists → the caller fails closed to warn.
func (h *LinkProtectHandler) decideAndAudit(ctx context.Context, claims *TokenClaims, base Verdict, scannerResults map[string]Verdict, allErrors, strict bool, ip string) (string, error) {
	if h.pool == nil {
		return "", fmt.Errorf("link_protect: no database pool configured")
	}

	scanners := make(map[string]string, len(scannerResults))
	for name, v := range scannerResults {
		scanners[name] = v.String()
	}
	scannerJSON, _ := json.Marshal(scanners)

	// claims.MessageID is the RFC Message-ID header string (minted at sign time
	// from the inbound headers). The reducer resolves it to the numeric
	// messages.id, scoped to the verified mailbox, for the audit FK (NULL when no
	// row matches — message deleted or cross-mailbox); the audit row still records
	// mailbox_id, verdict, url_hash, and client_ip.
	var out []byte
	if err := h.pool.QueryRow(ctx,
		`SELECT link_protect_check_and_audit($1,$2,$3,$4,$5,$6,$7,$8)`,
		claims.URL, claims.MessageID, claims.MailboxID, base.String(),
		scannerJSON, allErrors, strict, ip,
	).Scan(&out); err != nil {
		return "", err
	}

	var r struct {
		Verdict string `json:"verdict"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		return "", err
	}
	return r.Verdict, nil
}

// blockInterstitialHTML returns a simple inline HTML page for blocked URLs.
func blockInterstitialHTML(originalURL string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Blocked Link</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    display: flex; align-items: center; justify-content: center;
    min-height: 100vh; background: #000; color: #f5f5f7;
  }
  .glass-pane {
    background: rgba(255,255,255,0.06); backdrop-filter: blur(40px);
    border: 1px solid rgba(255,255,255,0.08); border-radius: 20px;
    padding: 48px; max-width: 520px; text-align: center;
  }
  .icon { font-size: 48px; margin-bottom: 20px; }
  h1 { font-size: 20px; font-weight: 600; margin-bottom: 12px; color: #BF5AF2; }
  p { font-size: 14px; line-height: 1.6; color: #98989d; margin-bottom: 24px; }
  .url-box {
    background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.06);
    border-radius: 10px; padding: 12px 16px; font-size: 12px;
    word-break: break-all; color: #6e6e73; margin-bottom: 20px;
    font-family: 'JetBrains Mono', 'SF Mono', monospace;
  }
</style>
</head>
<body>
<div class="glass-pane">
  <div class="icon">&#x1F6AB;</div>
  <h1>This link has been blocked</h1>
  <p>The destination was flagged as malicious by our security systems. Your account and data have not been compromised.</p>
  <div class="url-box">%s</div>
</div>
</body>
</html>`, escapeHTML(originalURL))
}

// warnInterstitialHTML returns an inline HTML page warning about an unknown URL.
func warnInterstitialHTML(originalURL string, tokenStr string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Warning — Unverified Link</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    display: flex; align-items: center; justify-content: center;
    min-height: 100vh; background: #000; color: #f5f5f7;
  }
  .glass-pane {
    background: rgba(255,255,255,0.06); backdrop-filter: blur(40px);
    border: 1px solid rgba(255,255,255,0.08); border-radius: 20px;
    padding: 48px; max-width: 520px; text-align: center;
  }
  .icon { font-size: 48px; margin-bottom: 20px; }
  h1 { font-size: 20px; font-weight: 600; margin-bottom: 12px; color: #FF9F0A; }
  p { font-size: 14px; line-height: 1.6; color: #98989d; margin-bottom: 24px; }
  .url-box {
    background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.06);
    border-radius: 10px; padding: 12px 16px; font-size: 12px;
    word-break: break-all; color: #6e6e73; margin-bottom: 24px;
    font-family: 'JetBrains Mono', 'SF Mono', monospace;
  }
  .btn-continue {
    display: inline-block; background: #FF9F0A; color: #000;
    border: none; border-radius: 10px; padding: 12px 32px;
    font-size: 14px; font-weight: 600; cursor: pointer;
    text-decoration: none; transition: opacity 0.2s;
    font-family: Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  }
  .btn-continue:hover { opacity: 0.85; }
</style>
</head>
<body>
<div class="glass-pane">
  <div class="icon">&#x26A0;&#xFE0F;</div>
  <h1>Unverified Link</h1>
  <p>Our security systems could not verify the safety of this destination. It may be safe, or it may be a phishing or malware site. Proceed with caution.</p>
  <div class="url-box">%s</div>
  <a class="btn-continue" href="/link-protect?token=%s&confirm=1">Continue</a>
</div>
</body>
</html>`, escapeHTML(originalURL), tokenStr)
}
