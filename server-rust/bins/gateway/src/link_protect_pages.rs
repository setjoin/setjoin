//! Frozen Go's link-protect interstitials (`linkprotect/handler.go`): byte-for-byte templates.
//! `{URL}` is the HTML-escaped destination, `{TOKEN}` the raw token text (as Go does).
pub const BLOCK: &str = r####"<!DOCTYPE html>
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
  <div class="url-box">{URL}</div>
</div>
</body>
</html>"####;
pub const WARN: &str = r####"<!DOCTYPE html>
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
  <div class="url-box">{URL}</div>
  <a class="btn-continue" href="/link-protect?token={TOKEN}&confirm=1">Continue</a>
</div>
</body>
</html>"####;
