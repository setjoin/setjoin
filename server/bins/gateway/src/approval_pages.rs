//! Frozen Go HTML templates (email_page.go); formatting is byte parity.
pub const CONFIRM: &str = r###"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Approval Request</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
     background:#f9fafb;color:#111827;min-height:100vh;
     display:flex;align-items:center;justify-content:center;padding:16px}
.card{background:#fff;border-radius:12px;box-shadow:0 1px 4px rgba(0,0,0,.1);
      max-width:480px;width:100%%;padding:32px 28px}
h1{font-size:1.25rem;font-weight:600;margin-bottom:8px}
.sub{color:#6b7280;font-size:.9rem;margin-bottom:24px}
.subject{font-size:1rem;font-weight:500;margin-bottom:24px;
         padding:12px;background:#f3f4f6;border-radius:8px;word-break:break-word}
.btn{display:inline-flex;align-items:center;justify-content:center;
     min-height:44px;padding:10px 24px;border:none;border-radius:8px;
     font-size:1rem;font-weight:500;cursor:pointer;color:#fff;width:100%%}
.btn-approve{background:#2563eb}.btn-approve:hover{background:#1d4ed8}
.btn-deny{background:#dc2626}.btn-deny:hover{background:#b91c1c}
@media(min-width:360px){.btn{width:auto}}
</style>
</head>
<body>
<div class="card" role="main">
  <h1>Approval Request</h1>
  <p class="sub">Your decision is required for the following request:</p>
  <div class="subject" aria-label="Request subject">%s</div>
  <form method="POST" action="%s">
    <button type="submit" class="btn %s" aria-label="%[4]s this request">%[4]s</button>
  </form>
</div>
</body></html>
"###;
pub const RESULT: &str = r###"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Decision recorded</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
     background:#f9fafb;color:#111827;min-height:100vh;
     display:flex;align-items:center;justify-content:center;padding:16px}
.card{background:#fff;border-radius:12px;box-shadow:0 1px 4px rgba(0,0,0,.1);
      max-width:480px;width:100%%;padding:32px 28px;text-align:center}
.icon{font-size:2.5rem;margin-bottom:16px}
h1{font-size:1.25rem;font-weight:600;margin-bottom:8px}
p{color:#6b7280;font-size:.9rem}
</style>
</head>
<body>
<div class="card" role="main">
  <div class="icon" aria-hidden="true">✓</div>
  <h1>Decision recorded</h1>
  <p>You have <strong>%s</strong> this request. The requester will be notified.</p>
</div>
</body></html>
"###;
pub const INACTIVE: &str = r###"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Approval no longer active</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
     background:#f9fafb;color:#111827;min-height:100vh;
     display:flex;align-items:center;justify-content:center;padding:16px}
.card{background:#fff;border-radius:12px;box-shadow:0 1px 4px rgba(0,0,0,.1);
      max-width:480px;width:100%;padding:32px 28px;text-align:center}
.icon{font-size:2.5rem;margin-bottom:16px}
h1{font-size:1.25rem;font-weight:600;margin-bottom:8px}
p{color:#6b7280;font-size:.9rem}
</style>
</head>
<body>
<div class="card" role="main">
  <div class="icon" aria-hidden="true">ℹ</div>
  <h1>This approval is no longer active</h1>
  <p>This request has already been decided or has expired. No action is needed.</p>
</div>
</body></html>
"###;
pub const BAD: &str = r###"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Invalid link</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
     background:#f9fafb;color:#111827;min-height:100vh;
     display:flex;align-items:center;justify-content:center;padding:16px}
.card{background:#fff;border-radius:12px;box-shadow:0 1px 4px rgba(0,0,0,.1);
      max-width:480px;width:100%;padding:32px 28px;text-align:center}
.icon{font-size:2.5rem;margin-bottom:16px}
h1{font-size:1.25rem;font-weight:600;margin-bottom:8px}
p{color:#6b7280;font-size:.9rem}
</style>
</head>
<body>
<div class="card" role="main">
  <div class="icon" aria-hidden="true">✗</div>
  <h1>Invalid or expired link</h1>
  <p>This approval link is invalid or has expired. Please request a new notification email.</p>
</div>
</body></html>
"###;
