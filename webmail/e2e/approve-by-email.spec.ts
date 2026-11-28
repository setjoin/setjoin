import { test, expect } from '@playwright/test';
import { createHmac } from 'node:crypto';
import { psql } from './helpers';

// Approve-by-email confirmation page — GET/POST /approvals/email/{token}.
// The route is UNAUTHENTICATED; security rests entirely on the HMAC token, so a
// test must mint a token the gateway will accept. The token format is
// base64url(json).base64url(HMAC-SHA256(json-b64)) using the gateway's
// JWT_SECRET (the same key linkprotect uses) — reproduced byte-for-byte here.
// The e2e gateway runs with the fixed secret below (see start-test-stack.sh).

const SECRET = 'test-e2e-secret-key-at-least-32-chars!!';
const sq = (s: string) => s.replace(/'/g, "''");

/** Go's base64.URLEncoding: URL-safe alphabet, padding RETAINED. */
function b64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_');
}

/**
 * Mint a signed approval-email token. The payload MUST byte-match Go's
 * json.Marshal(ApprovalEmailClaims{RequestID,ApproverUserID,Decision,ExpiresAt})
 * — compact, struct-field order r,a,d,e — because the HMAC is taken over the
 * base64url of those exact bytes.
 */
function mintToken(requestId: string, approverId: string, decision: 'approve' | 'deny', expUnix: number): string {
  const payload = `{"r":${requestId},"a":${approverId},"d":"${decision}","e":${expUnix}}`;
  const payloadB64 = b64url(Buffer.from(payload, 'utf-8'));
  const sig = createHmac('sha256', SECRET).update(payloadB64).digest();
  return `${payloadB64}.${b64url(sig)}`;
}

function userId(email: string): string {
  return psql(`SELECT id FROM users WHERE email = '${sq(email)}'`);
}

// group_moderation with no held row applies cleanly on approve (see approvals-app spec).
function seedGroupModRequest(subject: string, approverId: string): string {
  // CTE-wrap so psql -tA returns ONLY the id (a bare INSERT...RETURNING also
  // prints the "INSERT 0 1" command tag, which would corrupt the minted token).
  return psql(`
    WITH ins AS (
      INSERT INTO approval_requests
        (consumer_type, requester_user_id, subject, payload, status, approver_kind, approver_ref, expires_at)
      VALUES ('mail.group_moderation', NULL, '${sq(subject)}', '{}'::jsonb, 'pending', 'user', ${approverId}, now() + interval '1 hour')
      RETURNING id
    ) SELECT id FROM ins`);
}

test.describe('Approve-by-email confirmation page @admin', () => {
  // Token-driven unauthenticated page — pin to one project so the two project
  // runs don't seed/decide overlapping requests in parallel.
  test.beforeEach(() => {
  });

  test('a valid token renders the page and approves the request', async ({ page }) => {
    const admin = userId('admin@test.local');
    const subj = `E2E email ${Date.now()}`;
    const id = seedGroupModRequest(subj, admin);
    const exp = Math.floor(Date.now() / 1000) + 3600;
    const token = mintToken(id, admin, 'approve', exp);

    // ── GET: prefetch-safe confirmation page (no state change yet) ──
    await page.goto(`/approvals/email/${token}`);
    await expect(page.getByText(subj)).toBeVisible({ timeout: 10000 });
    expect(statusFor(id)).toBe('pending');

    // ── POST: submit the decision ──
    const submit = page.getByRole('button', { name: /approve/i });
    await expect(submit).toBeVisible();
    await submit.click();
    await expect(page.getByText(/approved this request|you have approved/i)).toBeVisible({ timeout: 10000 });

    // Applied server-side.
    expect(statusFor(id)).toBe('applied');
  });

  test('an invalid token shows the error page', async ({ page }) => {
    await page.goto('/approvals/email/not-a-valid-token.deadbeef');
    await expect(page.getByText(/invalid or expired/i)).toBeVisible({ timeout: 10000 });
  });
});

const statusFor = (id: string): string => psql(`SELECT status FROM approval_requests WHERE id = ${id}`);
