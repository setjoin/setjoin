import { describe, it, expect } from 'vitest';
import { isSenderAllowed } from './ipc-origin';

describe('isSenderAllowed', () => {
	const fileOrigin = ['file:///Applications/SetJoin.app/build/index.html'];
	const devOrigin = ['http://localhost:5173'];

	it('accepts the exact bundled file URL and its hash/query variants', () => {
		expect(isSenderAllowed(fileOrigin[0], fileOrigin)).toBe(true);
		expect(isSenderAllowed(`${fileOrigin[0]}#/inbox`, fileOrigin)).toBe(true);
	});

	it('rejects a different file path', () => {
		expect(isSenderAllowed('file:///etc/passwd', fileOrigin)).toBe(false);
		expect(isSenderAllowed('file:///Applications/Evil.app/index.html', fileOrigin)).toBe(false);
	});

	it('accepts the dev-server origin by parsed origin, not prefix', () => {
		expect(isSenderAllowed('http://localhost:5173/app', devOrigin)).toBe(true);
		// prefix look-alike must NOT match
		expect(isSenderAllowed('http://localhost:51735/app', devOrigin)).toBe(false);
	});

	it('rejects off-origin, empty, and unparseable URLs', () => {
		expect(isSenderAllowed('https://evil.example', devOrigin)).toBe(false);
		expect(isSenderAllowed(undefined, devOrigin)).toBe(false);
		expect(isSenderAllowed('', devOrigin)).toBe(false);
		expect(isSenderAllowed('not a url', devOrigin)).toBe(false);
	});
});

// Sender-gate matching matrix (deep-scan package desktop-drive-bridge-
// unconfined, proposedTest "sender-gate matrix"): the gate is SCHEME-SPECIFIC.
// http(s) origins match by parsed origin (scheme+host+port exact); file://
// entries match by STRING PREFIX, which is strictly weaker. The prefix
// behavior is pinned here as KNOWN-WEAKER-but-accepted: the deep scan found no
// exploitable navigation path (session lockdown denies off-origin
// navigation), so this documents the discrepancy instead of changing it.
describe('isSenderAllowed scheme-specific matrix', () => {
	const fileOrigin = ['file:///Applications/SetJoin.app/build/index.html'];
	const devOrigin = ['http://localhost:5173'];
	const prodHttps = ['https://mail.corp.example'];

	it('http(s): parsed-origin equality is port- and scheme-exact', () => {
		expect(isSenderAllowed('http://localhost:5173/anything?x=1', devOrigin)).toBe(true);
		expect(isSenderAllowed('http://localhost:51735/anything', devOrigin)).toBe(false); // port prefix lookalike
		expect(isSenderAllowed('https://localhost:5173/anything', devOrigin)).toBe(false); // scheme flip
		expect(isSenderAllowed('http://127.0.0.1:5173/anything', devOrigin)).toBe(false); // host is part of the origin
		expect(isSenderAllowed('https://mail.corp.example/', prodHttps)).toBe(true);
		expect(isSenderAllowed('https://mail.corp.example:443/', prodHttps)).toBe(true); // 443 IS the parsed https origin
		expect(isSenderAllowed('https://mail.corp.example.evil/', prodHttps)).toBe(false);
	});

	it('file://: prefix matching is KNOWN-WEAKER — suffix-prefixed paths pass (pinned, not exploited)', () => {
		// Legitimate hash/query routes pass:
		expect(isSenderAllowed(`${fileOrigin[0]}#/inbox`, fileOrigin)).toBe(true);
		// KNOWN-WEAKER: a different path whose string merely extends the allowed
		// one also passes the prefix check. Pinned as documented accepted
		// weakness (no exploitable navigation path established — deep-scan row
		// counterevidence); if this ever becomes reachable, tighten to
		// parsed-URL path comparison, do not silently rely on this pin.
		expect(isSenderAllowed(`${fileOrigin[0]}-evil.html`, fileOrigin)).toBe(true);
		expect(isSenderAllowed(`${fileOrigin[0]}/../elsewhere.html`, fileOrigin)).toBe(true);
		// A genuinely different file path still fails:
		expect(isSenderAllowed('file:///Applications/SetJoin.app/other.html', fileOrigin)).toBe(false);
		expect(isSenderAllowed('file:///etc/passwd', fileOrigin)).toBe(false);
	});

	it('mixed-list matching stays per-entry scheme-specific', () => {
		const both = [...fileOrigin, ...devOrigin];
		expect(isSenderAllowed(`${fileOrigin[0]}#/inbox`, both)).toBe(true);
		expect(isSenderAllowed('http://localhost:5173/app', both)).toBe(true);
		expect(isSenderAllowed('http://localhost:51735/app', both)).toBe(false);
	});
});
