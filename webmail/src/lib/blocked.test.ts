import { describe, it, expect } from 'vitest';
import { blockedCopy } from './blocked';

describe('blockedCopy', () => {
	it('plain browser hard-block → install-app or request, plus contact-admin', () => {
		const c = blockedCopy(/*native*/ false);
		expect(c.titleKey).toContain('blocked.title');
		expect(c.actions.map((a) => a.id)).toContain('contact_admin');
		// a plain browser cannot prove → must offer the native install, not a futile retry
		expect(c.actions.some((a) => a.id === 'install_app' || a.id === 'request_approval')).toBe(true);
	});
	it('native shell not-approved → request approval is primary', () => {
		const c = blockedCopy(/*native*/ true);
		expect(c.actions[0].id).toBe('request_approval');
		expect(c.actions[0].primary).toBe(true);
	});
});
