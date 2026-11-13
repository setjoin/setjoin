import { describe, it, expect, beforeEach } from 'vitest';
import { get } from 'svelte/store';
import { composeStore, MAX_COMPOSE_SESSIONS } from './compose';

function sessions() {
	return get(composeStore).sessions;
}
function maximized() {
	return sessions().filter((s) => !s.minimized);
}

describe('composeStore — multi-compose sessions (QoL #18)', () => {
	beforeEach(() => composeStore.reset());

	it('open() creates one maximized session', () => {
		const id = composeStore.open({ to: 'a@x.test' });
		expect(id).not.toBeNull();
		expect(sessions()).toHaveLength(1);
		expect(sessions()[0].minimized).toBe(false);
		expect(sessions()[0].opts.to).toBe('a@x.test');
	});

	it('opening a second compose minimizes the first (swap) — one maximized invariant', () => {
		const a = composeStore.open({ to: 'a@x.test' })!;
		const b = composeStore.open({ to: 'b@x.test' })!;
		expect(sessions()).toHaveLength(2);
		expect(maximized()).toHaveLength(1);
		expect(sessions().find((s) => s.id === a)!.minimized).toBe(true);
		expect(sessions().find((s) => s.id === b)!.minimized).toBe(false);
	});

	it('restore() swaps symmetrically — restoring a minimized one minimizes the current maximized', () => {
		const a = composeStore.open()!;
		const b = composeStore.open()!; // a minimized, b maximized
		composeStore.restore(a);
		expect(maximized()).toHaveLength(1);
		expect(sessions().find((s) => s.id === a)!.minimized).toBe(false);
		expect(sessions().find((s) => s.id === b)!.minimized).toBe(true);
	});

	it('minimize() collapses the maximized window (no id → maximized one)', () => {
		const a = composeStore.open()!;
		composeStore.minimize(a);
		expect(maximized()).toHaveLength(0);
		expect(sessions()[0].minimized).toBe(true);
	});

	it('caps concurrent sessions at 3 — a 4th open() returns null and is a no-op', () => {
		composeStore.open();
		composeStore.open();
		composeStore.open();
		expect(sessions()).toHaveLength(MAX_COMPOSE_SESSIONS);
		const fourth = composeStore.open();
		expect(fourth).toBeNull();
		expect(sessions()).toHaveLength(MAX_COMPOSE_SESSIONS);
	});

	it('close(id) removes only that session', () => {
		const a = composeStore.open()!;
		const b = composeStore.open()!;
		composeStore.close(a);
		expect(sessions()).toHaveLength(1);
		expect(sessions()[0].id).toBe(b);
	});

	it('close() with no id closes the current maximized window', () => {
		const a = composeStore.open()!;
		const b = composeStore.open()!; // b is maximized
		composeStore.close();
		expect(sessions().map((s) => s.id)).toEqual([a]);
	});

	it('sessions are isolated — distinct opts, setMeta touches only its own session', () => {
		const a = composeStore.open({ subject: 'A' })!;
		const b = composeStore.open({ subject: 'B' })!;
		composeStore.setMeta(a, { subject: 'draft A', recipient: 'a@x.test', saveError: true });
		const sa = sessions().find((s) => s.id === a)!;
		const sb = sessions().find((s) => s.id === b)!;
		expect(sa.subject).toBe('draft A');
		expect(sa.recipient).toBe('a@x.test');
		expect(sa.saveError).toBe(true);
		expect(sb.subject).toBe('');
		expect(sb.saveError).toBe(false);
	});

	it('setMeta returns the same array reference when nothing changed (no churn / no loop)', () => {
		const a = composeStore.open()!;
		composeStore.setMeta(a, { subject: 'x' });
		const before = get(composeStore).sessions;
		composeStore.setMeta(a, { subject: 'x' }); // identical → no-op
		expect(get(composeStore).sessions).toBe(before);
	});
});
