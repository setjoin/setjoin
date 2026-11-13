import { describe, expect, it } from 'vitest';

import { LocalCaptureConsent, serializeConsent, type ConsentRecord, type ConsentStore } from './consent';

function memoryStore(): ConsentStore & { saved: string[] } {
	let value: string | null = null;
	return {
		saved: [],
		async load() {
			return value;
		},
		async save(raw: string) {
			value = raw;
			this.saved.push(raw);
		},
	};
}

const T0 = 1_000_000;

async function grantedMachine(store: ConsentStore | null = null, surfaces = ['microphone'] as const) {
	const machine = await LocalCaptureConsent.load('execute', store);
	await machine.grant(42, [...surfaces], T0);
	return machine;
}

describe('LocalCaptureConsent — non-dismissible lifecycle transitions', () => {
	it('starts every scope unasked and fails the verdict closed', async () => {
		const machine = await LocalCaptureConsent.load('execute', memoryStore());
		expect(machine.scope(42).state).toBe('unasked');
		expect(machine.verdict(42, ['microphone'])).toMatchObject({
			allowed: false,
			refusal: { code: 'unknown_meeting' },
		});
	});

	it('ask() records the prompt but NEVER manufactures consent (non-dismissible core)', async () => {
		const machine = await grantedMachine();
		const denied = await LocalCaptureConsent.load('execute', memoryStore());
		const asked = await denied.ask(7, T0);
		expect(asked.ok).toBe(true);
		expect(asked.record.state).toBe('unasked');
		expect(asked.record.askedAtUnixMs).toBe(T0);
		expect(asked.record.decidedAtUnixMs).toBeNull();
		expect(denied.verdict(7, ['microphone']).refusal).toMatchObject({ code: 'not_asked' });
		// Asking again on a granted scope does not downgrade or re-bind it.
		const before = machine.scope(42);
		const askedAgain = await machine.ask(42, T0 + 1);
		expect(askedAgain.record.state).toBe('granted');
		expect(askedAgain.record.generation).toBe(before.generation + 1);
	});

	it('grant() is the only path to a startable capture, bound to its meeting and surfaces', async () => {
		const machine = await grantedMachine();
		expect(machine.scope(42)).toMatchObject({
			state: 'granted',
			grantedSurfaces: ['microphone'],
			decidedAtUnixMs: T0,
		});
		const verdict = machine.verdict(42, ['microphone']);
		expect(verdict.allowed).toBe(true);
		expect(verdict.refusal).toBeNull();
	});

	it('binds consent to the meeting scope: meeting 1 never authorizes meeting 2', async () => {
		const machine = await grantedMachine();
		expect(machine.verdict(43, ['microphone']).refusal).toMatchObject({ code: 'unknown_meeting' });
		const other = await machine.grant(43, ['microphone'], T0 + 1);
		expect(other.ok).toBe(true);
		await machine.revoke(43, 'user_revoked', T0 + 2);
		expect(machine.verdict(42, ['microphone']).allowed).toBe(true);
		expect(machine.verdict(43, ['microphone']).allowed).toBe(false);
	});

	it('binds consent to the granted surfaces: microphone never covers systemAudio', async () => {
		const machine = await grantedMachine();
		const verdict = machine.verdict(42, ['microphone', 'systemAudio']);
		expect(verdict.allowed).toBe(false);
		expect(verdict.refusal).toMatchObject({
			code: 'surfaces_not_covered',
			missing: ['systemAudio'],
		});
		expect(machine.verdict(42, ['systemAudio']).allowed).toBe(false);
		expect(machine.verdict(42, ['microphone']).allowed).toBe(true);
	});

	it('deny() blocks capture but stays re-askable until a revocation terminalizes it', async () => {
		const machine = await LocalCaptureConsent.load('execute', memoryStore());
		await machine.deny(42, T0);
		expect(machine.verdict(42, ['microphone']).refusal).toMatchObject({ code: 'denied' });
		const regrant = await machine.grant(42, ['microphone'], T0 + 1);
		expect(regrant.ok).toBe(true);
		expect(machine.verdict(42, ['microphone']).allowed).toBe(true);
	});

	it('revocation is a forced stop and TERMINAL for the meeting scope', async () => {
		const machine = await grantedMachine();
		const revoked = await machine.revoke(42, 'user_revoked', T0 + 5);
		expect(revoked.ok).toBe(true);
		expect(revoked.record).toMatchObject({ state: 'revoked', revokedReason: 'user_revoked', grantedSurfaces: [] });
		expect(machine.verdict(42, ['microphone']).refusal).toMatchObject({
			code: 'revoked',
			reason: 'user_revoked',
		});
		// grant/deny/ask after revocation are refused — a new meeting scope is
		// the only way to consent again.
		await expect(machine.grant(42, ['microphone'], T0 + 6)).resolves.toMatchObject({ ok: false });
		expect(machine.scope(42).state).toBe('revoked');
		await expect(machine.ask(42, T0 + 6)).resolves.toMatchObject({ ok: false });
		await expect(machine.deny(42, T0 + 6)).resolves.toMatchObject({ ok: false });
	});

	it('revoke is idempotent and keeps the first reason', async () => {
		const machine = await grantedMachine();
		await machine.revoke(42, 'policy_revoked', T0 + 1);
		const again = await machine.revoke(42, 'user_revoked', T0 + 2);
		expect(again.ok).toBe(true);
		expect(again.record.revokedReason).toBe('policy_revoked');
	});

	it('meeting end forces the stop state on a live grant', async () => {
		const machine = await grantedMachine();
		const ended = await machine.endMeeting(42, T0 + 10);
		expect(ended.ok).toBe(true);
		expect(ended.record).toMatchObject({ state: 'revoked', revokedReason: 'meeting_ended' });
		expect(machine.verdict(42, ['microphone']).refusal).toMatchObject({ code: 'revoked', reason: 'meeting_ended' });
		// Idempotent: a second meeting-end event keeps the first forced stop.
		const again = await machine.endMeeting(42, T0 + 11);
		expect(again.ok).toBe(true);
		expect(again.record.revokedReason).toBe('meeting_ended');
	});

	it('bumps the generation on every accepted transition (observable persistence race)', async () => {
		const machine = await LocalCaptureConsent.load('execute', memoryStore());
		const g0 = machine.scope(42).generation;
		await machine.ask(42, T0);
		const g1 = machine.scope(42).generation;
		await machine.grant(42, ['microphone'], T0 + 1);
		const g2 = machine.scope(42).generation;
		await machine.deny(42, T0 + 2);
		const g3 = machine.scope(42).generation;
		await machine.revoke(42, 'user_revoked', T0 + 3);
		expect([g1, g2, g3]).toEqual([g0 + 1, g0 + 2, g0 + 3]);
		expect(machine.scope(42).generation).toBe(g0 + 4); // revoke bumped too
		// Refused transitions do not bump.
		await machine.grant(42, ['microphone'], T0 + 4);
		expect(machine.scope(42).generation).toBe(g0 + 4);
	});

	it('refuses an empty grant', async () => {
		const machine = await LocalCaptureConsent.load('execute', memoryStore());
		await expect(machine.grant(42, [], T0)).resolves.toMatchObject({ ok: false });
		expect(machine.scope(42).state).toBe('unasked');
	});
});

describe('LocalCaptureConsent — flag discipline', () => {
	it('is inert in rollout mode off: entry points refuse and the store is never touched', async () => {
		const store = memoryStore();
		const machine = await LocalCaptureConsent.load('off', store);
		await expect(machine.grant(42, ['microphone'], T0)).resolves.toMatchObject({
			ok: false,
			refusal: expect.stringContaining("rollout mode 'off'"),
		});
		await expect(machine.ask(42, T0)).resolves.toMatchObject({ ok: false });
		await expect(machine.deny(42, T0)).resolves.toMatchObject({ ok: false });
		await expect(machine.revoke(42, 'user_revoked', T0)).resolves.toMatchObject({ ok: false });
		await expect(machine.endMeeting(42, T0)).resolves.toMatchObject({ ok: false });
		expect(machine.verdict(42, ['microphone']).refusal).toMatchObject({ code: 'flag_not_admitted' });
		expect(store.saved).toEqual([]);
	});

	it('observe mode is inert for the stateful consent path: transitions refuse', async () => {
		const store = memoryStore();
		const machine = await LocalCaptureConsent.load('observe', store);
		await expect(machine.grant(42, ['microphone'], T0)).resolves.toMatchObject({
			ok: false,
			refusal: expect.stringContaining("rollout mode 'observe'"),
		});
		expect(machine.verdict(42, ['microphone']).refusal).toMatchObject({ code: 'flag_not_admitted' });
		expect(store.saved).toEqual([]);
	});
});

describe('LocalCaptureConsent — persistence', () => {
	it('saves after every accepted transition and round-trips through load', async () => {
		const store = memoryStore();
		const machine = await LocalCaptureConsent.load('execute', store);
		await machine.ask(42, T0);
		await machine.grant(42, ['microphone', 'systemAudio'], T0 + 1);
		await machine.revoke(42, 'user_revoked', T0 + 2);
		expect(store.saved).toHaveLength(3);

		const reloaded = await LocalCaptureConsent.load('execute', store);
		expect(reloaded.scope(42)).toMatchObject({
			meetingId: 42,
			state: 'revoked',
			revokedReason: 'user_revoked',
			askedAtUnixMs: T0,
			decidedAtUnixMs: T0 + 2,
			generation: 3,
		});
		expect(reloaded.verdict(42, ['microphone']).allowed).toBe(false);
	});

	it('fails closed on a corrupted store: scopes fall back to unasked and capture is refused', async () => {
		const store = memoryStore();
		await store.save('this is not json{{{');
		const machine = await LocalCaptureConsent.load('execute', store);
		expect(machine.scope(42).state).toBe('unasked');
		expect(machine.verdict(42, ['microphone']).allowed).toBe(false);
	});

	it('drops records that fail validation instead of trusting them', async () => {
		const store = memoryStore();
		const forged: ConsentRecord = {
			meetingId: 42,
			state: 'granted',
			grantedSurfaces: [], // granted without surfaces is structurally invalid
			askedAtUnixMs: T0,
			decidedAtUnixMs: T0,
			generation: 1,
			revokedReason: null,
		};
		await store.save(serializeConsent({ 42: forged }));
		const machine = await LocalCaptureConsent.load('execute', store);
		expect(machine.verdict(42, ['microphone']).allowed).toBe(false);
	});

	it('fails closed when the store read throws', async () => {
		const throwing: ConsentStore = {
			load: async () => {
				throw new Error('vault locked');
			},
			save: async () => {},
		};
		const machine = await LocalCaptureConsent.load('execute', throwing);
		expect(machine.verdict(42, ['microphone']).allowed).toBe(false);
	});

	it('survives a store save failure without rolling back the in-memory decision', async () => {
		const failing: ConsentStore = {
			load: async () => null,
			save: async () => {
				throw new Error('disk full');
			},
		};
		const machine = await LocalCaptureConsent.load('execute', failing);
		const transition = await machine.grant(42, ['microphone'], T0);
		expect(transition.ok).toBe(true);
		expect(machine.verdict(42, ['microphone']).allowed).toBe(true);
	});
});
