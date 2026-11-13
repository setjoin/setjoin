import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, waitFor } from '@testing-library/svelte/svelte5';
import { get } from 'svelte/store';
import { jmapSession, sessionResolved } from '$lib/stores/session';
import { httpRequest } from '$lib/http';
import { authedBootstrap } from './authed-bootstrap.svelte';
import BootstrapHarness from './authed-bootstrap.harness.svelte';

// loadSessionStore probes /.well-known/jmap through the $lib/http seam.
vi.mock('$lib/http', () => ({ httpRequest: vi.fn() }));

const STALE_SESSION = { stale: true, capabilities: {} } as never;
const FRESH_SESSION = { fresh: true, capabilities: {} };

function probeResolves(): void {
	vi.mocked(httpRequest).mockResolvedValue({
		json: async () => FRESH_SESSION,
	} as unknown as Response);
}

function probeFails(): void {
	vi.mocked(httpRequest).mockRejectedValue(new Error('network down'));
}

async function settleProbe(): Promise<void> {
	// The probe resolved (success or failure) — give its async tail a tick.
	await new Promise((resolve) => setTimeout(resolve, 0));
}

beforeEach(() => {
	jmapSession.set(null);
	vi.mocked(httpRequest).mockReset();
});

afterEach(() => {
	cleanup();
	jmapSession.set(null);
});

describe('authedBootstrap gating', () => {
	it('runs the loader after a fresh session document is proven', async () => {
		probeResolves();
		const loader = vi.fn();
		render(BootstrapHarness, { props: { loader } });
		await waitFor(() => expect(loader).toHaveBeenCalledTimes(1));
		const signal = loader.mock.calls[0][0] as AbortSignal;
		expect(signal).toBeInstanceOf(AbortSignal);
		expect(signal.aborted).toBe(false);
		// The probe installed a fresh document (different reference than null).
		expect(get(jmapSession)).toEqual(FRESH_SESSION);
	});

	it('does NOT run the loader when the probe fails with no session (anonymous)', async () => {
		probeFails();
		const loader = vi.fn();
		render(BootstrapHarness, { props: { loader } });
		await waitFor(() => expect(get(sessionResolved)).toBe(true));
		await settleProbe();
		expect(loader).not.toHaveBeenCalled();
		expect(get(jmapSession)).toBeNull();
	});

	it('pins bootstrap against a STALE session after an unavailable probe', async () => {
		jmapSession.set(STALE_SESSION);
		probeFails(); // probe unavailable — the store retains the stale object
		const loader = vi.fn();
		render(BootstrapHarness, { props: { loader } });
		await waitFor(() => expect(get(sessionResolved)).toBe(true));
		await settleProbe();
		// The retained stale session is NOT authentication proof.
		expect(loader).not.toHaveBeenCalled();
		expect(get(jmapSession)).toBe(STALE_SESSION); // reference untouched
	});

	it('runs the loader when a fresh probe supersedes a stale session', async () => {
		jmapSession.set(STALE_SESSION);
		probeResolves();
		const loader = vi.fn();
		render(BootstrapHarness, { props: { loader } });
		await waitFor(() => expect(loader).toHaveBeenCalledTimes(1));
		expect(get(jmapSession)).toEqual(FRESH_SESSION);
	});

	it('invokes onUnproven exactly once when the probe proves nothing (anonymous)', async () => {
		probeFails();
		const loader = vi.fn();
		const onUnproven = vi.fn();
		render(BootstrapHarness, { props: { loader, options: { onUnproven } } });
		await waitFor(() => expect(get(sessionResolved)).toBe(true));
		await settleProbe();
		expect(loader).not.toHaveBeenCalled();
		expect(onUnproven).toHaveBeenCalledTimes(1);
	});

	it('invokes onUnproven once for a retained STALE session (unavailable probe) and never runs the loader', async () => {
		jmapSession.set(STALE_SESSION);
		probeFails();
		const loader = vi.fn();
		const onUnproven = vi.fn();
		render(BootstrapHarness, { props: { loader, options: { onUnproven } } });
		await waitFor(() => expect(get(sessionResolved)).toBe(true));
		await settleProbe();
		expect(loader).not.toHaveBeenCalled();
		expect(onUnproven).toHaveBeenCalledTimes(1);
	});

	it('does NOT invoke onUnproven after a proven probe, nor after an unmount aborted the bootstrap', async () => {
		probeResolves();
		const onUnproven = vi.fn();
		const { unmount } = render(BootstrapHarness, { props: { loader: vi.fn(), options: { onUnproven } } });
		await waitFor(() => expect(onUnproven).not.toHaveBeenCalled());
		unmount();
		expect(onUnproven).not.toHaveBeenCalled();
	});

	it('does NOT invoke onUnproven when the unmount lands while an unproven probe settles', async () => {
		let failProbe!: (err: Error) => void;
		vi.mocked(httpRequest).mockImplementation(
			() =>
				new Promise<Response>((_resolve, reject) => {
					failProbe = (err: Error) => reject(err);
				})
		);
		const onUnproven = vi.fn();
		const { unmount } = render(BootstrapHarness, { props: { loader: vi.fn(), options: { onUnproven } } });
		await settleProbe();
		unmount();
		failProbe(new Error('network down'));
		await settleProbe();
		await settleProbe();
		expect(onUnproven).not.toHaveBeenCalled();
	});
});

describe('authedBootstrap lifecycle', () => {
	it('aborts the loader signal on unmount', async () => {
		probeResolves();
		const loader = vi.fn();
		const { unmount } = render(BootstrapHarness, { props: { loader } });
		await waitFor(() => expect(loader).toHaveBeenCalledTimes(1));
		const signal = loader.mock.calls[0][0] as AbortSignal;
		expect(signal.aborted).toBe(false);
		unmount();
		expect(signal.aborted).toBe(true);
	});

	it('never runs the loader when unmounted during the probe', async () => {
		let releaseProbe!: () => void;
		vi.mocked(httpRequest).mockImplementation(
			() =>
				new Promise<Response>((resolve) => {
					releaseProbe = () => resolve({ json: async () => FRESH_SESSION } as unknown as Response);
				})
		);
		const loader = vi.fn();
		const { unmount } = render(BootstrapHarness, { props: { loader } });
		await settleProbe();
		unmount();
		releaseProbe(); // the probe completes AFTER the unmount
		await settleProbe();
		await settleProbe();
		expect(loader).not.toHaveBeenCalled();
	});

	it('no-ops under SSR: nothing registers, nothing loads', async () => {
		vi.resetModules();
		vi.doMock('$app/environment', () => ({ dev: true, browser: false, building: false, version: 'test-build' }));
		try {
			// Fresh module instance with browser:false. Calling authedBootstrap
			// OUTSIDE a component must not throw (it must never reach onMount)
			// and must not start a probe.
			const ssr = await import('./authed-bootstrap.svelte');
			const loader = vi.fn();
			expect(() => ssr.authedBootstrap(loader)).not.toThrow();
			await settleProbe();
			expect(loader).not.toHaveBeenCalled();
			expect(vi.mocked(httpRequest)).not.toHaveBeenCalled();
		} finally {
			vi.doMock('$app/environment', () => ({ dev: true, browser: true, building: false, version: 'test-build' }));
			vi.resetModules();
		}
	});
});
