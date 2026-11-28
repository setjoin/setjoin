import { afterEach, describe, expect, it, vi } from 'vitest';

import { installServiceWorkerGenerationCoordinator } from './sw-coordinator';

afterEach(() => vi.unstubAllGlobals());

describe('service worker generation coordinator', () => {
	it('acknowledges the mounted executable build without exposing identity', async () => {
		const postMessage = vi.fn();
		const registration = new EventTarget() as ServiceWorkerRegistration;
		Object.defineProperties(registration, { waiting: { value: null }, installing: { value: null } });
		vi.stubGlobal('requestAnimationFrame', (callback: FrameRequestCallback) => { callback(0); return 1; });
		vi.stubGlobal('navigator', {
			serviceWorker: Object.assign(new EventTarget(), {
				controller: { postMessage },
				ready: Promise.resolve(registration),
				getRegistration: vi.fn().mockResolvedValue(registration),
			}),
		});
		const coordinator = installServiceWorkerGenerationCoordinator('build-1');
		await vi.waitFor(() => expect(postMessage).toHaveBeenCalledWith({
			type: 'SETJOIN_SHELL_MOUNTED', protocolVersion: 1, buildId: 'build-1',
		}));
		expect(JSON.stringify(postMessage.mock.calls)).not.toMatch(/user|mailbox|token/i);
		coordinator.dispose();
	});

	it('keeps a candidate waiting until the caller reports a safe boundary', async () => {
		const postMessage = vi.fn();
		const waiting = { postMessage } as unknown as ServiceWorker;
		const registration = new EventTarget() as ServiceWorkerRegistration;
		Object.defineProperties(registration, { waiting: { value: waiting }, installing: { value: null } });
		const serviceWorker = Object.assign(new EventTarget(), {
			controller: null,
			ready: Promise.resolve(registration),
			getRegistration: vi.fn().mockResolvedValue(registration),
		});
		vi.stubGlobal('navigator', { serviceWorker });
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
			ok: true,
			redirected: false,
			url: `${location.origin}/critical-shell.v1.json`,
			json: async () => ({ protocolVersion: 1, buildId: 'build-2' }),
		}));
		Object.defineProperty(document, 'visibilityState', { value: 'visible', configurable: true });
		const coordinator = installServiceWorkerGenerationCoordinator('build-1', false);
		await Promise.resolve();
		expect(postMessage).not.toHaveBeenCalled();
		coordinator.setSafeToActivate(true);
		await vi.waitFor(() => expect(postMessage).toHaveBeenCalledWith({
			type: 'SETJOIN_ACTIVATE_CANDIDATE', protocolVersion: 1, buildId: 'build-2',
		}));
		coordinator.dispose();
	});
});
