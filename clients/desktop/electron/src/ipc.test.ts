import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock electron so ipc.ts can register without a real main process. We capture
// the wrapped handler ipcMain.handle receives so we can drive it with fake
// events (good/bad sender origin).
const handlers = new Map<string, (event: unknown, ...args: unknown[]) => unknown>();
vi.mock('electron', () => ({
	ipcMain: {
		handle: (channel: string, fn: (event: unknown, ...args: unknown[]) => unknown) => {
			handlers.set(channel, fn);
		},
	},
}));

import {
	registerHandler,
	registerHandlers,
	configureAllowedOrigins,
	registeredChannelList,
	_resetForTest,
} from './ipc';

const APP_ORIGIN = 'file:///app/build/index.html';
const goodEvent = { senderFrame: { url: APP_ORIGIN } };
const badEvent = { senderFrame: { url: 'https://evil.example' } };

beforeEach(() => {
	handlers.clear();
	_resetForTest();
	configureAllowedOrigins([APP_ORIGIN]);
});

describe('registerHandler (the single origin-gated wrapper)', () => {
	it('passes args through for an allowed sender origin', async () => {
		registerHandler('echo', (a) => `got:${a}`);
		const wrapped = handlers.get('echo')!;
		expect(await wrapped(goodEvent, 'x')).toBe('got:x');
	});

	it('rejects an off-origin sender', async () => {
		registerHandler('echo', (a) => a);
		const wrapped = handlers.get('echo')!;
		await expect(wrapped(badEvent, 'x')).rejects.toThrow(/rejected sender origin/);
	});

	it('rejects a sender with no frame URL', async () => {
		registerHandler('echo', (a) => a);
		const wrapped = handlers.get('echo')!;
		await expect(wrapped({ senderFrame: { url: undefined } }, 'x')).rejects.toThrow(
			/rejected sender origin/,
		);
	});

	it('throws on a duplicate channel (no silent second registration)', () => {
		registerHandler('dup', () => 1);
		expect(() => registerHandler('dup', () => 2)).toThrow(/duplicate IPC channel/);
	});

	it('registerHandlers tracks every channel in the map', () => {
		registerHandlers({ a: () => 1, b: () => 2 });
		expect(registeredChannelList().sort()).toEqual(['a', 'b']);
	});
});
