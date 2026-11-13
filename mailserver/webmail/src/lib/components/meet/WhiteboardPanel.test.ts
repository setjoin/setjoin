// WhiteboardPanel.test.ts — Meet B3 Task 9. The panel's own job is the
// SVELTE-side wiring (lazy import, loading state, export-to-chat glue,
// theme sync, teardown) — the React/Excalidraw mount itself is Task 9's
// OWN whiteboard.test.ts concern, so it is mocked wholesale here (the
// blur.ts genre) rather than re-proven through a real canvas render.
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { render, screen, waitFor, fireEvent } from '@testing-library/svelte/svelte5';
import { chatStore } from '$lib/chat/store.svelte';
import { toasts, clearToasts } from '$lib/components/ui';
import type { MeetRoom } from '$lib/meet/room.svelte';
import type { MountWhiteboardOptions, WhiteboardHandle } from '$lib/meet/whiteboard';

const mountWhiteboardMock = vi.fn();
const wireRoomSyncMock = vi.fn();

vi.mock('$lib/meet/whiteboard', () => ({
	mountWhiteboard: (...args: unknown[]) => mountWhiteboardMock(...args),
	wireRoomSync: (...args: unknown[]) => wireRoomSyncMock(...args),
}));

import WhiteboardPanel from './WhiteboardPanel.svelte';

function fakeHandle(): WhiteboardHandle {
	return {
		applyRemote: vi.fn(),
		getSceneElements: vi.fn(() => []),
		setTheme: vi.fn(),
		unmount: vi.fn(),
	};
}

function fakeRoom(): MeetRoom {
	return { sendWhiteboard: vi.fn(), onWhiteboard: vi.fn(), onWhiteboardRequest: vi.fn() } as unknown as MeetRoom;
}

beforeEach(() => {
	mountWhiteboardMock.mockReset();
	wireRoomSyncMock.mockReset();
	mountWhiteboardMock.mockReturnValue(fakeHandle());
	chatStore.activeChannelId = null;
	chatStore.openChannel = vi.fn().mockResolvedValue(undefined);
	chatStore.addAttachments = vi.fn().mockReturnValue([]);
	chatStore.send = vi.fn().mockResolvedValue(undefined);
	clearToasts();
});

describe('WhiteboardPanel — lazy load (DN5)', () => {
	it('never statically imports $lib/meet/whiteboard (source guard for the lazy-chunk contract)', () => {
		const src = readFileSync(join(process.cwd(), 'src/lib/components/meet/WhiteboardPanel.svelte'), 'utf-8');
		// A `import type {...}` is erased at compile time (zero runtime cost,
		// doesn't defeat lazy-loading) — only a VALUE import would eagerly
		// pull the ~1MB gz React+Excalidraw chunk into the main bundle.
		expect(src).not.toMatch(/^\s*import\s+(?!type\b)[^;]*from\s+['"]\$lib\/meet\/whiteboard['"]/m);
		expect(src).toMatch(/import\(\s*['"]\$lib\/meet\/whiteboard['"]\s*\)/);
	});

	it('shows the loading state immediately, then mounts once the dynamic import resolves', async () => {
		render(WhiteboardPanel, { room: fakeRoom(), theme: 'light', chatChannelId: null, onClose: vi.fn() });
		expect(screen.getByText('Loading whiteboard…')).toBeInTheDocument();
		expect(mountWhiteboardMock).not.toHaveBeenCalled();
		await waitFor(() => expect(mountWhiteboardMock).toHaveBeenCalledTimes(1));
		await waitFor(() => expect(screen.queryByText('Loading whiteboard…')).toBeNull());
	});
});

describe('WhiteboardPanel — mount wiring', () => {
	it('mounts with the given theme and wires onChange to room.sendWhiteboard', async () => {
		const room = fakeRoom();
		render(WhiteboardPanel, { room, theme: 'dark', chatChannelId: null, onClose: vi.fn() });
		await waitFor(() => expect(mountWhiteboardMock).toHaveBeenCalledTimes(1));
		const opts = mountWhiteboardMock.mock.calls[0][1] as MountWhiteboardOptions;
		expect(opts.theme).toBe('dark');
		opts.onChange(['delta']);
		expect(room.sendWhiteboard).toHaveBeenCalledWith(['delta']);
	});

	it('hides the export callback entirely when there is no bridged chat channel', async () => {
		render(WhiteboardPanel, { room: fakeRoom(), theme: 'light', chatChannelId: null, onClose: vi.fn() });
		await waitFor(() => expect(mountWhiteboardMock).toHaveBeenCalledTimes(1));
		const opts = mountWhiteboardMock.mock.calls[0][1] as MountWhiteboardOptions;
		expect(opts.onExport).toBeUndefined();
	});

	it('wires the handle into wireRoomSync(room, handle) once mounted', async () => {
		const room = fakeRoom();
		const handle = fakeHandle();
		mountWhiteboardMock.mockReturnValue(handle);
		render(WhiteboardPanel, { room, theme: 'light', chatChannelId: null, onClose: vi.fn() });
		await waitFor(() => expect(wireRoomSyncMock).toHaveBeenCalledWith(room, handle));
	});

	it('an over-cap report (onFull) toasts meet.wb.full', async () => {
		render(WhiteboardPanel, { room: fakeRoom(), theme: 'light', chatChannelId: null, onClose: vi.fn() });
		await waitFor(() => expect(mountWhiteboardMock).toHaveBeenCalledTimes(1));
		const opts = mountWhiteboardMock.mock.calls[0][1] as MountWhiteboardOptions;
		opts.onFull?.();
		expect(toasts.some((tst) => tst.message === 'Whiteboard is full (element limit reached)')).toBe(true);
	});
});

describe('WhiteboardPanel — export to chat (A2 rail)', () => {
	it('"Export to chat" uploads the PNG through chatStore.addAttachments then sends an attachment-only message', async () => {
		render(WhiteboardPanel, { room: fakeRoom(), theme: 'light', chatChannelId: 42, onClose: vi.fn() });
		await waitFor(() => expect(mountWhiteboardMock).toHaveBeenCalledTimes(1));
		const opts = mountWhiteboardMock.mock.calls[0][1] as MountWhiteboardOptions;
		expect(opts.onExport).toBeInstanceOf(Function);
		const blob = new Blob(['png'], { type: 'image/png' });
		opts.onExport?.(blob);
		await waitFor(() => expect(chatStore.send).toHaveBeenCalledWith('', null));
		expect(chatStore.openChannel).toHaveBeenCalledWith(42);
		expect(chatStore.addAttachments).toHaveBeenCalledWith(
			42,
			null,
			expect.arrayContaining([expect.objectContaining({ type: 'image/png' })]),
		);
	});

	it('does not re-open an already-active channel', async () => {
		chatStore.activeChannelId = 42;
		render(WhiteboardPanel, { room: fakeRoom(), theme: 'light', chatChannelId: 42, onClose: vi.fn() });
		await waitFor(() => expect(mountWhiteboardMock).toHaveBeenCalledTimes(1));
		const opts = mountWhiteboardMock.mock.calls[0][1] as MountWhiteboardOptions;
		opts.onExport?.(new Blob(['png'], { type: 'image/png' }));
		await waitFor(() => expect(chatStore.send).toHaveBeenCalled());
		expect(chatStore.openChannel).not.toHaveBeenCalled();
	});
});

describe('WhiteboardPanel — close + teardown', () => {
	it('the close button calls onClose', async () => {
		const onClose = vi.fn();
		render(WhiteboardPanel, { room: fakeRoom(), theme: 'light', chatChannelId: null, onClose });
		await fireEvent.click(screen.getByLabelText('Close'));
		expect(onClose).toHaveBeenCalled();
	});

	it('unmounting the component unmounts the whiteboard handle', async () => {
		const handle = fakeHandle();
		mountWhiteboardMock.mockReturnValue(handle);
		const { unmount } = render(WhiteboardPanel, {
			room: fakeRoom(),
			theme: 'light',
			chatChannelId: null,
			onClose: vi.fn(),
		});
		await waitFor(() => expect(mountWhiteboardMock).toHaveBeenCalledTimes(1));
		unmount();
		expect(handle.unmount).toHaveBeenCalled();
	});

	// B3 retro fix (design finding #9-nit): without this, an incoming wb/wb_req
	// frame after unmount would call into the now-dead Excalidraw handle.
	it('unregisters room.onWhiteboard/onWhiteboardRequest on unmount (retro fix)', async () => {
		const room = fakeRoom();
		const { unmount } = render(WhiteboardPanel, { room, theme: 'light', chatChannelId: null, onClose: vi.fn() });
		await waitFor(() => expect(mountWhiteboardMock).toHaveBeenCalledTimes(1));
		unmount();
		expect(room.onWhiteboard).toHaveBeenCalledWith(null);
		expect(room.onWhiteboardRequest).toHaveBeenCalledWith(null);
	});
});
