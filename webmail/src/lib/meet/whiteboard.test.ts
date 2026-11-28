// whiteboard.test.ts — Meet B3 Task 9. @excalidraw/excalidraw feature-detects
// canvas support (`ctx.filter`) at IMPORT time, and jsdom's HTMLCanvasElement
// has no getContext() (no `canvas` npm package installed) — merely importing
// the real package throws before a single test runs. Mocked entirely at this
// module's own import seam (the blur.ts/@livekit/track-processors genre) so
// the cap/diff/sync protocol logic — plain data-in/data-out, no canvas
// needed — stays unit-testable. `mountWhiteboard`'s own React wiring is
// exercised too, but only through the mock's captured props (never a real
// canvas render) — see the per-test comments below for what each proves.
import { describe, it, expect, vi } from 'vitest';
import type { ReactElement } from 'react';
import { flushSync } from 'react-dom';

let capturedProps: Record<string, unknown> | null = null;
const exportToBlobMock = vi.fn(async () => new Blob(['png'], { type: 'image/png' }));
const reconcileElementsMock = vi.fn(
	(local: unknown[], remote: unknown[], _appState: unknown) =>
		// A trivial-but-order-stable stand-in for the real LWW merge — good
		// enough to prove applyRemote WIRES local/remote/appState through to
		// updateScene; the real algorithm ships with the package, not here.
		[...local, ...remote],
);

vi.mock('@excalidraw/excalidraw', () => ({
	Excalidraw: (props: Record<string, unknown>) => {
		capturedProps = props;
		return null;
	},
	exportToBlob: (...args: unknown[]) => exportToBlobMock(...(args as [])),
	reconcileElements: (...args: [unknown[], unknown[], unknown]) => reconcileElementsMock(...args),
	CaptureUpdateAction: { NEVER: 'NEVER', IMMEDIATELY: 'IMMEDIATELY', EVENTUALLY: 'EVENTUALLY' },
}));

const { isOverCap, diffChangedElements, versionsOf, wireRoomSync, mountWhiteboard, WB_ELEMENT_CAP } =
	await import('./whiteboard');
import type { RoomWhiteboardOps, WhiteboardHandle } from './whiteboard';

function el(id: string, version: number) {
	return { id, version };
}

// ── isOverCap ────────────────────────────────────────────────────────────
describe('isOverCap', () => {
	it('is false at and under the cap', () => {
		expect(isOverCap(new Array(WB_ELEMENT_CAP).fill(0))).toBe(false);
		expect(isOverCap([])).toBe(false);
	});
	it('is true one past the cap', () => {
		expect(isOverCap(new Array(WB_ELEMENT_CAP + 1).fill(0))).toBe(true);
	});
});

// ── diffChangedElements / versionsOf ────────────────────────────────────
describe('diffChangedElements', () => {
	it('returns only elements whose version differs from the tracked snapshot', () => {
		const prev = versionsOf([el('a', 1), el('b', 1)]);
		const now = [el('a', 1), el('b', 2), el('c', 1)];
		expect(diffChangedElements(prev, now)).toEqual([el('b', 2), el('c', 1)]);
	});
	it('an empty prior snapshot treats every element as changed (first broadcast)', () => {
		const now = [el('a', 1), el('b', 1)];
		expect(diffChangedElements(new Map(), now)).toEqual(now);
	});
	it('no changes -> empty diff', () => {
		const prev = versionsOf([el('a', 1)]);
		expect(diffChangedElements(prev, [el('a', 1)])).toEqual([]);
	});
});

// ── wireRoomSync — the room.svelte.ts (Task 6) contract, plain fakes ────
function fakeRoom(): RoomWhiteboardOps & {
	whiteboardCb?: (elements: unknown) => void;
	requestCb?: () => void;
} {
	const room: RoomWhiteboardOps & { whiteboardCb?: (elements: unknown) => void; requestCb?: () => void } = {
		onWhiteboard: vi.fn((cb) => {
			room.whiteboardCb = cb;
		}),
		onWhiteboardRequest: vi.fn((cb) => {
			room.requestCb = cb;
		}),
		sendWhiteboard: vi.fn(),
		requestWhiteboardSync: vi.fn(),
		sendWhiteboardSync: vi.fn(),
	};
	return room;
}

function fakeHandle(): WhiteboardHandle {
	return {
		applyRemote: vi.fn(),
		getSceneElements: vi.fn(() => ['scene']),
		setTheme: vi.fn(),
		unmount: vi.fn(),
	};
}

describe('wireRoomSync', () => {
	it('routes an incoming wb delta to handle.applyRemote', () => {
		const room = fakeRoom();
		const handle = fakeHandle();
		wireRoomSync(room, handle);
		room.whiteboardCb?.(['incoming']);
		expect(handle.applyRemote).toHaveBeenCalledWith(['incoming']);
	});

	it('answers an incoming wb_req with the full current scene via sendWhiteboardSync', () => {
		const room = fakeRoom();
		const handle = fakeHandle();
		wireRoomSync(room, handle);
		room.requestCb?.();
		expect(handle.getSceneElements).toHaveBeenCalled();
		expect(room.sendWhiteboardSync).toHaveBeenCalledWith(['scene']);
	});

	it('a late joiner sends its own wb_req exactly once on open', () => {
		const room = fakeRoom();
		wireRoomSync(room, fakeHandle());
		expect(room.requestWhiteboardSync).toHaveBeenCalledTimes(1);
	});
});

// ── mountWhiteboard — React wiring, no real canvas render ───────────────
function fakeExcalidrawApi() {
	return {
		getSceneElements: vi.fn(() => ['a', 'b']),
		getSceneElementsIncludingDeleted: vi.fn(() => ['a', 'b', 'deleted-c']),
		getAppState: vi.fn(() => ({ viewBackgroundColor: '#fff' })),
		getFiles: vi.fn(() => ({})),
		updateScene: vi.fn(),
	};
}

async function mountAndCapture(opts: Parameters<typeof mountWhiteboard>[1]) {
	const container = document.createElement('div');
	document.body.appendChild(container);
	let handle!: ReturnType<typeof mountWhiteboard>;
	capturedProps = null;
	// React roots from adjacent tests may commit on the same macrotask. Flush
	// this root synchronously so capturedProps always belongs to this mount,
	// rather than whichever earlier root happened to commit last.
	flushSync(() => {
		handle = mountWhiteboard(container, opts);
	});
	const props = capturedProps as Record<string, unknown> | null;
	if (!props) throw new Error('Excalidraw mock did not render synchronously');
	return { handle, props };
}

describe('mountWhiteboard — onChange (cap + diff)', () => {
	it('broadcasts only changed elements on a normal edit', async () => {
		const onChange = vi.fn();
		const { props } = await mountAndCapture({ onChange, theme: 'light' });
		(props.onChange as (els: unknown[]) => void)([el('a', 1), el('b', 1)]);
		expect(onChange).toHaveBeenCalledWith([el('a', 1), el('b', 1)]);
		onChange.mockClear();
		(props.onChange as (els: unknown[]) => void)([el('a', 1), el('b', 2)]);
		expect(onChange).toHaveBeenCalledWith([el('b', 2)]);
	});

	it('an over-cap edit is refused (never broadcast) and reports via onFull', async () => {
		const onChange = vi.fn();
		const onFull = vi.fn();
		const { props } = await mountAndCapture({ onChange, onFull, theme: 'light' });
		const tooMany = new Array(WB_ELEMENT_CAP + 1).fill(0).map((_, i) => el(String(i), 1));
		(props.onChange as (els: unknown[]) => void)(tooMany);
		expect(onFull).toHaveBeenCalledTimes(1);
		expect(onChange).not.toHaveBeenCalled();
	});
});

describe('mountWhiteboard — applyRemote (reconcile)', () => {
	it('merges via reconcileElements(local incl. deleted, remote, appState) and updateScene()s the result', async () => {
		const { handle, props } = await mountAndCapture({ onChange: vi.fn(), theme: 'light' });
		const api = fakeExcalidrawApi();
		(props.excalidrawAPI as (a: unknown) => void)(api);
		handle.applyRemote([el('remote-1', 1)]);
		expect(reconcileElementsMock).toHaveBeenCalledWith(
			['a', 'b', 'deleted-c'],
			[el('remote-1', 1)],
			{ viewBackgroundColor: '#fff' },
		);
		expect(api.updateScene).toHaveBeenCalledWith({
			elements: ['a', 'b', 'deleted-c', el('remote-1', 1)],
			captureUpdate: 'NEVER',
		});
	});

	it('a non-array payload is treated as empty (never throws)', async () => {
		const { handle, props } = await mountAndCapture({ onChange: vi.fn(), theme: 'light' });
		const api = fakeExcalidrawApi();
		(props.excalidrawAPI as (a: unknown) => void)(api);
		expect(() => handle.applyRemote(null)).not.toThrow();
		expect(reconcileElementsMock).toHaveBeenLastCalledWith(['a', 'b', 'deleted-c'], [], {
			viewBackgroundColor: '#fff',
		});
	});

	it('an over-cap remote payload is silently truncated before merge (defense in depth, no onFull)', async () => {
		const onFull = vi.fn();
		const { handle, props } = await mountAndCapture({ onChange: vi.fn(), onFull, theme: 'light' });
		const api = fakeExcalidrawApi();
		(props.excalidrawAPI as (a: unknown) => void)(api);
		const tooMany = new Array(WB_ELEMENT_CAP + 5).fill(0).map((_, i) => el(String(i), 1));
		handle.applyRemote(tooMany);
		const remoteArg = reconcileElementsMock.mock.calls.at(-1)?.[1] as unknown[];
		expect(remoteArg.length).toBe(WB_ELEMENT_CAP);
		expect(onFull).not.toHaveBeenCalled();
	});

	it('drops non-element-shaped array members before the reconciler (untrusted peer payload)', async () => {
		const { handle, props } = await mountAndCapture({ onChange: vi.fn(), theme: 'light' });
		const api = fakeExcalidrawApi();
		(props.excalidrawAPI as (a: unknown) => void)(api);
		handle.applyRemote([el('remote-1', 1), 'garbage', 42, null, { noId: true }, { id: 7 }]);
		const remoteArg = reconcileElementsMock.mock.calls.at(-1)?.[1] as unknown[];
		expect(remoteArg).toEqual([el('remote-1', 1)]);
	});

	it('a reconciler throw is contained to the frame (dispatch loop survives)', async () => {
		const { handle, props } = await mountAndCapture({ onChange: vi.fn(), theme: 'light' });
		const api = fakeExcalidrawApi();
		(props.excalidrawAPI as (a: unknown) => void)(api);
		reconcileElementsMock.mockImplementationOnce(() => {
			throw new Error('poisoned frame');
		});
		const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {});
		try {
			expect(() => handle.applyRemote([el('remote-1', 1)])).not.toThrow();
			expect(api.updateScene).not.toHaveBeenCalled();
			// A subsequent good frame still applies.
			handle.applyRemote([el('remote-2', 1)]);
			expect(api.updateScene).toHaveBeenCalled();
		} finally {
			consoleError.mockRestore();
		}
	});

	it('getSceneElements reads through to the live API', async () => {
		const { handle, props } = await mountAndCapture({ onChange: vi.fn(), theme: 'light' });
		const api = fakeExcalidrawApi();
		(props.excalidrawAPI as (a: unknown) => void)(api);
		expect(handle.getSceneElements()).toEqual(['a', 'b']);
	});

	it('getSceneElements is [] before the API has attached', async () => {
		const { handle } = await mountAndCapture({ onChange: vi.fn(), theme: 'light' });
		expect(handle.getSceneElements()).toEqual([]);
	});
});

describe('mountWhiteboard — export to chat (renderTopRightUI)', () => {
	it('renders no button at all when onExport is omitted (no bridged chat channel)', async () => {
		const { props } = await mountAndCapture({ onChange: vi.fn(), theme: 'light' });
		const topRight = props.renderTopRightUI as () => ReactElement | null;
		expect(topRight()).toBeNull();
	});

	it('clicking the rendered export button exports the current scene and calls onExport with the blob', async () => {
		const onExport = vi.fn();
		const { props } = await mountAndCapture({ onChange: vi.fn(), onExport, theme: 'light' });
		const api = fakeExcalidrawApi();
		(props.excalidrawAPI as (a: unknown) => void)(api);
		const topRight = props.renderTopRightUI as () => ReactElement;
		const button = topRight();
		expect(button).not.toBeNull();
		(button.props as { onClick: () => void }).onClick();
		await new Promise((r) => setTimeout(r, 0));
		expect(exportToBlobMock).toHaveBeenCalledWith(
			expect.objectContaining({ elements: ['a', 'b'], mimeType: 'image/png' }),
		);
		expect(onExport).toHaveBeenCalledWith(expect.any(Blob));
	});
});

describe('mountWhiteboard — theme sync + unmount', () => {
	it('setTheme re-renders with the new theme prop', async () => {
		const { handle } = await mountAndCapture({ onChange: vi.fn(), theme: 'light' });
		handle.setTheme('dark');
		await new Promise((r) => setTimeout(r, 0));
		expect(capturedProps?.theme).toBe('dark');
	});

	it('unmount tears down the React root without throwing', async () => {
		const { handle } = await mountAndCapture({ onChange: vi.fn(), theme: 'light' });
		expect(() => handle.unmount()).not.toThrow();
	});
});
