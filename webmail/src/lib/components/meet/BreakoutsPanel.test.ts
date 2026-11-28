// BreakoutsPanel.test.ts — Meet B3 Task 7 named tests: count/autoAssign open,
// D3's assignable-target filter (guests + self excluded), assign/close wire
// calls, and the informational-not-alarming failure copy (D3 wire note).
import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import BreakoutsPanel from './BreakoutsPanel.svelte';
import { MeetError, type Breakout } from '$lib/meet/api';
import type { SheetParticipant } from './ControlsBar.svelte';
import { toasts, clearToasts } from '$lib/components/ui';

const openBreakouts = vi.fn();
const closeBreakouts = vi.fn();
const assignBreakout = vi.fn();
vi.mock('$lib/meet/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/meet/api')>('$lib/meet/api');
	return {
		...actual,
		openBreakouts: (...a: unknown[]) => openBreakouts(...a),
		closeBreakouts: (...a: unknown[]) => closeBreakouts(...a),
		assignBreakout: (...a: unknown[]) => assignBreakout(...a),
	};
});

afterEach(() => {
	vi.clearAllMocks();
	clearToasts();
});

const PARTICIPANTS: SheetParticipant[] = [
	{ identity: 'u:1', displayName: 'Host Self', role: 'host' },
	{ identity: 'u:2', displayName: 'Alice Member', role: 'member' },
	{ identity: 'u:3', displayName: 'Bob Cohost', role: 'member' },
	{ identity: 'g:9', displayName: 'Gary Guest', role: 'guest' },
];

const ROOMS: Breakout[] = [
	{ breakoutId: 10, idx: 1, title: 'Room A' },
	{ breakoutId: 11, idx: 2, title: null },
];

interface Props {
	meetingId: number;
	breakouts: Breakout[];
	assignments: Record<string, number | null>;
	participants: SheetParticipant[];
	selfIdentity: string;
	selfCurrentBreakoutId?: number | null;
	onJoinRoom?: (breakoutId: number) => void;
	onReturnToMain?: () => void;
}

function baseProps(over: Partial<Props> = {}): Props {
	return {
		meetingId: 42,
		breakouts: [],
		assignments: {},
		participants: PARTICIPANTS,
		selfIdentity: 'u:1',
		...over,
	};
}

describe('BreakoutsPanel — open (no breakouts yet)', () => {
	it('open calls openBreakouts(meetingId, count, undefined, autoAssign)', async () => {
		openBreakouts.mockResolvedValue({ breakouts: ROOMS });
		render(BreakoutsPanel, baseProps());

		await fireEvent.change(screen.getByTestId('breakouts-count'), { target: { value: '3' } });
		await fireEvent.click(screen.getByRole('switch')); // autoAssign
		await fireEvent.click(screen.getByTestId('breakouts-open'));

		expect(openBreakouts).toHaveBeenCalledWith(42, 3, undefined, true);
		await vi.waitFor(() => expect(screen.getAllByText('Room A').length).toBeGreaterThan(0));
	});

	it('a count 1..20 stepper offers exactly 20 options', () => {
		render(BreakoutsPanel, baseProps());
		const select = screen.getByTestId('breakouts-count') as HTMLSelectElement;
		expect(select.options.length).toBe(20);
		expect(select.options[0].value).toBe('1');
		expect(select.options[19].value).toBe('20');
	});

	it('an open failure toasts openFailed', async () => {
		openBreakouts.mockRejectedValue(new Error('boom'));
		render(BreakoutsPanel, baseProps());
		await fireEvent.click(screen.getByTestId('breakouts-open'));
		await vi.waitFor(() =>
			expect(toasts.some((t) => t.message === 'Could not open breakout rooms')).toBe(true),
		);
	});
});

describe('BreakoutsPanel — rooms open', () => {
	it('D3: lists ONLY assignable targets — self and guests are filtered client-side', () => {
		render(BreakoutsPanel, baseProps({ breakouts: ROOMS }));
		expect(screen.queryByTestId('breakouts-assign-u:1')).toBeNull(); // self
		expect(screen.queryByTestId('breakouts-assign-g:9')).toBeNull(); // guest
		expect(screen.getByTestId('breakouts-assign-u:2')).toBeTruthy();
		expect(screen.getByTestId('breakouts-assign-u:3')).toBeTruthy();
	});

	it('a default (NULL) title renders via defaultName with the room idx', () => {
		render(BreakoutsPanel, baseProps({ breakouts: ROOMS }));
		expect(screen.getAllByText('Breakout 2').length).toBeGreaterThan(0);
	});

	it('selecting a room for a participant calls assignBreakout(meetingId, targetUserId, breakoutId)', async () => {
		assignBreakout.mockResolvedValue(undefined);
		render(BreakoutsPanel, baseProps({ breakouts: ROOMS }));
		await fireEvent.change(screen.getByTestId('breakouts-assign-u:2'), { target: { value: '10' } });
		expect(assignBreakout).toHaveBeenCalledWith(42, 2, 10);
	});

	it('selecting "Main room" calls assignBreakout with breakoutId null', async () => {
		assignBreakout.mockResolvedValue(undefined);
		render(BreakoutsPanel, baseProps({ breakouts: ROOMS, assignments: { 'u:2': 10 } }));
		await fireEvent.change(screen.getByTestId('breakouts-assign-u:2'), { target: { value: '' } });
		expect(assignBreakout).toHaveBeenCalledWith(42, 2, null);
	});

	// D3 wire note: the eviction-502 case is informational, never alarming —
	// the DB assignment already committed, the worker heals the eviction.
	it('a 5xx assign failure (the eviction-502 case) toasts the informational assignFailed copy and is NOT reverted', async () => {
		assignBreakout.mockRejectedValue(new MeetError({ status: 502, code: '', detail: 'evict failed' }));
		render(BreakoutsPanel, baseProps({ breakouts: ROOMS }));
		await fireEvent.change(screen.getByTestId('breakouts-assign-u:2'), { target: { value: '10' } });
		await vi.waitFor(() =>
			expect(toasts.some((t) => t.message === 'Assignment saved — the move completes automatically.')).toBe(true),
		);
		// never reverted — the select still shows the optimistic value
		expect((screen.getByTestId('breakouts-assign-u:2') as HTMLSelectElement).value).toBe('10');
	});

	// B3 retro fix (design finding #4): a genuine failure (4xx/network) never
	// committed server-side — revert the optimistic write and say so plainly.
	it('a 4xx assign failure reverts the optimistic write and toasts the genuine-failure assignRejected copy', async () => {
		assignBreakout.mockRejectedValue(new MeetError({ status: 422, code: 'BZ201', detail: 'breakout invalid' }));
		render(BreakoutsPanel, baseProps({ breakouts: ROOMS }));
		await fireEvent.change(screen.getByTestId('breakouts-assign-u:2'), { target: { value: '10' } });
		await vi.waitFor(() => expect(toasts.some((t) => t.message === 'Could not assign — please try again')).toBe(true));
		await vi.waitFor(() => expect((screen.getByTestId('breakouts-assign-u:2') as HTMLSelectElement).value).toBe(''));
	});

	// A network/transport error (no MeetError, no status at all) is the SAME
	// genuine-failure branch as a 4xx — status defaults to 0.
	it('a network error (no status) also reverts and toasts assignRejected', async () => {
		assignBreakout.mockRejectedValue(new Error('offline'));
		render(BreakoutsPanel, baseProps({ breakouts: ROOMS }));
		await fireEvent.change(screen.getByTestId('breakouts-assign-u:2'), { target: { value: '10' } });
		await vi.waitFor(() => expect(toasts.some((t) => t.message === 'Could not assign — please try again')).toBe(true));
		await vi.waitFor(() => expect((screen.getByTestId('breakouts-assign-u:2') as HTMLSelectElement).value).toBe(''));
	});

	it('Close all disables in-flight and re-enables on error', async () => {
		let resolveClose: (() => void) | undefined;
		closeBreakouts.mockImplementation(
			() =>
				new Promise<void>((_resolve, reject) => {
					resolveClose = () => reject(new Error('close failed'));
				}),
		);
		render(BreakoutsPanel, baseProps({ breakouts: ROOMS }));
		await fireEvent.click(screen.getByTestId('breakouts-close-all'));
		expect((screen.getByTestId('breakouts-close-all') as HTMLButtonElement).disabled).toBe(true);
		resolveClose?.();
		await vi.waitFor(() => expect((screen.getByTestId('breakouts-close-all') as HTMLButtonElement).disabled).toBe(false));
		await vi.waitFor(() => expect(toasts.some((t) => t.message === 'Could not close breakout rooms')).toBe(true));
	});

	it('Close all on success clears the room list — the open form reappears', async () => {
		closeBreakouts.mockResolvedValue(undefined);
		render(BreakoutsPanel, baseProps({ breakouts: ROOMS }));
		await fireEvent.click(screen.getByTestId('breakouts-close-all'));
		await vi.waitFor(() => expect(screen.getByTestId('breakouts-open')).toBeTruthy());
	});

	it('a live assignments prop update (the panel map, e.g. a breakout_assigned push) re-seeds the select without a re-fetch', async () => {
		const { rerender } = render(BreakoutsPanel, baseProps({ breakouts: ROOMS }));
		expect((screen.getByTestId('breakouts-assign-u:2') as HTMLSelectElement).value).toBe('');
		await rerender(baseProps({ breakouts: ROOMS, assignments: { 'u:2': 11 } }));
		await vi.waitFor(() => expect((screen.getByTestId('breakouts-assign-u:2') as HTMLSelectElement).value).toBe('11'));
	});
});

// B3 retro fix (design finding #1 — host/cohost roaming): the reducer/route
// layer already supported a host/cohost joining a breakout room; this panel
// gains the UI entry point.
describe('BreakoutsPanel — host/cohost roaming (retro fix)', () => {
	it('clicking Join on a room calls onJoinRoom with that room\'s id', async () => {
		const onJoinRoom = vi.fn();
		render(BreakoutsPanel, baseProps({ breakouts: ROOMS, onJoinRoom }));
		await fireEvent.click(screen.getByTestId('breakouts-join-10'));
		expect(onJoinRoom).toHaveBeenCalledWith(10);
	});

	it('does not offer a Join button for the room the caller is ALREADY in', () => {
		render(BreakoutsPanel, baseProps({ breakouts: ROOMS, onJoinRoom: vi.fn(), selfCurrentBreakoutId: 10 }));
		expect(screen.queryByTestId('breakouts-join-10')).toBeNull();
		expect(screen.getByTestId('breakouts-join-11')).toBeTruthy();
	});

	it('no Join button renders at all when onJoinRoom is undefined (the member/hide-when-undefined posture — D3)', () => {
		render(BreakoutsPanel, baseProps({ breakouts: ROOMS }));
		expect(screen.queryByTestId('breakouts-join-10')).toBeNull();
		expect(screen.queryByTestId('breakouts-join-11')).toBeNull();
	});

	it('shows "Return to main" only while roaming (selfCurrentBreakoutId !== null), and clicking it calls onReturnToMain', async () => {
		const onReturnToMain = vi.fn();
		const { rerender } = render(
			BreakoutsPanel,
			baseProps({ breakouts: ROOMS, onReturnToMain, selfCurrentBreakoutId: null }),
		);
		expect(screen.queryByTestId('breakouts-return-main')).toBeNull();

		await rerender(baseProps({ breakouts: ROOMS, onReturnToMain, selfCurrentBreakoutId: 10 }));
		expect(screen.getByTestId('breakouts-return-main')).toBeTruthy();
		await fireEvent.click(screen.getByTestId('breakouts-return-main'));
		expect(onReturnToMain).toHaveBeenCalled();
	});

	it('no "Return to main" affordance renders when onReturnToMain is undefined', () => {
		render(BreakoutsPanel, baseProps({ breakouts: ROOMS, selfCurrentBreakoutId: 10 }));
		expect(screen.queryByTestId('breakouts-return-main')).toBeNull();
	});
});
