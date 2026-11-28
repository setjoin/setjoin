// LobbyWaiting.test.ts — Meet B1 Task 16 named test: the member state
// machine (pending → admitted / denied / expired). Design #2: this is the
// SAME component the guest join page (Task 17) reuses — its own fuller
// backoff/network-error/ask-again suite lands there.
import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen } from '@testing-library/svelte/svelte5';
import { createRawSnippet } from 'svelte';
import LobbyWaiting from './LobbyWaiting.svelte';
import { MeetError } from '$lib/meet/api';

const guestPoll = vi.fn();
vi.mock('$lib/meet/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/meet/api')>('$lib/meet/api');
	return { ...actual, guestPoll: (...a: unknown[]) => guestPoll(...a) };
});

afterEach(() => vi.clearAllMocks());

describe('LobbyWaiting', () => {
	it('renders the pending state and polls guestPoll(slug, requestId, secret)', () => {
		guestPoll.mockReturnValue(new Promise(() => {})); // never resolves — stays pending
		render(LobbyWaiting, { slug: 's1', requestId: 7, secret: 'sec', onAdmitted: vi.fn() });
		expect(screen.getByTestId('lobby-waiting').dataset.state).toBe('pending');
		expect(guestPoll).toHaveBeenCalledWith('s1', 7, 'sec');
	});

	it('transitions to admitted and calls onAdmitted with the token (and recordingActive, captionsOn, ccIdentity) on an admitted poll result', async () => {
		guestPoll.mockResolvedValue({ state: 'admitted', token: 'tok', wsPath: '/rtc', expiresAt: 'later' });
		const onAdmitted = vi.fn();
		render(LobbyWaiting, { slug: 's1', requestId: 7, secret: 'sec', onAdmitted });
		await vi.waitFor(() => expect(screen.getByTestId('lobby-waiting').dataset.state).toBe('admitted'));
		expect(onAdmitted).toHaveBeenCalledWith({ token: 'tok', wsPath: '/rtc', expiresAt: 'later' }, false, false, '');
	});

	// Meet B2 Task 10, D5's flicker-window belt.
	it('the pending screen shows the recording consent line when the poll carries recordingActive', async () => {
		guestPoll.mockResolvedValue({ state: 'pending', recordingActive: true });
		render(LobbyWaiting, { slug: 's1', requestId: 7, secret: 'sec', onAdmitted: vi.fn() });
		await vi.waitFor(() => expect(screen.getByText('This meeting is being recorded')).toBeTruthy());
	});

	it('onAdmitted carries recordingActive=true when the admitted grant carries it', async () => {
		guestPoll.mockResolvedValue({ state: 'admitted', token: 'tok', wsPath: '/rtc', expiresAt: 'later', recordingActive: true });
		const onAdmitted = vi.fn();
		render(LobbyWaiting, { slug: 's1', requestId: 7, secret: 'sec', onAdmitted });
		await vi.waitFor(() =>
			expect(onAdmitted).toHaveBeenCalledWith({ token: 'tok', wsPath: '/rtc', expiresAt: 'later' }, true, false, ''),
		);
	});

	// B3 Task 15, DN3: the captions indicator rides the SAME admitted grant.
	it('onAdmitted carries captionsOn=true when the admitted grant carries it', async () => {
		guestPoll.mockResolvedValue({ state: 'admitted', token: 'tok', wsPath: '/rtc', expiresAt: 'later', captionsOn: true });
		const onAdmitted = vi.fn();
		render(LobbyWaiting, { slug: 's1', requestId: 7, secret: 'sec', onAdmitted });
		await vi.waitFor(() =>
			expect(onAdmitted).toHaveBeenCalledWith({ token: 'tok', wsPath: '/rtc', expiresAt: 'later' }, false, true, ''),
		);
	});

	// B3 retro fix (design findings #4/#5): ccIdentity rides the SAME
	// admitted grant, unconditional on captionsOn — the guest-captions
	// attestation ceiling fix.
	it('onAdmitted carries ccIdentity when the admitted grant carries it', async () => {
		guestPoll.mockResolvedValue({ state: 'admitted', token: 'tok', wsPath: '/rtc', expiresAt: 'later', ccIdentity: 'cc:42' });
		const onAdmitted = vi.fn();
		render(LobbyWaiting, { slug: 's1', requestId: 7, secret: 'sec', onAdmitted });
		await vi.waitFor(() =>
			expect(onAdmitted).toHaveBeenCalledWith(
				{ token: 'tok', wsPath: '/rtc', expiresAt: 'later' },
				false,
				false,
				'cc:42',
			),
		);
	});

	it('transitions to denied on a denied poll result', async () => {
		guestPoll.mockResolvedValue({ state: 'denied' });
		render(LobbyWaiting, { slug: 's1', requestId: 7, secret: 'sec', onAdmitted: vi.fn() });
		await vi.waitFor(() => expect(screen.getByTestId('lobby-waiting').dataset.state).toBe('denied'));
	});

	it('transitions to expired on an expired poll result', async () => {
		guestPoll.mockResolvedValue({ state: 'expired' });
		render(LobbyWaiting, { slug: 's1', requestId: 7, secret: 'sec', onAdmitted: vi.fn() });
		await vi.waitFor(() => expect(screen.getByTestId('lobby-waiting').dataset.state).toBe('expired'));
	});

	// Task 17's fuller backoff/network-error suite, promised by this file's
	// own header comment.
	it('a network error just retries at the base 3s+jitter cadence — never surfaced as an error', async () => {
		vi.useFakeTimers();
		guestPoll.mockRejectedValueOnce(new Error('offline blip')).mockResolvedValue({ state: 'pending' });
		render(LobbyWaiting, { slug: 's1', requestId: 7, secret: 'sec', onAdmitted: vi.fn() });
		await vi.waitFor(() => expect(guestPoll).toHaveBeenCalledTimes(1));
		expect(screen.getByTestId('lobby-waiting').dataset.state).toBe('pending'); // no error flash
		await vi.advanceTimersByTimeAsync(3600); // base 3000ms + up to 500ms jitter
		await vi.waitFor(() => expect(guestPoll).toHaveBeenCalledTimes(2));
		expect(screen.getByTestId('lobby-waiting').dataset.state).toBe('pending');
		vi.useRealTimers();
	});

	it('a 429 backs off to 10s, keeping the SAME pending copy (design #16 — never an error flash)', async () => {
		vi.useFakeTimers();
		guestPoll
			.mockRejectedValueOnce(new MeetError({ status: 429, code: '', detail: 'rate limited' }))
			.mockResolvedValue({ state: 'pending' });
		render(LobbyWaiting, { slug: 's1', requestId: 7, secret: 'sec', onAdmitted: vi.fn() });
		await vi.waitFor(() => expect(guestPoll).toHaveBeenCalledTimes(1));
		expect(screen.getByText('Waiting for the host to let you in…')).toBeTruthy();
		await vi.advanceTimersByTimeAsync(3600); // base cadence alone must NOT have fired the retry yet
		expect(guestPoll).toHaveBeenCalledTimes(1);
		await vi.advanceTimersByTimeAsync(6500); // …but the full 10s backoff does
		await vi.waitFor(() => expect(guestPoll).toHaveBeenCalledTimes(2));
		expect(screen.getByText('Waiting for the host to let you in…')).toBeTruthy(); // same copy, no error
		vi.useRealTimers();
	});

	// Task 17: the `expired` snippet the guest join page renders an "Ask
	// again" button through — LobbyWaiting itself is agnostic to what's in it.
	it('renders the `expired` snippet only while state === expired', async () => {
		guestPoll.mockResolvedValue({ state: 'expired' });
		render(LobbyWaiting, {
			slug: 's1',
			requestId: 7,
			secret: 'sec',
			onAdmitted: vi.fn(),
			expired: createRawSnippet(() => ({ render: () => `<button>ask-again-marker</button>` })),
		});
		await vi.waitFor(() => expect(screen.getByText('ask-again-marker')).toBeTruthy());
	});
});
