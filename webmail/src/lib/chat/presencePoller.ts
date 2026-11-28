// Presence poll scheduler with jittered steady-state cadence and full-jitter
// exponential backoff on transient failures (#389).
//
// Steady-state polls stay >= PRESENCE_POLL_BASE_MS (60s — obeys grill Q2's
// <= 1/60s client ceiling) plus additive random jitter [0, 30s] so clients
// mounted or reconnected together do not poll in lockstep. On failure, retries
// back off exponentially with full random jitter (~1s base, ~60s cap) and reset
// only after remaining healthy past the stability threshold.
import {
	computeJitteredIntervalMs,
	ReconnectBackoff,
	type ReconnectBackoffOptions,
} from '$lib/ws/backoff';

export const PRESENCE_POLL_BASE_MS = 60_000;
export const PRESENCE_POLL_JITTER_MS = 30_000;

export interface PresencePollerOptions {
	/** Minimum steady-state interval between successful polls in ms (default: 60000 ms). */
	baseIntervalMs?: number;
	/** Additive random jitter applied to steady-state intervals in ms (default: 30000 ms). */
	jitterMs?: number;
	/** Failure retry backoff configuration (defaults to 1s base, 60s cap, 15s stability). */
	backoff?: ReconnectBackoffOptions;
}

export interface PresencePoller {
	/** Runs a poll immediately (coalescing overlapping calls) and reschedules the loop. */
	triggerNow(): Promise<void>;
	/** Stops all future polls and resets backoff state. */
	stop(): void;
}

export function createPresencePoller(
	poll: () => Promise<void>,
	options: PresencePollerOptions = {},
): PresencePoller {
	const baseIntervalMs = options.baseIntervalMs ?? PRESENCE_POLL_BASE_MS;
	const jitterMs = options.jitterMs ?? PRESENCE_POLL_JITTER_MS;
	const backoff = new ReconnectBackoff(options.backoff);
	const random = options.backoff?.random ?? (() => Math.random());

	let timer: ReturnType<typeof setTimeout> | null = null;
	let inFlight: Promise<void> | null = null;
	let pendingRetrigger = false;
	let stopped = false;

	function clearTimer(): void {
		if (timer !== null) {
			clearTimeout(timer);
			timer = null;
		}
	}

	function schedule(delayMs: number): void {
		if (stopped) return;
		clearTimer();
		timer = setTimeout(() => {
			timer = null;
			void run();
		}, delayMs);
	}

	async function run(): Promise<void> {
		if (stopped) return;
		if (inFlight) {
			pendingRetrigger = true;
			return inFlight;
		}
		clearTimer();
		const task = (async () => {
			try {
				await poll();
				if (stopped) return;
				backoff.markConnected();
				schedule(computeJitteredIntervalMs(baseIntervalMs, jitterMs, random));
			} catch {
				// Stale presence beats a broken poll loop — retry with full-jitter backoff.
				if (stopped) return;
				const retryDelayMs = backoff.markDisconnected();
				schedule(retryDelayMs);
			}
		})();
		inFlight = task;
		try {
			await task;
		} finally {
			inFlight = null;
			if (!stopped && pendingRetrigger) {
				pendingRetrigger = false;
				void run();
			}
		}
	}

	return {
		triggerNow(): Promise<void> {
			return run();
		},
		stop(): void {
			stopped = true;
			pendingRetrigger = false;
			clearTimer();
			backoff.reset();
		},
	};
}
