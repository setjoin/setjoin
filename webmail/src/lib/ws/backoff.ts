// Shared exponential backoff with full random jitter (AWS "Exponential Backoff
// And Jitter" — Full Jitter) and connection-stability uptime gating (#389).
//
// Used by the JMAP WebSocket push hub, the guest EventSource/SSE stream, and
// the Chat presence poller so a gateway restart or network blip spreads
// client reconnects across the backoff window instead of creating a thundering
// herd.

export const DEFAULT_BASE_DELAY_MS = 1000;
export const DEFAULT_MAX_DELAY_MS = 60_000;
export const DEFAULT_STABLE_UPTIME_MS = 15_000;

const MAX_EXPONENT = 30;

export interface ReconnectBackoffOptions {
	/** Base delay in ms for attempt 0 (default: 1000 ms). */
	baseDelayMs?: number;
	/** Maximum backoff cap in ms (default: 60000 ms). */
	maxDelayMs?: number;
	/**
	 * Minimum continuous connected/healthy duration in ms before a subsequent
	 * disconnect resets the attempt counter back to 0 (default: 15000 ms).
	 * Prevents flapping sockets (accept → immediate drop) from pinning retries
	 * at the base interval.
	 */
	stableUptimeMs?: number;
	/** Random source returning a float in [0, 1). Injectable for deterministic tests. */
	random?: () => number;
	/** Clock returning epoch/monotonic ms. Injectable for deterministic tests. */
	now?: () => number;
}

function clampUnitRandom(raw: number): number {
	if (!Number.isFinite(raw)) return 0.5;
	if (raw <= 0) return 0;
	if (raw >= 1) return 1;
	return raw;
}

/**
 * Computes the uncapped-jitter exponential ceiling `min(maxDelayMs, baseDelayMs * 2^attempt)`.
 */
export function computeBackoffCeilingMs(
	attempt: number,
	baseDelayMs = DEFAULT_BASE_DELAY_MS,
	maxDelayMs = DEFAULT_MAX_DELAY_MS,
): number {
	const safeBase = Math.max(0, Number.isFinite(baseDelayMs) ? baseDelayMs : DEFAULT_BASE_DELAY_MS);
	const safeMax = Math.max(safeBase, Number.isFinite(maxDelayMs) ? maxDelayMs : DEFAULT_MAX_DELAY_MS);
	const safeAttempt = Math.min(MAX_EXPONENT, Math.max(0, Math.floor(Number.isFinite(attempt) ? attempt : 0)));
	return Math.min(safeMax, safeBase * 2 ** safeAttempt);
}

/**
 * Full-jitter exponential backoff delay in `[0, min(maxDelayMs, baseDelayMs * 2^attempt)]`.
 */
export function computeFullJitterDelayMs(
	attempt: number,
	baseDelayMs = DEFAULT_BASE_DELAY_MS,
	maxDelayMs = DEFAULT_MAX_DELAY_MS,
	random: () => number = () => Math.random(),
): number {
	const ceiling = computeBackoffCeilingMs(attempt, baseDelayMs, maxDelayMs);
	const unit = clampUnitRandom(random());
	return unit >= 1 ? ceiling : Math.floor(unit * ceiling);
}

/**
 * Computes a jittered steady-state poll interval in `[baseIntervalMs, baseIntervalMs + jitterMs]`.
 * Keeping jitter additive preserves server rate ceilings like `<= 1 / 60s` while
 * desynchronizing clients that mounted or reconnected together.
 */
export function computeJitteredIntervalMs(
	baseIntervalMs: number,
	jitterMs: number,
	random: () => number = () => Math.random(),
): number {
	const safeBase = Math.max(0, Number.isFinite(baseIntervalMs) ? baseIntervalMs : 0);
	const safeJitter = Math.max(0, Number.isFinite(jitterMs) ? jitterMs : 0);
	if (safeJitter === 0) return safeBase;
	const unit = clampUnitRandom(random());
	return safeBase + (unit >= 1 ? safeJitter : Math.floor(unit * safeJitter));
}

/**
 * Stateful reconnect backoff tracker with uptime-gated attempt resets.
 *
 * Call `markConnected()` when a transport opens (or a poll succeeds) and
 * `markDisconnected()` when it drops (or fails). The attempt counter resets to
 * 0 ONLY if the connection remained up for at least `stableUptimeMs`.
 */
export class ReconnectBackoff {
	readonly #baseDelayMs: number;
	readonly #maxDelayMs: number;
	readonly #stableUptimeMs: number;
	readonly #random: () => number;
	readonly #now: () => number;

	#attempt = 0;
	#connectedAt: number | null = null;

	constructor(options: ReconnectBackoffOptions = {}) {
		this.#baseDelayMs = options.baseDelayMs ?? DEFAULT_BASE_DELAY_MS;
		this.#maxDelayMs = options.maxDelayMs ?? DEFAULT_MAX_DELAY_MS;
		this.#stableUptimeMs = Math.max(
			0,
			typeof options.stableUptimeMs === 'number' && Number.isFinite(options.stableUptimeMs)
				? options.stableUptimeMs
				: DEFAULT_STABLE_UPTIME_MS,
		);
		// Defer global lookups until call time so Vitest fake timers and spies take effect.
		this.#random = options.random ?? (() => Math.random());
		this.#now = options.now ?? (() => Date.now());
	}

	/** Current attempt index that will be used on the next disconnect (unless reset by stability). */
	get attempt(): number {
		return this.#attempt;
	}

	/** Timestamp when the current connection became healthy, or null if disconnected. */
	get connectedAt(): number | null {
		return this.#connectedAt;
	}

	/** True when currently connected and uptime has met or exceeded `stableUptimeMs`. */
	hasReachedStableUptime(): boolean {
		return this.#connectedAt !== null && this.#now() - this.#connectedAt >= this.#stableUptimeMs;
	}

	/**
	 * Records that the transport is open/healthy. Preserves an existing open
	 * timestamp if invoked redundantly on the same connection, and does NOT
	 * reset the backoff attempt until `stableUptimeMs` elapses.
	 */
	markConnected(): void {
		if (this.#connectedAt === null) {
			this.#connectedAt = this.#now();
		}
	}

	/**
	 * Records a drop/failure and returns the next full-jitter delay in ms.
	 * Resets the attempt counter to 0 first if the connection stayed healthy for
	 * at least `stableUptimeMs`.
	 */
	markDisconnected(): number {
		if (this.hasReachedStableUptime()) {
			this.#attempt = 0;
		}
		this.#connectedAt = null;
		const delayMs = computeFullJitterDelayMs(this.#attempt, this.#baseDelayMs, this.#maxDelayMs, this.#random);
		this.#attempt += 1;
		return delayMs;
	}

	/** Explicit teardown reset (e.g. logout or unsubscribe). */
	reset(): void {
		this.#attempt = 0;
		this.#connectedAt = null;
	}
}
