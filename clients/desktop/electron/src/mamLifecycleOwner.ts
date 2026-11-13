//! Exactly-one MAM start/resume composition owner for Electron.
//!
//! The production root constructs one process-wide instance with mode `off`.
//! A later Connectivity E4 rollout may narrow trusted policy/build input onto
//! the same off/observe/execute contract; it must not create another timer.

export type MamRolloutMode = 'off' | 'observe' | 'execute';

export const DEFAULT_MAM_ROLLOUT_MODE: MamRolloutMode = 'off';
export const MAM_PERIODIC_INTERVAL_MS = 15 * 60 * 1000;

export interface MamLifecycleClock {
	setInterval(callback: () => void, intervalMs: number): ReturnType<typeof setInterval>;
	clearInterval(timer: ReturnType<typeof setInterval>): void;
}

const systemClock: MamLifecycleClock = {
	setInterval: (callback, intervalMs) => setInterval(callback, intervalMs),
	clearInterval: (timer) => clearInterval(timer),
};

export class MamLifecycleOwner {
	private started = false;
	private foreground = true;
	private inFlight: Promise<void> | null = null;
	private pendingOpportunity = false;
	private timer: ReturnType<typeof setInterval> | null = null;

	constructor(
		private readonly mode: MamRolloutMode,
		private readonly checkin: () => Promise<unknown>,
		private readonly onError: (error: unknown) => void = () => {},
		private readonly clock: MamLifecycleClock = systemClock,
	) {}

	start(): void {
		if (this.started) return;
		this.started = true;
		this.foreground = true;
		if (this.mode !== 'execute') return;
		this.requestOpportunity();
		this.timer = this.clock.setInterval(() => this.requestOpportunity(), MAM_PERIODIC_INTERVAL_MS);
	}

	pause(): void {
		if (!this.started) return;
		this.foreground = false;
	}

	resume(): void {
		if (!this.started || this.foreground) return;
		this.foreground = true;
		this.requestOpportunity();
	}

	stop(): void {
		if (!this.started) return;
		this.started = false;
		this.foreground = false;
		this.pendingOpportunity = false;
		if (this.timer !== null) {
			this.clock.clearInterval(this.timer);
			this.timer = null;
		}
	}

	private requestOpportunity(): void {
		if (!this.started || !this.foreground || this.mode !== 'execute') return;
		if (this.inFlight !== null) {
			this.pendingOpportunity = true;
			return;
		}
		this.inFlight = Promise.resolve()
			.then(() => this.checkin())
			.catch((error) => this.onError(error))
			.then(() => {})
			.finally(() => {
				this.inFlight = null;
				if (this.pendingOpportunity && this.started && this.foreground) {
					this.pendingOpportunity = false;
					this.requestOpportunity();
				}
			});
	}
}
