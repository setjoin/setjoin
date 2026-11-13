/**
 * E4-I balanced Critical-scope composition seam.
 *
 * The E4 Astra integration corrections require balanced begin/end handles with
 * finally/cancellation cleanup — never an untrusted renderer-supplied counter.
 * Repeated lifecycle opportunities coalesce into one counter; teardown removes
 * the ability of stale epoch callbacks to reopen work; and the counter is
 * structurally independent of the optional-work rollout mode, so Optional
 * OFF/observe cannot suppress required security cleanup. Existing MAM
 * OFF/observe semantics remain unchanged; this plan does not enable them.
 *
 * The counter feeds the coordinator's external Critical ingestion
 * (`createCoordinator(...).criticalBegin()`); native security-request
 * begin/end across Electron/Tauri/HarmonyOS lifecycle owners composes with
 * this seam through one subscription per shell.
 */

export interface CriticalScopeHandle {
	/** Idempotent; only the first call releases this scope. */
	end(): void;
	readonly scopeId: number;
	readonly released: boolean;
}

export interface CriticalActivityCounter {
	begin(reason?: string): CriticalScopeHandle;
	count(): number;
	/** True between a 0→1 begin and the matching final end. */
	isActive(): boolean;
	/**
	 * Subscribe to activity-count transitions (0→1 and →0). Multiple
	 * subscribers compose; unsubscribe removes only the given listener.
	 * E4-I Astra correction: the transfer executor subscribes so a Critical
	 * 0→1 transition mid-flight aborts in-flight optional I/O immediately
	 * instead of only being observed at the next cycle boundary.
	 */
	subscribe(listener: (count: number) => void): () => void;
	/**
	 * Permanently close the counter (owner teardown). Open handles' end()
	 * stays safe; stale callbacks can never reopen work afterwards, and
	 * begin() returns no-op handles that never increment.
	 */
	teardown(): void;
	readonly tornDown: boolean;
}

export interface CriticalActivityCounterOptions {
	/** Fired on every 0→1 and →0 transition (coordinator quiet-time ingestion). */
	onTransition?: (count: number) => void;
}

export function createCriticalActivityCounter(
	options: CriticalActivityCounterOptions = {},
): CriticalActivityCounter {
	let count = 0;
	let nextScopeId = 1;
	let tornDown = false;
	const openScopes = new Set<number>();
	const transitionListeners = new Set<(count: number) => void>();

	function emitTransition(next: number): void {
		options.onTransition?.(next);
		for (const listener of [...transitionListeners]) {
			try {
				listener(next);
			} catch {
				// A faulty subscriber can never corrupt the count or other
				// subscribers; the counter stays authoritative.
			}
		}
	}

	const counter: CriticalActivityCounter = {
		begin(reason?: string): CriticalScopeHandle {
			void reason;
			const scopeId = nextScopeId;
			nextScopeId += 1;
			if (tornDown) {
				// Stale epoch callback after teardown: a permanently released handle.
				return { end(): void {}, scopeId, released: true };
			}
			openScopes.add(scopeId);
			count += 1;
			if (count === 1) emitTransition(1);
			return {
				scopeId,
				get released(): boolean {
					return !openScopes.has(scopeId);
				},
				end(): void {
					if (!openScopes.delete(scopeId)) return;
					count -= 1;
					if (count === 0) emitTransition(0);
				},
			};
		},
		count(): number {
			return count;
		},
		isActive(): boolean {
			return count > 0;
		},
		subscribe(listener: (count: number) => void): () => void {
			if (tornDown) return () => {};
			transitionListeners.add(listener);
			return () => {
				transitionListeners.delete(listener);
			};
		},
		teardown(): void {
			if (tornDown) return;
			tornDown = true;
			const hadActivity = count > 0;
			openScopes.clear();
			count = 0;
			if (hadActivity) emitTransition(0);
		},
		get tornDown(): boolean {
			return tornDown;
		},
	};
	return counter;
}

/**
 * Run `fn` inside one balanced scope. The end handle is released on every
 * path — success, throw and cancellation — so failure cannot leak Critical
 * activity and block optional admission forever.
 */
export async function withCriticalScope<T>(
	counter: CriticalActivityCounter,
	fn: () => Promise<T>,
): Promise<T> {
	const handle = counter.begin('withCriticalScope');
	try {
		return await fn();
	} finally {
		handle.end();
	}
}
