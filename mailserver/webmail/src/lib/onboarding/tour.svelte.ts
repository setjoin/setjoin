// Welcome-tour persistence, request signal, and one per-host run controller.
// DOM-free so state transitions unit-test by direct calls.
// Do not mutate `tourRequest` from outside — use requestTour()/consumeRequest().

import type { TourStep } from './steps';

const SEEN_PREFIX = 'sj-welcome-tour:';

export function seenKey(email: string): string {
	return SEEN_PREFIX + email;
}

export function hasSeenTour(email: string): boolean {
	if (!email) return true; // no identity → never auto-show
	try {
		return localStorage.getItem(seenKey(email)) === '1';
	} catch {
		return false;
	}
}

export function markTourSeen(email: string): void {
	if (!email) return;
	try {
		localStorage.setItem(seenKey(email), '1');
	} catch {
		/* storage unavailable — best effort */
	}
}

export type TourStartReason = 'auto' | 'replay';
export type TourPhase =
	| 'idle'
	| 'resolving'
	| 'active'
	| 'suspended'
	| 'completed'
	| 'skipped'
	| 'failed-safe';

export const tourRequest = $state<{
	pending: boolean;
	force: boolean;
	trigger: HTMLElement | null;
}>({ pending: false, force: false, trigger: null });

// Compatibility signal for shell observers and existing tests. It no longer
// makes the application inert; the per-host controller is authoritative.
export const tourUi = $state<{ active: boolean }>({ active: false });

export function requestTour(force = false): void {
	tourRequest.force = force;
	tourRequest.trigger =
		force && typeof document !== 'undefined' && document.activeElement instanceof HTMLElement
			? document.activeElement
			: null;
	tourRequest.pending = true;
}

export function consumeRequest(): void {
	tourRequest.pending = false;
}

export interface TourRunState {
	phase: TourPhase;
	startReason: TourStartReason;
	userEmail: string;
	startPath: string;
	steps: TourStep[];
	index: number;
	resumeIndex: number;
	restoreFocus: HTMLElement | null;
}

export interface TourRunController {
	state: TourRunState;
	readonly current: TourStep | undefined;
	readonly isFirst: boolean;
	readonly isLast: boolean;
	beginResolving(reason: TourStartReason, trigger: HTMLElement | null): void;
	start(input: { userEmail: string; pathname: string; steps: TourStep[] }): void;
	cancelResolution(): void;
	next(): void;
	back(): void;
	suspend(advanceCurrent?: boolean): void;
	resume(): void;
	complete(): void;
	skip(): void;
	failSafe(): void;
	reset(): void;
}

export function createTourRun(
	persistSeen: (email: string) => void = markTourSeen,
): TourRunController {
	const state = $state<TourRunState>({
		phase: 'idle',
		startReason: 'auto',
		userEmail: '',
		startPath: '',
		steps: [],
		index: 0,
		resumeIndex: 0,
		restoreFocus: null,
	});

	function close(phase: Extract<TourPhase, 'completed' | 'skipped' | 'failed-safe'>) {
		if (state.userEmail) persistSeen(state.userEmail);
		state.phase = phase;
		tourUi.active = false;
		const restore = state.startReason === 'replay' ? state.restoreFocus : null;
		state.steps = [];
		state.index = 0;
		state.resumeIndex = 0;
		state.restoreFocus = null;
		if (restore?.isConnected) restore.focus();
	}

	const controller: TourRunController = {
		state,
		get current() {
			return state.steps[state.index];
		},
		get isFirst() {
			return state.index === 0;
		},
		get isLast() {
			return state.index === state.steps.length - 1;
		},
		beginResolving(reason, trigger) {
			state.phase = 'resolving';
			state.startReason = reason;
			state.restoreFocus = reason === 'replay' ? trigger : null;
			state.steps = [];
			state.index = 0;
			state.resumeIndex = 0;
			tourUi.active = false;
		},
		start(input) {
			if (input.steps.length === 0) {
				controller.cancelResolution();
				return;
			}
			state.userEmail = input.userEmail;
			state.startPath = input.pathname;
			state.steps = input.steps;
			state.index = 0;
			state.resumeIndex = 0;
			state.phase = 'active';
			tourUi.active = true;
		},
		cancelResolution() {
			state.phase = 'idle';
			state.steps = [];
			state.index = 0;
			state.resumeIndex = 0;
			state.restoreFocus = null;
			tourUi.active = false;
		},
		next() {
			if (state.phase !== 'active') return;
			if (controller.isLast) controller.complete();
			else state.index += 1;
		},
		back() {
			if (state.phase === 'active' && state.index > 0) state.index -= 1;
		},
		suspend(advanceCurrent = false) {
			if (state.phase !== 'active') return;
			state.resumeIndex = advanceCurrent ? state.index + 1 : state.index;
			state.phase = 'suspended';
			tourUi.active = false;
		},
		resume() {
			if (state.phase !== 'suspended') return;
			if (state.resumeIndex >= state.steps.length) {
				controller.complete();
				return;
			}
			state.index = state.resumeIndex;
			state.phase = 'active';
			tourUi.active = true;
		},
		complete() {
			close('completed');
		},
		skip() {
			close('skipped');
		},
		failSafe() {
			close('failed-safe');
		},
		reset() {
			state.phase = 'idle';
			state.startReason = 'auto';
			state.userEmail = '';
			state.startPath = '';
			state.steps = [];
			state.index = 0;
			state.resumeIndex = 0;
			state.restoreFocus = null;
			tourUi.active = false;
		},
	};
	return controller;
}

export function shouldAutoRequestTour(o: {
	authInitializing: boolean;
	authenticated: boolean;
	pathname: string;
	email: string | undefined;
	alreadyRequested: boolean;
}): boolean {
	return (
		!o.alreadyRequested &&
		!o.authInitializing &&
		o.authenticated &&
		o.pathname.startsWith('/inbox') &&
		!!o.email
	);
}
