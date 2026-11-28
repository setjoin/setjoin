import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
	seenKey, hasSeenTour, markTourSeen,
	tourRequest, requestTour, consumeRequest,
	shouldAutoRequestTour,
	tourUi,
	createTourRun,
} from './tour.svelte';
import type { TourStep } from './steps';

describe('tour store — seen flag', () => {
	beforeEach(() => {
		localStorage.clear();
		consumeRequest();
	});

	it('keys per email', () => {
		expect(seenKey('a@x.test')).toBe('sj-welcome-tour:a@x.test');
	});

	it('round-trips, scoped per email', () => {
		expect(hasSeenTour('a@x.test')).toBe(false);
		markTourSeen('a@x.test');
		expect(hasSeenTour('a@x.test')).toBe(true);
		expect(hasSeenTour('b@x.test')).toBe(false);
	});
});

describe('tour store — request signal', () => {
	beforeEach(() => consumeRequest());

	it('requestTour sets pending + force; consumeRequest clears', () => {
		requestTour(true);
		expect(tourRequest.pending).toBe(true);
		expect(tourRequest.force).toBe(true);
		consumeRequest();
		expect(tourRequest.pending).toBe(false);
	});
});

describe('tour store — shouldAutoRequestTour', () => {
	const base = { authInitializing: false, authenticated: true, pathname: '/inbox', email: 'a@x.test', alreadyRequested: false };

	it('true on the happy path', () => {
		expect(shouldAutoRequestTour(base)).toBe(true);
	});
	it('false while auth initializing', () => {
		expect(shouldAutoRequestTour({ ...base, authInitializing: true })).toBe(false);
	});
	it('false when unauthenticated', () => {
		expect(shouldAutoRequestTour({ ...base, authenticated: false })).toBe(false);
	});
	it('false off the inbox route', () => {
		expect(shouldAutoRequestTour({ ...base, pathname: '/calendar' })).toBe(false);
	});
	it('false without an email', () => {
		expect(shouldAutoRequestTour({ ...base, email: undefined })).toBe(false);
	});
	it('false once already requested', () => {
		expect(shouldAutoRequestTour({ ...base, alreadyRequested: true })).toBe(false);
	});
});

describe('tour store — tourUi', () => {
	it('active is false by default', () => {
		expect(tourUi.active).toBe(false);
	});
});

const steps: TourStep[] = [
	{ id: 'apps', target: '[data-tour="apps"]', placement: 'right', titleKey: 'a', bodyKey: 'b' },
	{ id: 'compose', target: '[data-tour="compose"]', placement: 'right', titleKey: 'c', bodyKey: 'd' },
	{ id: 'search', target: '[data-tour="search"]', placement: 'bottom', titleKey: 'e', bodyKey: 'f' },
];

describe('createTourRun', () => {
	it('owns an exact per-run step set and forward/back transitions', () => {
		const persisted: string[] = [];
		const run = createTourRun((email) => persisted.push(email));
		run.beginResolving('auto', null);
		run.start({ userEmail: 'a@x.test', pathname: '/inbox', steps });
		expect(run.state.phase).toBe('active');
		expect(run.current?.id).toBe('apps');
		run.next();
		expect(run.current?.id).toBe('compose');
		run.back();
		expect(run.current?.id).toBe('apps');
		expect(persisted).toEqual([]);
	});

	it('suspends and resumes either the same or next logical step', () => {
		const run = createTourRun();
		run.beginResolving('auto', null);
		run.start({ userEmail: 'a@x.test', pathname: '/inbox', steps });
		run.suspend(false);
		expect(run.state.phase).toBe('suspended');
		run.resume();
		expect(run.current?.id).toBe('apps');
		run.suspend(true);
		run.resume();
		expect(run.current?.id).toBe('compose');
	});

	it('persists only terminal outcomes, never a zero-anchor resolution', () => {
		const persisted: string[] = [];
		const run = createTourRun((email) => persisted.push(email));
		run.beginResolving('auto', null);
		run.start({ userEmail: 'a@x.test', pathname: '/inbox', steps: [] });
		expect(run.state.phase).toBe('idle');
		expect(persisted).toEqual([]);

		run.beginResolving('auto', null);
		run.start({ userEmail: 'a@x.test', pathname: '/inbox', steps });
		run.skip();
		expect(run.state.phase).toBe('skipped');
		expect(persisted).toEqual(['a@x.test']);
	});

	it('restores focus only for an explicit replay', () => {
		const trigger = document.createElement('button');
		document.body.appendChild(trigger);
		const focus = vi.spyOn(trigger, 'focus');
		const run = createTourRun();
		run.beginResolving('replay', trigger);
		run.start({ userEmail: 'a@x.test', pathname: '/inbox', steps });
		run.complete();
		expect(focus).toHaveBeenCalledOnce();

		focus.mockClear();
		run.beginResolving('auto', trigger);
		run.start({ userEmail: 'a@x.test', pathname: '/inbox', steps });
		run.complete();
		expect(focus).not.toHaveBeenCalled();
	});
});
