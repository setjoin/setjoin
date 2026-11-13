export type InboxReadiness = 'inactive' | 'loading' | 'loaded-empty' | 'loaded-populated';

export interface TourHostContext {
	setInboxReadiness(readiness: InboxReadiness): void;
}

export const TOUR_HOST_CONTEXT = Symbol('setjoin-tour-host');
