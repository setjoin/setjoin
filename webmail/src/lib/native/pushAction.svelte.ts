// Bridge contract (QoL #9, DX M7): native shells (mobile OS push, not this
// browser's own SW — see service-worker.ts for that path) call
// window.__setjoinPushAction(actionId, messageId) when the user taps a
// notification action button. The SPA registers the callback once at boot
// (wired from +layout.svelte); see clients/AGENTS.md for the shell-side
// contract this callback fulfills.
import { goto } from '$app/navigation';

interface PendingPushAction {
	actionId: string;
	messageId: string;
}

let pending = $state<PendingPushAction | null>(null);

/**
 * Consumed by the inbox page once its deep-link restore (`?t=`) has resolved
 * the message: an 'archive' action is applied via the page's own archiveEmail
 * (this module only stashes the intent — it doesn't reimplement the mutation).
 * Clears on read so a stale action can't replay on a later, unrelated load.
 */
export function consumePendingPushAction(): PendingPushAction | null {
	const p = pending;
	pending = null;
	return p;
}

/** Registers the bridge callback. Returns an unsubscribe for onMount cleanup. */
export function installPushActionHandler(): () => void {
	const w = window as unknown as { __setjoinPushAction?: (actionId: string, messageId: string) => void };
	w.__setjoinPushAction = (actionId, messageId) => {
		if (actionId === 'archive') pending = { actionId, messageId };
		// Every action (archive included) opens/focuses the message's thread —
		// mirrors the SW's notificationclick routing (routeNotificationClick in
		// service-worker.ts) so native and PWA push land on the same deep link.
		void goto(`/inbox?t=${encodeURIComponent(messageId)}`);
	};
	return () => {
		delete w.__setjoinPushAction;
	};
}
