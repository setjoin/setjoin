import { browser } from '$app/environment';

// Debug logger for webmail frontend.
// In dev builds (vite dev) this is on by default.
// In production builds it is off unless ?debug=1 is in the URL.
const enabled = browser
	? import.meta.env.DEV || new URLSearchParams(window.location.search).has('debug')
	: false;

function timestamp(): string {
	return new Date().toISOString();
}

export const logger = {
	log(action: string, detail?: unknown) {
		if (!enabled) return;

		console.log(`[${timestamp()}] [webmail] ${action}`, detail !== undefined ? detail : '');
	},
	error(action: string, err: unknown) {
		if (!enabled) return;

		console.error(`[${timestamp()}] [webmail] ${action}`, err);
	},
	warn(action: string, detail?: unknown) {
		if (!enabled) return;

		console.warn(`[${timestamp()}] [webmail] ${action}`, detail !== undefined ? detail : '');
	},
};
