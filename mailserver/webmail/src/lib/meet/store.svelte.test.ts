// store.svelte.test.ts — MeetStore structural pins (arch review #A12). These
// three pins used to live in MeetApp.test.ts (raw-source-scanning
// `MeetApp.svelte`) — they moved here verbatim (regex updated for class-
// method syntax: `async openMeeting(...)` not `async function openMeeting`,
// `this.foo` not bare `foo`) because the functions themselves moved into
// MeetStore. The full behavioral suite (WS push reconciliation, view-FSM
// transitions, the F1/F2a/F3/F5/D-1..D10/B3 scenarios) stays in
// MeetApp.test.ts unchanged — it already exercises store.applyEvent and every
// store method end-to-end through the rendered component (all 342 of those
// tests kept passing, unmodified, across this refactor — the behavioral
// lock this refactor's "byte-identical" requirement rests on).
import { describe, it, expect } from 'vitest';

describe('MeetStore — structural pins', () => {
	// F3 (structural, moved from MeetApp.test.ts): a meeting switch mid-room
	// must never leave the PREVIOUS room's mic/cam hot — teardownLiveRoom()
	// must be openMeeting/openBySlug's FIRST statement so a future edit can't
	// silently reorder it after the getMeeting/resolveSlug await.
	it('F3: openMeeting and openBySlug both call this.teardownLiveRoom() as their first statement', async () => {
		const mod = (await import('./store.svelte.ts?raw')) as unknown as { default: string };
		const src = mod.default;
		expect(src).toMatch(/async openMeeting\([^)]*\)\s*:\s*Promise<void>\s*\{\s*this\.teardownLiveRoom\(\);/);
		expect(src).toMatch(/async openBySlug\([^)]*\)\s*:\s*Promise<void>\s*\{\s*this\.teardownLiveRoom\(\);/);
	});

	// [UX #1, structural] (moved from MeetApp.test.ts): loadMeetings must
	// showToast(errText(e)) on failure, never a dead errorMessage assignment
	// (the landing view has no view==='error' transition to render it).
	// createMeeting's OWN copy of this pin stays in MeetApp.test.ts — it
	// stayed in MeetApp.svelte (thin landing-page form glue, not part of the
	// meeting/view/push slice).
	it('[UX #1] loadMeetings showToast(errText(e)) on failure, never the dead errorMessage assignment', async () => {
		const mod = (await import('./store.svelte.ts?raw')) as unknown as { default: string };
		const src = mod.default;
		const re = /async loadMeetings\(\)\s*:\s*Promise<void>\s*\{[\s\S]*?catch \(e\) \{\s*showToast\(errText\(e\)\);/;
		expect(src, 'loadMeetings should showToast(errText(e)) on failure').toMatch(re);
	});

	// D4 (structural, moved from MeetApp.test.ts): teardownLiveRoom clears
	// every B3 state field — no leak into the next meeting.
	it('D4: teardownLiveRoom clears every B3 state field — no leak into the next meeting', async () => {
		const mod = (await import('./store.svelte.ts?raw')) as unknown as { default: string };
		const src = mod.default;
		const body = src.match(/teardownLiveRoom\(\): void \{[\s\S]*?\n\t\}/)?.[0] ?? '';
		expect(body).toMatch(/this\.sidePanel = null;/);
		expect(body).toMatch(/this\.breakoutAssignments = \{\};/);
		expect(body).toMatch(/this\.currentBreakoutId = null;/);
		expect(body).toMatch(/this\.moveInterstitial = null;/);
		// B3 Task 9: the main-stage whiteboard joins the same D4 enumeration.
		expect(body).toMatch(/this\.whiteboardOpen = false;/);
	});
});
