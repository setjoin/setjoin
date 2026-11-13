import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import { readFileSync } from 'node:fs';

vi.mock('$lib/offline/reconcile', () => ({
	listSyncIssues: vi.fn(),
	clearSyncIssue: vi.fn(async () => {})
}));
import { listSyncIssues, clearSyncIssue } from '$lib/offline/reconcile';
import { queueAction } from '$lib/db/offline';

// Stub the offline ecosystem so SyncIssuesInspector can import without side-effects.
// state.svelte.ts uses $state/$derived in class fields (Svelte runes compiled at
// module-load time); mocking it avoids running runes outside a Svelte effect root.
vi.mock('$lib/offline/state.svelte', () => ({
	offline: { refreshIssueCount: vi.fn(async () => {}) }
}));
vi.mock('$lib/offline/store', () => ({
	isOfflineAvailable: vi.fn().mockReturnValue(true),
	getStore: vi.fn().mockReturnValue(null),
	MAIL_APP_KEY: 'mail',
}));
vi.mock('$lib/offline/sync', () => ({ requestSync: vi.fn() }));
vi.mock('$lib/offline/leader', () => ({ withSyncOwnership: vi.fn() }));
vi.mock('$lib/jmap/client', () => ({ emailQuery: vi.fn(), emailGet: vi.fn() }));
vi.mock('$lib/db/offline', () => ({ getPendingActions: vi.fn().mockResolvedValue([]), queueAction: vi.fn(async () => 1) }));
vi.mock('$lib/components/ui/toasts.svelte', () => ({ showToast: vi.fn() }));

// ponytail: import Inspector once at top level (not per-test vi.resetModules()) —
// vi.resetModules() + Svelte 5 component import mismatch causes effect_orphan in
// @testing-library/svelte v5. Per-test isolation is covered by vi.mocked().mockXxx()
// per test, which is what the brief's beforeEach was actually solving.
import Inspector from './SyncIssuesInspector.svelte';

beforeEach(() => {
	vi.mocked(listSyncIssues).mockReset();
	vi.mocked(clearSyncIssue).mockReset();
	vi.mocked(clearSyncIssue).mockResolvedValue(undefined);
	vi.mocked(queueAction).mockReset();
	vi.mocked(queueAction).mockResolvedValue(1);
});

describe('SyncIssuesInspector', () => {
	it('shows a warm empty state (the COMMON case) that explains auto-merge', async () => {
		vi.mocked(listSyncIssues).mockResolvedValue([]);
		const { findByText } = render(Inspector, { open: true });
		// "Everything's in sync" + an explanation that flag/label/folder changes merge
		// automatically — reassuring, not a bare "No issues".
		expect(await findByText(/in sync|synced/i)).toBeTruthy();
		expect(await findByText(/merge automatically|automatically/i)).toBeTruthy();
	});

	it('renders a stale and a rejected issue with distinct kind labels', async () => {
		vi.mocked(listSyncIssues).mockResolvedValue([
			{ id: 1, kind: 'stale', actionType: 'emailSetUpdate', payload: { id: 'srv-1', subject: 'Budget' }, error: 'stateMismatch', at: 1 },
			{ id: 2, kind: 'rejected', actionType: 'emailSubmissionSet', payload: { subject: 'Reply' }, error: 'rejected', at: 2 }
		] as never);
		const { findByText } = render(Inspector, { open: true });
		expect(await findByText(/out of date/i)).toBeTruthy();
		expect(await findByText(/rejected by server/i)).toBeTruthy();
	});

	it('discard goes through a confirm dialog before clearing', async () => {
		vi.mocked(listSyncIssues).mockResolvedValue([
			{ id: 7, kind: 'rejected', actionType: 'emailSetDestroy', payload: { id: 'x', subject: 'Old' }, error: 'rejected', at: 1 }
		] as never);
		const { findByTestId, getByTestId } = render(Inspector, { open: true });
		await fireEvent.click(await findByTestId('issue-discard-7'));
		// confirm dialog appears; clearSyncIssue NOT called yet
		expect(clearSyncIssue).not.toHaveBeenCalled();
		await fireEvent.click(getByTestId('issue-discard-confirm'));
		expect(clearSyncIssue).toHaveBeenCalledWith(7);
	});

	it('retry re-enqueues the action then clears the issue (not a silent drop)', async () => {
		const payload = { id: 'srv-1', subject: 'Budget' };
		vi.mocked(listSyncIssues).mockResolvedValue([
			{ id: 9, kind: 'stale', actionType: 'emailSetUpdate', payload, error: 'stateMismatch', at: 1 }
		] as never);
		const { findByRole } = render(Inspector, { open: true });
		// wait for list to render
		await findByRole('list');
		const retryBtn = document.querySelector('[data-testid="issue-retry-9"]') as HTMLButtonElement | null;
		// The retry button may not have a testid — find by text instead
		const buttons = document.querySelectorAll('button');
		const retryButton = Array.from(buttons).find(b => /retry/i.test(b.textContent ?? ''));
		if (retryButton) await fireEvent.click(retryButton);
		// queueAction must be called with the original actionType + payload
		expect(queueAction).toHaveBeenCalledWith('emailSetUpdate', payload);
		// clearSyncIssue also called (removes the issue marker)
		expect(clearSyncIssue).toHaveBeenCalledWith(9);
	});

	it('shows an error state with a retry when listing fails', async () => {
		vi.mocked(listSyncIssues).mockRejectedValue(new Error('db locked'));
		const { findByRole } = render(Inspector, { open: true });
		expect(await findByRole('alert')).toBeTruthy();
	});

	it('truncates a 120-char subject with a full-value title (no row overflow)', async () => {
		const long = 'X'.repeat(120);
		vi.mocked(listSyncIssues).mockResolvedValue([
			{ id: 3, kind: 'stale', actionType: 'emailSetUpdate', payload: { id: 'a', subject: long }, error: 'stateMismatch', at: 1 }
		] as never);
		const { findByTestId } = render(Inspector, { open: true });
		const subj = await findByTestId('issue-subject-3');
		expect(subj.getAttribute('title')).toBe(long); // full value preserved for hover/AT
	});

	it('renders "(no subject)" when the affected message has no subject', async () => {
		vi.mocked(listSyncIssues).mockResolvedValue([
			{ id: 4, kind: 'rejected', actionType: 'emailSetDestroy', payload: { id: 'a' }, error: 'rejected', at: 1 }
		] as never);
		const { findByText } = render(Inspector, { open: true });
		expect(await findByText(/no subject/i)).toBeTruthy();
	});

	it('caps a huge list at 50 rows + "Showing 50 of N"', async () => {
		const many = Array.from({ length: 200 }, (_, i) => ({ id: i + 1, kind: 'stale', actionType: 'emailSetUpdate', payload: { id: String(i), subject: 'S' }, error: 'e', at: i }));
		vi.mocked(listSyncIssues).mockResolvedValue(many as never);
		const { findByText, getAllByRole } = render(Inspector, { open: true });
		expect(await findByText(/showing 50 of 200/i)).toBeTruthy();
		expect(getAllByRole('listitem').length).toBeLessThanOrEqual(50);
	});

	it('falls back to the raw actionType for an unknown action (forward-compat, no crash)', async () => {
		vi.mocked(listSyncIssues).mockResolvedValue([
			{ id: 5, kind: 'stale', actionType: 'futureAction', payload: { id: 'a', subject: 'S' }, error: 'e', at: 1 }
		] as never);
		const { findByText } = render(Inspector, { open: true });
		expect(await findByText(/futureAction/)).toBeTruthy();
	});
});

const src = readFileSync('src/lib/components/SyncIssuesInspector.svelte', 'utf8');
describe('SyncIssuesInspector style invariants', () => {
	it('uses border-inline-start (RTL-safe) for the kind accent bar, not border-left', () => {
		const style = src.slice(src.indexOf('<style>'));
		expect(style).toMatch(/border-inline-start/);
		expect(style).not.toMatch(/border-left\s*:/);
	});
	it('declares a reduced-motion fallback and is token-only (no raw hex)', () => {
		const style = src.slice(src.indexOf('<style>'));
		expect(src).toMatch(/@media\s*\(prefers-reduced-motion:\s*reduce\)/);
		expect(style).not.toMatch(/#[0-9a-fA-F]{3,6}\b/);
	});
});
