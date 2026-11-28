import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import DirectoryPage from './+page.svelte';
import type { DirectoryNode } from '$lib/stores/directory';

const NODES: DirectoryNode[] = [
	{ id: '1', name: 'Engineering', parentId: null, memberCount: 2 } as DirectoryNode
];

const loadSession = vi.fn().mockResolvedValue({});
const directoryTree = vi.fn().mockResolvedValue(NODES);
const setDirectoryAccountId = vi.fn();
const directoryMembers = vi.fn().mockResolvedValue({ list: [], total: 0 });

vi.mock('$lib/jmap/client', () => ({ loadSession: () => loadSession() }));
vi.mock('$lib/stores/directory', () => ({
	directoryTree: () => directoryTree(),
	setDirectoryAccountId: (id: string) => setDirectoryAccountId(id),
	directoryMembers: (...a: unknown[]) => directoryMembers(...a)
}));
// OrgChart issues its own fetch on mount; stub it.
vi.mock('./OrgChart.svelte', () => ({ default: () => null }));

describe('directory page', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		directoryTree.mockResolvedValue(NODES);
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) }));
	});
	afterEach(() => vi.unstubAllGlobals());

	it('renders M1 Tabs with sentence-case, space-free labels', async () => {
		const { container } = render(DirectoryPage);
		await screen.findByText('Engineering');
		const tablist = container.querySelector('[role="tablist"]');
		expect(tablist).not.toBeNull();
		const tabs = container.querySelectorAll('[role="tab"]');
		const labels = Array.from(tabs).map((t) => t.textContent?.trim());
		expect(labels).toContain('Directory browser');
		expect(labels).toContain('Organization chart');
		// No stray leading space and no Title Case "Browser"/"Chart".
		expect(labels).not.toContain('Directory Browser');
	});

	it('defaults to the company-directory heading and switches to org via the tab', async () => {
		const { container } = render(DirectoryPage);
		expect(await screen.findByText('Company directory')).toBeTruthy();

		const orgTab = Array.from(container.querySelectorAll('[role="tab"]')).find(
			(t) => t.textContent?.trim() === 'Organization chart'
		) as HTMLButtonElement;
		await fireEvent.click(orgTab);
		expect(orgTab.getAttribute('aria-selected')).toBe('true');
	});

	it('shows the localized error banner when the directory fails to load', async () => {
		directoryTree.mockRejectedValueOnce(new Error('boom'));
		render(DirectoryPage);
		expect(await screen.findByText('Failed to load directory. Please try again.')).toBeTruthy();
	});
});
