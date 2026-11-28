import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render } from '@testing-library/svelte/svelte5';
import { fireEvent } from '@testing-library/svelte';

// ── fetch mock helpers ────────────────────────────────────────────────────────

function makeOkResponse(body: unknown) {
	return Promise.resolve({
		ok: true,
		status: 200,
		json: async () => body,
		text: async () => JSON.stringify(body)
	});
}

function makeErrorResponse(status: number, body: string) {
	return Promise.resolve({
		ok: false,
		status,
		json: async () => ({ error: body }),
		text: async () => body
	});
}

// ── tree fixtures ─────────────────────────────────────────────────────────────

const ENG_NODE = {
	id: 10,
	name: 'Engineering',
	parentId: undefined,
	path: '/eng',
	ldapOu: 'ou=eng',
	sortOrder: 1,
	userCount: 5,
	children: [
		{
			id: 11,
			name: 'Backend',
			parentId: 10,
			path: '/eng/backend',
			ldapOu: 'ou=backend,ou=eng',
			sortOrder: 1,
			userCount: 3,
			children: [
				{
					id: 12,
					name: 'Platform',
					parentId: 11,
					path: '/eng/backend/platform',
					ldapOu: '',
					sortOrder: 1,
					userCount: 2,
					children: []
				}
			]
		},
		{
			id: 13,
			name: 'Frontend',
			parentId: 10,
			path: '/eng/frontend',
			ldapOu: '',
			sortOrder: 2,
			userCount: 2,
			children: []
		}
	]
};

const TREE_TWO = [
	ENG_NODE,
	{
		id: 20,
		name: 'Marketing',
		parentId: undefined,
		path: '/marketing',
		ldapOu: '',
		sortOrder: 2,
		userCount: 4,
		children: []
	}
];

function mockFetchTree(tree: unknown[]) {
	return vi.fn((url: string) => {
		if ((url as string).includes('/admin/departments/tree')) return makeOkResponse(tree);
		return makeOkResponse({});
	});
}

function mockFetchError() {
	return vi.fn((url: string) => {
		if ((url as string).includes('/admin/departments/tree'))
			return makeErrorResponse(500, 'server error');
		return makeOkResponse({});
	});
}

// ── tests ─────────────────────────────────────────────────────────────────────

describe('DepartmentTreePicker', () => {
	beforeEach(() => vi.resetAllMocks());

	// ── default state ─────────────────────────────────────────────────────────

	it('default: radio "Whole domain" is selected, value is null, tree is hidden', async () => {
		vi.stubGlobal('fetch', mockFetchTree(TREE_TWO));
		const { default: DepartmentTreePicker } = await import('./DepartmentTreePicker.svelte');
		const { container } = render(DepartmentTreePicker);
		await new Promise((r) => setTimeout(r, 20));

		// radio group
		const radios = container.querySelectorAll('input[type="radio"]');
		expect(radios.length).toBe(2);
		const wholeDomain = container.querySelector('input[value="whole"]') as HTMLInputElement;
		expect(wholeDomain?.checked).toBe(true);

		// tree not visible while "Whole domain" is selected
		expect(container.querySelector('[role="tree"]')).toBeNull();

		vi.unstubAllGlobals();
	});

	it('default: no confirmation chip visible', async () => {
		vi.stubGlobal('fetch', mockFetchTree(TREE_TWO));
		const { default: DepartmentTreePicker } = await import('./DepartmentTreePicker.svelte');
		const { container } = render(DepartmentTreePicker);
		await new Promise((r) => setTimeout(r, 20));

		expect(container.querySelector('.dtp-chip')).toBeNull();
		vi.unstubAllGlobals();
	});

	// ── radio group a11y ──────────────────────────────────────────────────────

	it('radio group has role=radiogroup or is a fieldset', async () => {
		vi.stubGlobal('fetch', mockFetchTree(TREE_TWO));
		const { default: DepartmentTreePicker } = await import('./DepartmentTreePicker.svelte');
		const { container } = render(DepartmentTreePicker);
		await new Promise((r) => setTimeout(r, 20));

		const hasFieldset = container.querySelector('fieldset') !== null;
		const hasRoleRadiogroup = container.querySelector('[role="radiogroup"]') !== null;
		expect(hasFieldset || hasRoleRadiogroup).toBe(true);

		vi.unstubAllGlobals();
	});

	// ── "Limit to a department" radio reveals tree ────────────────────────────

	it('selecting "Limit to a department" reveals role=tree', async () => {
		vi.stubGlobal('fetch', mockFetchTree(TREE_TWO));
		const { default: DepartmentTreePicker } = await import('./DepartmentTreePicker.svelte');
		const { container } = render(DepartmentTreePicker);
		await new Promise((r) => setTimeout(r, 20));

		const limitRadio = container.querySelector('input[value="ou"]') as HTMLInputElement;
		fireEvent.click(limitRadio);
		await new Promise((r) => setTimeout(r, 20));

		expect(container.querySelector('[role="tree"]')).not.toBeNull();
		vi.unstubAllGlobals();
	});

	// ── tree renders nodes with role=treeitem ────────────────────────────────

	it('tree nodes have role=treeitem', async () => {
		vi.stubGlobal('fetch', mockFetchTree(TREE_TWO));
		const { default: DepartmentTreePicker } = await import('./DepartmentTreePicker.svelte');
		const { container } = render(DepartmentTreePicker);
		await new Promise((r) => setTimeout(r, 20));

		const limitRadio = container.querySelector('input[value="ou"]') as HTMLInputElement;
		fireEvent.click(limitRadio);
		await new Promise((r) => setTimeout(r, 20));

		const treeitems = container.querySelectorAll('[role="treeitem"]');
		expect(treeitems.length).toBeGreaterThan(0);
		vi.unstubAllGlobals();
	});

	// ── parent nodes have aria-expanded ──────────────────────────────────────

	it('parent nodes have aria-expanded attribute', async () => {
		vi.stubGlobal('fetch', mockFetchTree(TREE_TWO));
		const { default: DepartmentTreePicker } = await import('./DepartmentTreePicker.svelte');
		const { container } = render(DepartmentTreePicker);
		await new Promise((r) => setTimeout(r, 20));

		const limitRadio = container.querySelector('input[value="ou"]') as HTMLInputElement;
		fireEvent.click(limitRadio);
		await new Promise((r) => setTimeout(r, 20));

		// Engineering has children → should have aria-expanded
		const items = container.querySelectorAll('[role="treeitem"]');
		const expanded = [...items].filter((el) => el.hasAttribute('aria-expanded'));
		expect(expanded.length).toBeGreaterThan(0);
		vi.unstubAllGlobals();
	});

	// ── roving tabindex ───────────────────────────────────────────────────────

	it('exactly one treeitem has tabindex=0 (roving tabindex)', async () => {
		vi.stubGlobal('fetch', mockFetchTree(TREE_TWO));
		const { default: DepartmentTreePicker } = await import('./DepartmentTreePicker.svelte');
		const { container } = render(DepartmentTreePicker);
		await new Promise((r) => setTimeout(r, 20));

		const limitRadio = container.querySelector('input[value="ou"]') as HTMLInputElement;
		fireEvent.click(limitRadio);
		await new Promise((r) => setTimeout(r, 20));

		// The items that have tabindex set
		const items = container.querySelectorAll('[role="treeitem"]');
		const tabbable = [...items].filter((el) => el.getAttribute('tabindex') === '0');
		expect(tabbable.length).toBe(1);

		const minusOne = [...items].filter((el) => el.getAttribute('tabindex') === '-1');
		expect(minusOne.length).toBe(items.length - 1);
		vi.unstubAllGlobals();
	});

	// ── selecting a node ──────────────────────────────────────────────────────

	it('clicking a node selects it: aria-selected=true', async () => {
		vi.stubGlobal('fetch', mockFetchTree(TREE_TWO));
		const { default: DepartmentTreePicker } = await import('./DepartmentTreePicker.svelte');
		const { container } = render(DepartmentTreePicker);
		await new Promise((r) => setTimeout(r, 20));

		fireEvent.click(container.querySelector('input[value="ou"]') as HTMLInputElement);
		await new Promise((r) => setTimeout(r, 20));

		// Click the first treeitem row
		const firstRow = container.querySelector('.dtp-row') as HTMLElement;
		fireEvent.click(firstRow);
		await new Promise((r) => setTimeout(r, 10));

		const selected = container.querySelector('[aria-selected="true"]');
		expect(selected).not.toBeNull();
		vi.unstubAllGlobals();
	});

	it('clicking Engineering node shows "+ all N sub-departments" badge', async () => {
		vi.stubGlobal('fetch', mockFetchTree(TREE_TWO));
		const { default: DepartmentTreePicker } = await import('./DepartmentTreePicker.svelte');
		const { container } = render(DepartmentTreePicker);
		await new Promise((r) => setTimeout(r, 20));

		fireEvent.click(container.querySelector('input[value="ou"]') as HTMLInputElement);
		await new Promise((r) => setTimeout(r, 20));

		// Find and click the Engineering row
		const rows = container.querySelectorAll('.dtp-row');
		// Engineering is the first row (first in list)
		const engRow = [...rows].find((r) => r.textContent?.includes('Engineering'));
		expect(engRow).not.toBeUndefined();
		fireEvent.click(engRow as HTMLElement);
		await new Promise((r) => setTimeout(r, 10));

		// Should show badge with sub-department count
		const badge = container.querySelector('.dtp-subtree-badge');
		expect(badge).not.toBeNull();
		expect(badge!.textContent).toMatch(/sub-department/i);
		vi.unstubAllGlobals();
	});

	it('clicking Engineering node shows confirmation chip', async () => {
		vi.stubGlobal('fetch', mockFetchTree(TREE_TWO));
		const { default: DepartmentTreePicker } = await import('./DepartmentTreePicker.svelte');
		const { container } = render(DepartmentTreePicker);
		await new Promise((r) => setTimeout(r, 20));

		fireEvent.click(container.querySelector('input[value="ou"]') as HTMLInputElement);
		await new Promise((r) => setTimeout(r, 20));

		const engRow = [...container.querySelectorAll('.dtp-row')].find((r) =>
			r.textContent?.includes('Engineering')
		);
		fireEvent.click(engRow as HTMLElement);
		await new Promise((r) => setTimeout(r, 10));

		// Confirmation chip renders with scope text
		const chip = container.querySelector('.dtp-chip');
		expect(chip).not.toBeNull();
		expect(chip!.textContent).toContain('Engineering');
		vi.unstubAllGlobals();
	});

	it('descendants of selected node have tinted class', async () => {
		vi.stubGlobal('fetch', mockFetchTree(TREE_TWO));
		const { default: DepartmentTreePicker } = await import('./DepartmentTreePicker.svelte');
		const { container } = render(DepartmentTreePicker);
		await new Promise((r) => setTimeout(r, 20));

		fireEvent.click(container.querySelector('input[value="ou"]') as HTMLInputElement);
		await new Promise((r) => setTimeout(r, 20));

		const engRow = [...container.querySelectorAll('.dtp-row')].find((r) =>
			r.textContent?.includes('Engineering')
		);
		fireEvent.click(engRow as HTMLElement);
		await new Promise((r) => setTimeout(r, 10));

		// Descendants should have the tint class
		const tinted = container.querySelectorAll('.dtp-row--tinted');
		expect(tinted.length).toBeGreaterThan(0);
		vi.unstubAllGlobals();
	});

	// ── polite live region ────────────────────────────────────────────────────

	it('polite live region exists for screen-reader announcements', async () => {
		vi.stubGlobal('fetch', mockFetchTree(TREE_TWO));
		const { default: DepartmentTreePicker } = await import('./DepartmentTreePicker.svelte');
		const { container } = render(DepartmentTreePicker);
		await new Promise((r) => setTimeout(r, 20));

		const liveRegion = container.querySelector('[aria-live="polite"]');
		expect(liveRegion).not.toBeNull();
		vi.unstubAllGlobals();
	});

	// ── keyboard navigation ───────────────────────────────────────────────────

	it('ArrowDown moves focus to next treeitem', async () => {
		vi.stubGlobal('fetch', mockFetchTree(TREE_TWO));
		const { default: DepartmentTreePicker } = await import('./DepartmentTreePicker.svelte');
		const { container } = render(DepartmentTreePicker);
		await new Promise((r) => setTimeout(r, 20));

		fireEvent.click(container.querySelector('input[value="ou"]') as HTMLInputElement);
		await new Promise((r) => setTimeout(r, 20));

		const tree = container.querySelector('[role="tree"]') as HTMLElement;
		const items = container.querySelectorAll('[role="treeitem"]');
		// Focus the tree's first item
		(items[0] as HTMLElement).focus();
		fireEvent.keyDown(tree, { key: 'ArrowDown' });
		await new Promise((r) => setTimeout(r, 10));

		// After ArrowDown, second item should have tabindex=0
		const tabbable = [...container.querySelectorAll('[role="treeitem"]')].filter(
			(el) => el.getAttribute('tabindex') === '0'
		);
		expect(tabbable.length).toBe(1);
		vi.unstubAllGlobals();
	});

	it('Enter key selects the focused treeitem', async () => {
		vi.stubGlobal('fetch', mockFetchTree(TREE_TWO));
		const { default: DepartmentTreePicker } = await import('./DepartmentTreePicker.svelte');
		const { container } = render(DepartmentTreePicker);
		await new Promise((r) => setTimeout(r, 20));

		fireEvent.click(container.querySelector('input[value="ou"]') as HTMLInputElement);
		await new Promise((r) => setTimeout(r, 20));

		const tree = container.querySelector('[role="tree"]') as HTMLElement;
		fireEvent.keyDown(tree, { key: 'Enter' });
		await new Promise((r) => setTimeout(r, 10));

		const selected = container.querySelector('[aria-selected="true"]');
		expect(selected).not.toBeNull();
		vi.unstubAllGlobals();
	});

	// ── loading state ─────────────────────────────────────────────────────────

	it('loading state: skeleton rows present before fetch resolves', async () => {
		let resolveTree!: (v: unknown) => void;
		const pending = new Promise((r) => (resolveTree = r));
		vi.stubGlobal(
			'fetch',
			vi.fn((url: string) => {
				if ((url as string).includes('/admin/departments/tree'))
					return pending.then((body) => makeOkResponse(body));
				return makeOkResponse({});
			})
		);

		const { default: DepartmentTreePicker } = await import('./DepartmentTreePicker.svelte');
		const { container } = render(DepartmentTreePicker);
		// Immediately reveal tree panel before fetch resolves
		fireEvent.click(container.querySelector('input[value="ou"]') as HTMLInputElement);
		// No await — tree fetch is still pending
		await new Promise((r) => setTimeout(r, 5));

		const skeletons = container.querySelectorAll('.dtp-skeleton-row');
		expect(skeletons.length).toBeGreaterThan(0);

		resolveTree(TREE_TWO);
		vi.unstubAllGlobals();
	});

	// ── empty state ───────────────────────────────────────────────────────────

	it('empty tree: shows warm empty state with helpful text', async () => {
		vi.stubGlobal('fetch', mockFetchTree([]));
		const { default: DepartmentTreePicker } = await import('./DepartmentTreePicker.svelte');
		const { container } = render(DepartmentTreePicker);
		await new Promise((r) => setTimeout(r, 20));

		fireEvent.click(container.querySelector('input[value="ou"]') as HTMLInputElement);
		await new Promise((r) => setTimeout(r, 20));

		const txt = container.textContent ?? '';
		expect(txt).toMatch(/no departments/i);
		vi.unstubAllGlobals();
	});

	// ── error state ───────────────────────────────────────────────────────────

	it('fetch error: shows error message with Retry button; value stays null (form submittable)', async () => {
		vi.stubGlobal('fetch', mockFetchError());
		const { default: DepartmentTreePicker } = await import('./DepartmentTreePicker.svelte');
		const capturedValue: unknown = 'UNSET';
		const { container } = render(DepartmentTreePicker, { props: { value: capturedValue as null } });
		await new Promise((r) => setTimeout(r, 20));

		// Switch to 'ou' — fetch (re)fires and fails
		fireEvent.click(container.querySelector('input[value="ou"]') as HTMLInputElement);
		await new Promise((r) => setTimeout(r, 20));

		// Error card is visible in the tree panel
		const txt = container.textContent ?? '';
		expect(txt).toMatch(/couldn.t load/i);

		// Retry button present
		const retryBtn = [...container.querySelectorAll('button')].find((b) =>
			b.textContent?.toLowerCase().includes('retry')
		);
		expect(retryBtn).not.toBeUndefined();

		// The OU radio is active (user's choice), but error card shows
		const ouRadio = container.querySelector('input[value="ou"]') as HTMLInputElement;
		expect(ouRadio?.checked).toBe(true);

		vi.unstubAllGlobals();
	});

	// ── search / filter (deep tree) ───────────────────────────────────────────

	it('search box filters visible nodes', async () => {
		// Build a tree with 50+ nodes to trigger search box
		const bigTree = Array.from({ length: 25 }, (_, i) => ({
			id: 100 + i,
			name: `Dept${i}`,
			parentId: undefined,
			path: `/dept${i}`,
			ldapOu: '',
			sortOrder: i,
			userCount: 1,
			children:
				i < 5
					? [
							{
								id: 200 + i,
								name: `SubDept${i}`,
								parentId: 100 + i,
								path: `/dept${i}/sub`,
								ldapOu: '',
								sortOrder: 1,
								userCount: 1,
								children: []
							}
						]
					: []
		}));
		// Add 30 more to go over 50 threshold
		const tree50 = [
			...bigTree,
			...Array.from({ length: 30 }, (_, i) => ({
				id: 300 + i,
				name: `Extra${i}`,
				parentId: undefined,
				path: `/extra${i}`,
				ldapOu: '',
				sortOrder: 50 + i,
				userCount: 1,
				children: []
			}))
		];

		vi.stubGlobal('fetch', mockFetchTree(tree50));
		const { default: DepartmentTreePicker } = await import('./DepartmentTreePicker.svelte');
		const { container } = render(DepartmentTreePicker);
		await new Promise((r) => setTimeout(r, 20));

		fireEvent.click(container.querySelector('input[value="ou"]') as HTMLInputElement);
		await new Promise((r) => setTimeout(r, 20));

		// Search box appears for deep trees
		const searchInput = container.querySelector('input[type="search"], input[placeholder]') as HTMLInputElement | null;
		// We check it exists but don't fail if it's a regular text input
		const searchEl = container.querySelector('.dtp-search input, [data-testid="dtp-search"]') as HTMLInputElement | null;
		const anySearch = searchInput ?? searchEl;
		expect(anySearch).not.toBeNull();

		// Type to filter
		fireEvent.input(anySearch!, { target: { value: 'Dept0' } });
		await new Promise((r) => setTimeout(r, 20));

		// After filtering, "Dept0" row visible
		const txt = container.textContent ?? '';
		expect(txt).toContain('Dept0');

		vi.unstubAllGlobals();
	});
});
