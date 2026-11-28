import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import DirectorySidebar from './DirectorySidebar.svelte';
import type { DirectoryNode } from '$lib/stores/directory';

const NODES: DirectoryNode[] = [
	{ id: '1', name: 'Engineering', parentId: null, memberCount: 3 } as DirectoryNode,
	{ id: '2', name: 'Backend', parentId: '1', memberCount: 2 } as DirectoryNode,
	{ id: '3', name: 'Sales', parentId: null, memberCount: 0 } as DirectoryNode
];

describe('DirectorySidebar', () => {
	afterEach(() => vi.clearAllMocks());

	it('renders a role=tree with treeitem rows', () => {
		const { container } = render(DirectorySidebar, { props: { nodes: NODES } });
		const tree = container.querySelector('[role="tree"]');
		expect(tree).not.toBeNull();
		// Roots are treeitems.
		const items = container.querySelectorAll('[role="treeitem"]');
		expect(items.length).toBeGreaterThanOrEqual(2);
		expect(screen.getByText('Engineering')).toBeTruthy();
		expect(screen.getByText('Sales')).toBeTruthy();
	});

	it('renders expand/collapse chevrons as Lucide svgs, not ▸/▾ glyphs', () => {
		const { container } = render(DirectorySidebar, { props: { nodes: NODES } });
		const chevron = container.querySelector('.chevron');
		expect(chevron).not.toBeNull();
		expect(chevron!.querySelector('svg')).not.toBeNull();
		expect(chevron!.textContent).not.toContain('▸');
		expect(chevron!.textContent).not.toContain('▾');
	});

	it('expands a node, wrapping children in a role=group, and reflects aria-expanded', async () => {
		const { container } = render(DirectorySidebar, { props: { nodes: NODES } });
		// Engineering row starts collapsed.
		const engRow = screen.getByText('Engineering').closest('[role="treeitem"]') as HTMLElement;
		expect(engRow.getAttribute('aria-expanded')).toBe('false');
		expect(container.querySelector('[role="group"]')).toBeNull();

		const chevron = engRow.querySelector('.chevron') as HTMLButtonElement;
		await fireEvent.click(chevron);

		expect(engRow.getAttribute('aria-expanded')).toBe('true');
		const group = container.querySelector('[role="group"]');
		expect(group).not.toBeNull();
		expect(screen.getByText('Backend')).toBeTruthy();
	});

	it('selecting a node fires onsetSelect and marks the row selected', async () => {
		const onsetSelect = vi.fn();
		const { container } = render(DirectorySidebar, { props: { nodes: NODES, onsetSelect } });
		const label = screen.getByText('Engineering').closest('button') as HTMLButtonElement;
		await fireEvent.click(label);
		expect(onsetSelect).toHaveBeenCalledWith('1');
		const engRow = container.querySelector('.tree-row.selected');
		expect(engRow).not.toBeNull();
		expect(engRow!.getAttribute('aria-selected')).toBe('true');
	});

	it('leaf nodes with no children/members show no chevron button', () => {
		const { container } = render(DirectorySidebar, { props: { nodes: NODES } });
		// Sales (id 3, memberCount 0, no children) -> placeholder, not a chevron button.
		const salesRow = screen.getByText('Sales').closest('[role="treeitem"]') as HTMLElement;
		expect(salesRow.querySelector('.chevron')).toBeNull();
		expect(salesRow.querySelector('.chevron-placeholder')).not.toBeNull();
	});
});
