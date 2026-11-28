import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/svelte/svelte5';
import FileList from './FileList.svelte';
import type { DriveNode } from '$lib/drive/api';

function node(overrides: Partial<DriveNode> = {}): DriveNode {
	return {
		id: 1,
		parentId: null,
		kind: 'file',
		name: 'report.xlsx',
		branchCount: 0,
		lock: null,
		capabilities: ['read_metadata', 'rename', 'delete', 'manage_acl'],
		...overrides,
	};
}

const noop = vi.fn();

describe('FileList — P4 branch badge + lock presence', () => {
	it('renders a branch badge (icon + count text) when branchCount > 0', () => {
		render(FileList, {
			nodes: [node({ branchCount: 2 })],
			loading: false,
			deletedView: false,
			onOpenFolder: noop,
			onSelectFile: noop,
			onRename: noop,
			onTrash: noop,
			onRestore: noop,
			onDestroy: noop,
		});
		expect(screen.getByLabelText('2 branches')).toBeTruthy();
	});

	it('renders no branch badge when branchCount is 0', () => {
		render(FileList, {
			nodes: [node({ branchCount: 0 })],
			loading: false,
			deletedView: false,
			onOpenFolder: noop,
			onSelectFile: noop,
			onRename: noop,
			onTrash: noop,
			onRestore: noop,
			onDestroy: noop,
		});
		expect(screen.queryByLabelText(/branches$/)).toBeNull();
	});

	it('renders a lock presence badge (icon + text, never color-only, aria-live) when locked', () => {
		const { container } = render(FileList, {
			nodes: [
				node({
					lock: {
						holderId: 7,
						holderName: 'Bob',
						mode: 'soft',
						branchId: null,
						acquiredAt: '2026-07-10T07:00:00Z',
						expiresAt: '2026-07-10T15:00:00Z',
					},
				}),
			],
			loading: false,
			deletedView: false,
			onOpenFolder: noop,
			onSelectFile: noop,
			onRename: noop,
			onTrash: noop,
			onRestore: noop,
			onDestroy: noop,
		});
		expect(screen.getByText(/Bob/)).toBeTruthy();
		const badge = container.querySelector('.fl-row__lock');
		expect(badge?.getAttribute('aria-live')).toBe('polite');
	});

	it('renders no lock badge when the node is unlocked', () => {
		render(FileList, {
			nodes: [node({ lock: null })],
			loading: false,
			deletedView: false,
			onOpenFolder: noop,
			onSelectFile: noop,
			onRename: noop,
			onTrash: noop,
			onRestore: noop,
			onDestroy: noop,
		});
		expect(screen.queryByText(/is editing/)).toBeNull();
	});

	it('shows the folder-admins entry point on a folder row for a manager only', () => {
		const onManageFolderAdmins = vi.fn();
		const { rerender } = render(FileList, {
			nodes: [node({ kind: 'folder', name: 'Docs' })],
			loading: false,
			deletedView: false,
			onOpenFolder: noop,
			onSelectFile: noop,
			onRename: noop,
			onTrash: noop,
			onRestore: noop,
			onDestroy: noop,
			onManageFolderAdmins,
		});
		const btn = screen.getByRole('button', { name: 'Folder admins' });
		btn.click();
		expect(onManageFolderAdmins).toHaveBeenCalled();

		rerender({
			nodes: [node({ kind: 'folder', name: 'Docs', capabilities: ['read_metadata'] })],
			loading: false,
			deletedView: false,
			onOpenFolder: noop,
			onSelectFile: noop,
			onRename: noop,
			onTrash: noop,
			onRestore: noop,
			onDestroy: noop,
			onManageFolderAdmins,
		});
		expect(screen.queryByRole('button', { name: 'Folder admins' })).toBeNull();
	});

	it('never shows the folder-admins entry point on a FILE row', () => {
		render(FileList, {
			nodes: [node({ kind: 'file', name: 'report.xlsx' })],
			loading: false,
			deletedView: false,
			onOpenFolder: noop,
			onSelectFile: noop,
			onRename: noop,
			onTrash: noop,
			onRestore: noop,
			onDestroy: noop,
			onManageFolderAdmins: vi.fn(),
		});
		expect(screen.queryByRole('button', { name: 'Folder admins' })).toBeNull();
	});

	it('fails closed for mutation actions when exact capabilities are absent', () => {
		render(FileList, {
			nodes: [node({ kind: 'folder', name: 'Read only', capabilities: ['read_metadata'] })],
			loading: false,
			deletedView: false,
			onOpenFolder: noop,
			onSelectFile: noop,
			onRename: noop,
			onTrash: noop,
			onRestore: noop,
			onDestroy: noop,
			onManageFolderAdmins: vi.fn(),
			onManageAccess: vi.fn(),
		});
		expect(screen.queryByRole('button', { name: 'Rename' })).toBeNull();
		expect(screen.queryByRole('button', { name: 'Move to trash' })).toBeNull();
		expect(screen.queryByRole('button', { name: 'Folder admins' })).toBeNull();
		// Readable properties remain inspectable; mutations inside the drawer
		// independently require canManage/writesEnabled from the server.
		expect(screen.getByRole('button', { name: 'Properties and permissions' })).toBeTruthy();
	});
});
