import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import DirectoryMemberList from './DirectoryMemberList.svelte';
import type { DirectoryMember } from '$lib/stores/directory';

// Mock the directory store's network call.
const directoryMembers = vi.fn();
vi.mock('$lib/stores/directory', () => ({
	directoryMembers: (...args: unknown[]) => directoryMembers(...args)
}));

function member(over: Partial<DirectoryMember> = {}): DirectoryMember {
	return {
		id: '1',
		displayName: 'Alice Smith',
		email: 'alice@example.com',
		jobTitle: 'Engineer',
		department: 'Eng',
		phone: '',
		isManager: false,
		avatar: null,
		...over
	} as DirectoryMember;
}

describe('DirectoryMemberList', () => {
	beforeEach(() => {
		directoryMembers.mockReset();
	});
	afterEach(() => {
		vi.clearAllMocks();
	});

	it('renders members returned by the store', async () => {
		directoryMembers.mockResolvedValue({ list: [member()], total: 1 });
		render(DirectoryMemberList, { props: { departmentId: 5 } });
		expect(await screen.findByText('Alice Smith')).toBeTruthy();
		expect(screen.getByText('alice@example.com')).toBeTruthy();
		// store called with the department id, offset 0, and the fixed page limit.
		expect(directoryMembers).toHaveBeenCalledWith(5, 0, 50);
	});

	it('marks managers with a Lucide Star icon (no emoji)', async () => {
		directoryMembers.mockResolvedValue({ list: [member({ isManager: true })], total: 1 });
		const { container } = render(DirectoryMemberList, { props: { departmentId: 5 } });
		await screen.findByText('Alice Smith');
		const badge = container.querySelector('.manager-badge');
		expect(badge).not.toBeNull();
		// The badge renders a Lucide svg, not the ⭐ emoji glyph.
		expect(badge!.querySelector('svg')).not.toBeNull();
		expect(badge!.textContent).not.toContain('⭐');
		expect(badge!.getAttribute('title')).toBe('Manager');
	});

	it('renders a person\'s full address set (primary + aliases + UPN) — ARCH-004', async () => {
		directoryMembers.mockResolvedValue({
			list: [
				member({
					email: 'alice@example.com',
					addresses: [
						{ email: 'alice@example.com', type: 'primary', isPrimary: true },
						{ email: 'a.smith@example.com', type: 'alias', isPrimary: false },
						{ email: 'alice@subsidiary.example', type: 'alias', isPrimary: false },
						{ email: 'asmith@corp.local', type: 'upn', isPrimary: false }
					]
				})
			],
			total: 1
		});
		const { container } = render(DirectoryMemberList, { props: { departmentId: 5 } });
		await screen.findByText('Alice Smith');

		// Every address in the set is rendered as a mailto link, including aliases + UPN.
		const mailtos = Array.from(container.querySelectorAll('a[href^="mailto:"]')).map(
			(a) => a.getAttribute('href')
		);
		expect(mailtos).toContain('mailto:alice@example.com');
		expect(mailtos).toContain('mailto:a.smith@example.com');
		expect(mailtos).toContain('mailto:alice@subsidiary.example');
		expect(mailtos).toContain('mailto:asmith@corp.local');

		// The secondary addresses live in the multi-address list with kind labels.
		const extras = container.querySelector('.member-addresses');
		expect(extras).not.toBeNull();
		expect(extras!.textContent).toContain('a.smith@example.com');
		expect(extras!.textContent).toContain('asmith@corp.local');
		// Alias rows are tagged "Alias"; the UPN row is tagged "UPN".
		const kinds = Array.from(extras!.querySelectorAll('.address-kind')).map((s) => s.textContent);
		expect(kinds).toContain('Alias');
		expect(kinds).toContain('UPN');
		// The primary address is NOT duplicated inside the secondary list.
		expect(extras!.textContent).not.toContain('alice@example.com');
	});

	it('renders only the primary when a person has a single address', async () => {
		directoryMembers.mockResolvedValue({
			list: [
				member({
					email: 'bob@example.com',
					addresses: [{ email: 'bob@example.com', type: 'primary', isPrimary: true }]
				})
			],
			total: 1
		});
		const { container } = render(DirectoryMemberList, { props: { departmentId: 5 } });
		await screen.findByText('Alice Smith');
		expect(screen.getByText('bob@example.com')).toBeTruthy();
		// No secondary-address list when there is nothing beyond the primary.
		expect(container.querySelector('.member-addresses')).toBeNull();
	});

	it('falls back to the bare email when no address set is present (legacy payload)', async () => {
		directoryMembers.mockResolvedValue({
			list: [member({ email: 'legacy@example.com', addresses: undefined })],
			total: 1
		});
		const { container } = render(DirectoryMemberList, { props: { departmentId: 5 } });
		await screen.findByText('Alice Smith');
		const link = container.querySelector('.member-contact a');
		expect(link?.getAttribute('href')).toBe('mailto:legacy@example.com');
		expect(container.querySelector('.member-addresses')).toBeNull();
	});

	it('shows the empty state when the department has no members', async () => {
		directoryMembers.mockResolvedValue({ list: [], total: 0 });
		render(DirectoryMemberList, { props: { departmentId: 5 } });
		expect(await screen.findByText('No members in this department.')).toBeTruthy();
	});

	it('does not load when departmentId is 0 (no department selected)', async () => {
		render(DirectoryMemberList, { props: { departmentId: 0 } });
		await Promise.resolve();
		expect(directoryMembers).not.toHaveBeenCalled();
	});

	it('paginates via the M1 Pagination range when total exceeds the page size', async () => {
		directoryMembers.mockResolvedValue({
			list: Array.from({ length: 50 }, (_, i) => member({ id: String(i), displayName: `User ${i}` })),
			total: 120
		});
		const { container } = render(DirectoryMemberList, { props: { departmentId: 9 } });
		await screen.findByText('User 0');
		// M1 Pagination shows an en-dash range label.
		const range = container.querySelector('.sj-pagination__range');
		expect(range).not.toBeNull();
		expect(range!.textContent).toContain('1–50 of 120');

		// Next page maps page 2 -> offset 50.
		directoryMembers.mockClear();
		directoryMembers.mockResolvedValue({
			list: [member({ id: 'x', displayName: 'Page Two' })],
			total: 120
		});
		const next = container.querySelector('[aria-label="Next page"]') as HTMLButtonElement;
		await fireEvent.click(next);
		await screen.findByText('Page Two');
		expect(directoryMembers).toHaveBeenCalledWith(9, 50, 50);
	});
});
