import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import ContactsApp from './ContactsApp.svelte';
import { directoryTree } from '$lib/stores/directory';
import { galResults, isGAL, findDuplicates, merge, selectedAddressBookId } from '$lib/stores/contacts';
import type { ContactCard } from '$lib/types/jmap';

function mockStore<T>(initial: T) {
	let val = initial;
	const subs = new Set<(v: T) => void>();
	return {
		subscribe: vi.fn((cb: (v: T) => void) => { cb(val); return () => subs.delete(cb); }),
		set: vi.fn((v: T) => { val = v; for (const cb of subs) cb(v); }),
		update: vi.fn(),
	};
}

vi.mock('$lib/stores/contacts', () => ({
	addressBooks: mockStore([]),
	contacts: mockStore([]),
	selectedAddressBookId: mockStore(null),
	galResults: mockStore([]),
	viewMode: mockStore('list'),
	searchText: mockStore(''),
	isGAL: mockStore(false),
	duplicates: mockStore([{ email: 'a@x.test', contactIds: ['1', '2'] }]),
	duplicateContacts: mockStore({
		'1': { id: '1', displayName: 'Ann A', jobTitle: 'Eng', emails: [{ type: 'work', address: 'a@x.test' }] },
		'2': { id: '2', displayName: 'Ann', emails: [{ type: 'home', address: 'a@x.test' }] }
	}),
	loadAddressBooks: vi.fn(),
	loadContacts: vi.fn(),
	searchGAL: vi.fn(),
	createContact: vi.fn(),
	updateContact: vi.fn(),
	deleteContact: vi.fn(),
	findDuplicates: vi.fn().mockResolvedValue(undefined),
	merge: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('$lib/stores/directory', () => ({
	setDirectoryAccountId: vi.fn(),
	directoryTree: vi.fn().mockResolvedValue([]),
	directoryMembers: vi.fn(),
}));

vi.mock('$lib/stores/contactGroups', () => ({
	contactGroups: mockStore([{ id: '1', name: 'Marketing', memberCount: 2, members: [] }]),
	loadGroups: vi.fn().mockResolvedValue(undefined),
	deleteGroup: vi.fn().mockResolvedValue(undefined),
	expandGroup: vi.fn().mockResolvedValue([]),
}));

vi.mock('$lib/jmap/client', () => ({
	loadSession: vi.fn(),
	uploadBlob: vi.fn(),
}));

vi.mock('$app/navigation', () => ({
	goto: vi.fn(),
}));

describe('ContactsApp', () => {
	beforeEach(() => {
		vi.clearAllMocks();
	});

	it('renders the pim-shell root element', () => {
		const { container } = render(ContactsApp);
		const root = container.querySelector('[data-pim-shell]');
		expect(root).toBeTruthy();
	});

	it('renders the pim topbar title "Contacts"', () => {
		const { container } = render(ContactsApp);
		const title = container.querySelector('.pim-topbar__title');
		expect(title).toBeTruthy();
		expect(title!.textContent).toBe('Contacts');
	});

	it('directory search filters the directory tree (dirSearch is wired)', async () => {
		vi.mocked(directoryTree).mockResolvedValueOnce([
			{ id: '1', name: 'Engineering', parentId: null, memberCount: 0 } as never,
			{ id: '2', name: 'Marketing', parentId: null, memberCount: 0 } as never,
		]);
		const { container } = render(ContactsApp);

		// Both departments visible after the directory loads.
		await waitFor(() => {
			expect(container.textContent).toContain('Engineering');
			expect(container.textContent).toContain('Marketing');
		});

		// Typing into the directory search filters the tree to matches only.
		const dirInput = container.querySelector('.dir-search-bar input') as HTMLInputElement;
		expect(dirInput).toBeTruthy();
		await fireEvent.input(dirInput, { target: { value: 'eng' } });

		await waitFor(() => {
			expect(container.textContent).toContain('Engineering');
			expect(container.textContent).not.toContain('Marketing');
		});
	});

	describe('contact groups + CSV import (A4)', () => {
		beforeEach(() => {
			// The groups sidebar + CSV button live in the non-directory ("Contacts") view.
			localStorage.setItem('directoryMode', 'false');
		});

		it('renders a Groups section in the contacts sidebar', async () => {
			const { findByText } = render(ContactsApp);
			expect(await findByText('Groups')).toBeInTheDocument();
		});

		it('lists existing groups with their names', async () => {
			const { findByText } = render(ContactsApp);
			expect(await findByText('Marketing')).toBeInTheDocument();
		});

		it('renders an Import CSV button', async () => {
			const { findByText } = render(ContactsApp);
			expect(await findByText('Import CSV')).toBeInTheDocument();
		});

		describe('export navigation', () => {
			// jsdom doesn't perform real navigation, so a bare `location.href = x`
			// assignment logs "Not implemented: navigation" and leaves href
			// unchanged. Stub `location` with a plain writable object so the
			// assignment is observable, matching the pattern in jmap/client.test.ts.
			beforeEach(() => {
				selectedAddressBookId.set('42');
				vi.stubGlobal('location', { href: '' });
			});
			afterEach(() => {
				vi.unstubAllGlobals();
				selectedAddressBookId.set(null);
			});

			it('Export CSV navigates to the export endpoint scoped to the selected address book', async () => {
				const { findByText } = render(ContactsApp);
				await fireEvent.click(await findByText('Export CSV'));
				expect(window.location.href).toBe('/api/contacts/export/csv?addressBookId=42');
			});

			it('Export vCard navigates to the vcf export endpoint scoped to the selected address book', async () => {
				const { findByText } = render(ContactsApp);
				await fireEvent.click(await findByText('Export vCard'));
				expect(window.location.href).toBe('/api/contacts/export/vcf?addressBookId=42');
			});
		});

		it('exposes a New group affordance', async () => {
			const { findByLabelText } = render(ContactsApp);
			expect(await findByLabelText('New group')).toBeInTheDocument();
		});
	});

	describe('find & merge duplicates', () => {
		beforeEach(() => {
			localStorage.setItem('directoryMode', 'false');
		});

		it('shows the duplicate clusters + Merge, and Merge keeps the fuller card', async () => {
			const { findByText, getByText } = render(ContactsApp);

			// Enter the duplicates view.
			await fireEvent.click(await findByText('Find duplicates'));
			expect(vi.mocked(findDuplicates)).toHaveBeenCalled();

			// The cluster renders both involved contacts + their shared email.
			expect(await findByText('a@x.test')).toBeInTheDocument();
			expect(await findByText('Ann A')).toBeInTheDocument();
			expect(await findByText('Ann')).toBeInTheDocument();

			// Merge: keeps '1' (fuller: has jobTitle) and drops '2'.
			await fireEvent.click(getByText('Merge'));
			await waitFor(() => expect(vi.mocked(merge)).toHaveBeenCalledWith('1', '2'));
		});
	});

	describe('GAL card renders a person\'s full address set (ARCH-004)', () => {
		const galPerson: ContactCard = {
			id: 'gal-1',
			displayName: 'Alice Smith',
			jobTitle: 'Engineer',
			email: 'alice@example.com',
			addresses: [
				{ email: 'alice@example.com', type: 'primary', isPrimary: true },
				{ email: 'a.smith@example.com', type: 'alias', isPrimary: false },
				{ email: 'asmith@corp.local', type: 'upn', isPrimary: false }
			]
		};

		beforeEach(() => {
			localStorage.setItem('directoryMode', 'false');
			isGAL.set(true);
			galResults.set([galPerson]);
		});

		it('shows the primary address plus a "+N more" indicator in the list card', async () => {
			const { container } = render(ContactsApp);
			await waitFor(() => expect(container.textContent).toContain('Alice Smith'));
			const emailLine = container.querySelector('.contact-card .email');
			expect(emailLine).not.toBeNull();
			expect(emailLine!.textContent).toContain('alice@example.com');
			// Two non-primary addresses (alias + UPN) => "+2 more".
			expect(emailLine!.querySelector('.addr-more')!.textContent).toContain('+2 more');
		});

		it('renders every address with its kind label in the detail modal', async () => {
			const { container } = render(ContactsApp);
			await waitFor(() => expect(container.textContent).toContain('Alice Smith'));
			// Open the detail modal for the GAL person.
			const card = container.querySelector('.contact-card') as HTMLElement;
			await fireEvent.click(card);

			await waitFor(() => {
				const links = Array.from(document.querySelectorAll('.addr-line a')).map((a) =>
					a.getAttribute('href')
				);
				expect(links).toContain('mailto:alice@example.com');
				expect(links).toContain('mailto:a.smith@example.com');
				expect(links).toContain('mailto:asmith@corp.local');
			});
			const kinds = Array.from(document.querySelectorAll('.addr-line .addr-kind')).map(
				(s) => s.textContent
			);
			expect(kinds).toContain('Primary');
			expect(kinds).toContain('Alias');
			expect(kinds).toContain('UPN');
		});
	});
});
