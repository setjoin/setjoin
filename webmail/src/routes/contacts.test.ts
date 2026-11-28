import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import ContactsPage from './contacts/+page.svelte';
import { reset as resetContacts } from '$lib/stores/contacts';

vi.mock('$lib/jmap/websocket', () => ({
	connect: vi.fn(),
	disconnect: vi.fn(),
}));

vi.mock('$lib/logger', () => ({
	logger: { log: vi.fn(), error: vi.fn() },
}));

vi.mock('$lib/sanitize', () => ({
	sanitizeHTML: (h: string) => h,
}));

const mockDirectoryTree = vi.fn();
const mockDirectoryMembers = vi.fn();
const mockSetDirectoryAccountId = vi.fn();
vi.mock('$lib/stores/directory', () => ({
	directoryTree: (...args: any[]) => mockDirectoryTree(...args),
	directoryMembers: (...args: any[]) => mockDirectoryMembers(...args),
	setDirectoryAccountId: (...args: any[]) => mockSetDirectoryAccountId(...args),
}));

const mockAddressBooks = [{ id: 'ab1', name: 'Personal' }];

const mockContacts = [
	{
		id: 'c1',
		addressbookId: 'ab1',
		displayName: 'John Doe',
		firstName: 'John',
		lastName: 'Doe',
		company: 'Acme Inc',
		jobTitle: 'Engineer',
		department: 'Engineering',
		emails: [{ type: 'work', address: 'john@example.com', is_primary: true }],
		phones: [{ type: 'mobile', number: '+1-555-0100' }],
		notes: 'Test contact',
		avatar: '',
	},
];

interface ContactsTestHarness {
	mockFetch: ReturnType<typeof vi.fn>;
	contactSetRequests: { body: unknown }[];
	resolveContactSet: (data?: Record<string, unknown>) => void;
}

function setupContactsTest(): ContactsTestHarness {
	let contactSetResolve: (v: Response) => void = () => {};
	let contactSetPromise: Promise<Response> = Promise.resolve(new Response());

	const contactSetRequests: { body: unknown }[] = [];

	function createContactSetPromise() {
		contactSetPromise = new Promise<Response>((resolve, _reject) => {
			contactSetResolve = resolve;
		});
	}
	createContactSetPromise();

	const mockFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = typeof input === 'string' ? input : input.toString();
		const reqBody = init?.body ? JSON.parse(init.body as string) : {};
		const methodCalls: string[][] = reqBody.methodCalls || [];

		const hasContactSet = methodCalls.some((mc: string[]) => mc[0] === 'ContactCard/set');

		if (hasContactSet) {
			contactSetRequests.push({ body: reqBody });
			return contactSetPromise;
		}

		if (url.includes('/.well-known/jmap')) {
			return {
				ok: true,
				status: 200,
				json: async () => ({
					apiUrl: '/jmap',
					downloadUrl: '/blobs',
					uploadUrl: '/blobs',
					accounts: { a1: { name: 'alice@test.local', isPersonal: true, accountCapabilities: {} } },
					primaryAccounts: { 'urn:ietf:params:jmap:contacts': 'a1' },
					username: 'alice@test.local',
					capabilities: { 'urn:ietf:params:jmap:core': {} },
				}),
				text: async () => '',
			};
		}

		if (url.includes('/jmap') && !url.includes('/jmap/ws')) {
			const responses: unknown[] = [];
			for (const mc of methodCalls) {
				const [name, _args, callId] = mc;
				switch (name) {
					case 'Session':
						responses.push([
							name,
							{
								accounts: { a1: { name: 'alice@test.local', isPrimary: true } },
								primaryAccounts: {},
								capabilities: {},
							},
							callId,
						]);
						break;
					case 'AddressBook/get':
						responses.push([name, { list: mockAddressBooks, state: 's1' }, callId]);
						break;
					case 'ContactCard/directoryTree':
						responses.push([name, { list: [], state: 's1' }, callId]);
						break;
					case 'ContactCard/query':
						responses.push([
							name,
							{
								ids: mockContacts.map((c: { id: string }) => c.id),
								total: mockContacts.length,
							},
							callId,
						]);
						break;
					case 'ContactCard/get':
						responses.push([name, { list: mockContacts, state: 's1' }, callId]);
						break;
					case 'ContactCard/galSearch':
						responses.push([name, { list: mockContacts, state: 's1' }, callId]);
						break;
					default:
						responses.push([name, {}, callId]);
				}
			}
			return {
				ok: true,
				status: 200,
				json: async () => ({ methodResponses: responses }),
				text: async () => '',
			};
		}

		if (url.includes('/admin/departments/tree')) {
			return { ok: true, status: 200, json: async () => [], text: async () => '' };
		}

		return { ok: true, status: 200, json: async () => ({}), text: async () => '' };
	});

	vi.stubGlobal('fetch', mockFetch);

	return {
		mockFetch,
		contactSetRequests,
		resolveContactSet: (data?: Record<string, unknown>) => {
			contactSetResolve({
				ok: true,
				status: 200,
				json: async () => ({
					methodResponses: [
						[
							'ContactCard/set',
							{
								created: data?.created || { k1: { id: 'c-new' } },
								updated: data?.updated || [],
								destroyed: data?.destroyed || [],
								notUpdated: {},
							},
							'0',
						],
					],
				}),
				text: async () => '',
			} as unknown as Response);
			createContactSetPromise();
		},
	};
}

describe('Contacts Page - Loading States', () => {
	beforeEach(() => {
		resetStores();
		resetContacts();
		localStorage.clear();
		localStorage.setItem('directoryMode', 'false');
		mockDirectoryTree.mockReset().mockResolvedValue([]);
		mockDirectoryMembers.mockReset().mockResolvedValue({ list: [], total: 0 });
		mockSetDirectoryAccountId.mockReset();
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('mounts contacts page without crashing', async () => {
		setupContactsTest();
		const { container } = await renderAsUser(ContactsPage);
		expect(container).toBeTruthy();
	});

	it('shows contacts after loading', async () => {
		setupContactsTest();
		await renderAsUser(ContactsPage);
		await waitFor(() => {
			expect(screen.getByText('John Doe')).toBeTruthy();
		});
	});

	it('disables Submit button and shows Saving text during saveContact', async () => {
		const fetcher = setupContactsTest();
		await renderAsUser(ContactsPage);

		await waitFor(() => {
			expect(screen.getByText('John Doe')).toBeTruthy();
		});

		const newBtn = screen.getByRole('button', { name: 'New contact' })!;
		fireEvent.click(newBtn);

		await waitFor(() => {
			expect(document.querySelector('.sj-dialog__title')?.textContent).toContain('New contact');
		});

		const displayNameInput = document.getElementById('contact-displayName') as HTMLInputElement;
		fireEvent.input(displayNameInput, { target: { value: 'Jane Smith' } });

		const createBtn = screen.getByText('Create').closest('button')!;
		fireEvent.click(createBtn);

		await waitFor(() => {
			expect(screen.getByText('Saving...')).toBeTruthy();
		});

		fetcher.resolveContactSet();

		await waitFor(() => {
			expect(screen.queryByText('Saving...')).toBeFalsy();
		});
	});

	it('prevents duplicate submission when clicking Create twice', async () => {
		const fetcher = setupContactsTest();
		await renderAsUser(ContactsPage);

		await waitFor(() => {
			expect(screen.getByText('John Doe')).toBeTruthy();
		});

		const newBtn = screen.getByRole('button', { name: 'New contact' })!;
		fireEvent.click(newBtn);

		await waitFor(() => {
			expect(document.querySelector('.sj-dialog__title')?.textContent).toContain('New contact');
		});

		const displayNameInput = document.getElementById('contact-displayName') as HTMLInputElement;
		fireEvent.input(displayNameInput, { target: { value: 'Jane Smith' } });

		const createBtn = screen.getByText('Create').closest('button')!;
		fireEvent.click(createBtn);

		await waitFor(() => {
			expect(screen.getByText('Saving...')).toBeTruthy();
		});

		fireEvent.click(createBtn);

		fetcher.resolveContactSet();

		await waitFor(() => {
			expect(fetcher.contactSetRequests.length).toBe(1);
		});
	});

	it('disables Delete button during handleDelete', async () => {
		const fetcher = setupContactsTest();
		await renderAsUser(ContactsPage);

		await waitFor(() => {
			expect(screen.getByText('John Doe')).toBeTruthy();
		});

		const contactCard = screen.getByText('John Doe').closest('.contact-card') as HTMLElement;
		fireEvent.click(contactCard);

		await waitFor(() => {
			expect(screen.getByText('Delete')).toBeTruthy();
		});

		const deleteBtn = screen.getByText('Delete').closest('button')!;
		fireEvent.click(deleteBtn);

		await waitFor(() => {
			expect(screen.getByText('Deleting...')).toBeTruthy();
		});

		fetcher.resolveContactSet({ destroyed: ['c1'] });

		await waitFor(() => {
			expect(screen.queryByText('Deleting...')).toBeFalsy();
		});
	});

	it('disables Add to Contacts button during importFromGAL', async () => {
		const { isGAL, galResults } = await import('$lib/stores/contacts');
		isGAL.set(true);
		galResults.set(mockContacts as any);

		const fetcher = setupContactsTest();
		await renderAsUser(ContactsPage);

		await waitFor(() => {
			expect(screen.getByText('John Doe')).toBeTruthy();
		});

		const contactCard = screen.getByText('John Doe').closest('.contact-card') as HTMLElement;
		fireEvent.click(contactCard);

		await waitFor(() => {
			expect(screen.getByText('Add to Contacts')).toBeTruthy();
		});

		const importBtn = screen.getByText('Add to Contacts').closest('button')!;
		fireEvent.click(importBtn);

		await waitFor(() => {
			expect(screen.getByText('Importing...')).toBeTruthy();
		});

		fetcher.resolveContactSet();

		await waitFor(() => {
			expect(screen.queryByText('Importing...')).toBeFalsy();
		});
	});
});

describe('Contacts Page - Directory Error State', () => {
	beforeEach(() => {
		resetStores();
		resetContacts();
		localStorage.clear();
		localStorage.setItem('directoryMode', 'true');
		mockDirectoryTree.mockReset();
		mockDirectoryMembers.mockReset().mockResolvedValue({ list: [], total: 0 });
		mockSetDirectoryAccountId.mockReset();
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('shows error when directory fails to load', async () => {
		mockDirectoryTree.mockRejectedValue(new Error('Failed to load directory tree'));
		setupContactsTest();
		const { container } = await renderAsUser(ContactsPage);
		await waitFor(() => {
			expect(container.textContent).toContain('Failed to load directory. Please try again.');
		});
	});
});
