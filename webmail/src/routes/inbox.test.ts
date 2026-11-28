import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import { toasts, clearToasts } from '$lib/components/ui';
import InboxPage from './inbox/+page.svelte';

// Mock websocket to noop
vi.mock('$lib/jmap/websocket', () => ({
	connect: vi.fn(),
	disconnect: vi.fn(),
	subscribe: vi.fn(() => () => {}),
}));

// Mock logger
vi.mock('$lib/logger', () => ({
	logger: { log: vi.fn(), error: vi.fn() },
}));

// Mock sanitize
vi.mock('$lib/sanitize', () => ({
	sanitizeHTML: (h: string) => h,
}));

// Mock offline helpers
vi.mock('$lib/db/offline', () => ({
	isOnline: () => true,
	onNetworkChange: vi.fn(),
}));

function testEmail(overrides: Record<string, unknown> = {}) {
	return {
		id: 'e1',
		threadId: 't1',
		subject: 'Test Email',
		from: [{ email: 'sender@test.com', name: 'Sender' }],
		to: [{ email: 'user@test.com', name: 'User' }],
		receivedAt: '2026-01-01T09:00:00Z',
		mailboxIds: { mb1: true },
		keywords: {},
		preview: 'This is a test...',
		...overrides,
	};
}

const sessionResponse = {
	apiUrl: '/jmap',
	downloadUrl: '/blobs',
	uploadUrl: '/blobs',
	eventSourceUrl: '',
	state: 's1',
	accounts: { a1: { name: 'alice@test.local', isPersonal: true, accountCapabilities: {} } },
	primaryAccounts: { 'urn:ietf:params:jmap:mail': 'a1' },
	username: 'alice@test.local',
	capabilities: { 'urn:ietf:params:jmap:core': {} },
};

const defaultMailboxes = [
	{ id: 'mb1', name: 'Inbox', role: 'inbox', totalEmails: 1, unreadEmails: 0 },
	{ id: 'mb2', name: 'Trash', role: 'trash', totalEmails: 0, unreadEmails: 0 },
	{ id: 'ut1', name: 'Personal', role: undefined as unknown as string, totalEmails: 0, unreadEmails: 0 },
];

/**
 * Set up a controllable fetch mock for inbox tests.
 */
function setupInboxTest(emails: any[] = [testEmail()]) {
	let emailSetResolve: ((v: Response) => void) | null = null;
	let emailSetReject: ((e: Error) => void) | null = null;
	let emailSetPromise: Promise<Response> | null = null;
	const emailSetRequests: { body: any }[] = [];

	function createEmailSetPromise() {
		emailSetPromise = new Promise<Response>((resolve, reject) => {
			emailSetResolve = resolve;
			emailSetReject = reject;
		});
	}
	createEmailSetPromise();

	const mockFetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = typeof input === 'string' ? input : input.toString();
		const reqBody = init?.body ? JSON.parse(init.body as string) : {};
		const methodCalls: any[] = reqBody.methodCalls || [];

		// Intercept Email/set calls with a controlled promise
		const hasEmailSet = methodCalls.some((mc: string[]) => mc[0] === 'Email/set');
		if (hasEmailSet) {
			emailSetRequests.push({ body: reqBody });
			return emailSetPromise!;
		}

		// Handle /.well-known/jmap
		if (url.includes('/.well-known/jmap')) {
			return {
				ok: true,
				status: 200,
				json: async () => sessionResponse,
				text: async () => '',
			};
		}

		// Handle /jmap (non-Email/set calls)
		if (url.includes('/jmap') && !url.includes('/jmap/ws')) {
			const responses: any[] = [];
			for (const mc of methodCalls) {
				const [name, _args, callId] = mc;
				switch (name) {
					case 'Mailbox/get':
						responses.push([name, { list: defaultMailboxes, state: 's1' }, callId]);
						break;
					case 'Email/query':
						responses.push([name, {
							ids: emails.map((e: any) => e.id),
							total: emails.length,
							position: emails.length,
						}, callId]);
						break;
					case 'Email/get':
						responses.push([name, { list: emails, state: 's1' }, callId]);
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

		// /quarantine/count and other endpoints
		return { ok: true, status: 200, json: async () => ({}), text: async () => '' };
	});

	vi.stubGlobal('fetch', mockFetch);

	return {
		mockFetch,
		emailSetRequests,
		resolveEmailSet: (data?: any) => {
			emailSetResolve!({
				ok: true,
				status: 200,
				json: async () => ({
					methodResponses: [[
						'Email/set',
						{
							created: data?.created || {},
							updated: data?.updated || ['e1'],
							destroyed: data?.destroyed || [],
							notCreated: {},
							notUpdated: {},
						},
						'0',
					]],
				}),
				text: async () => '',
			} as unknown as Response);
			createEmailSetPromise();
		},
		rejectEmailSet: () => {
			emailSetResolve!({
				ok: false,
				status: 500,
				json: async () => { throw new Error('Internal Server Error'); },
				text: async () => 'Internal Server Error',
			} as unknown as Response);
			createEmailSetPromise();
		},
	};
}

describe('Inbox Page - Coordinator', () => {
	beforeEach(() => {
		resetStores();
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('mounts inbox page without crashing', async () => {
		const emails = [testEmail()];
		setupInboxTest(emails);

		const { container } = await renderAsUser(InboxPage);
		expect(container).toBeTruthy();
	});

	it('shows email subjects after loading', async () => {
		const emails = [testEmail()];
		setupInboxTest(emails);

		await renderAsUser(InboxPage);
		await waitFor(() => {
			expect(screen.getByText('Test Email')).toBeTruthy();
		});
	});

	it('renders the MailSidebar with 7 kit views', async () => {
		const emails = [testEmail()];
		setupInboxTest(emails);

		await renderAsUser(InboxPage);
		await waitFor(() => {
			expect(screen.getByText('Inbox')).toBeTruthy();
		});
		expect(screen.getByText('Snoozed')).toBeTruthy();
		expect(screen.getByText('Scheduled')).toBeTruthy();
		expect(screen.getByText('Drafts')).toBeTruthy();
		expect(screen.getByText('Sent')).toBeTruthy();
		expect(screen.getByText('All Mail')).toBeTruthy();
		expect(screen.getByText('Trash')).toBeTruthy();
	});

	it('renders search input', async () => {
		const emails = [testEmail()];
		setupInboxTest(emails);

		await renderAsUser(InboxPage);
		await waitFor(() => {
			expect(screen.getByPlaceholderText(/Search mail/)).toBeTruthy();
		});
	});

	it('quick-filter chips update the query, execute it, and toggle off cleanly', async () => {
		const harness = setupInboxTest([testEmail()]);
		await renderAsUser(InboxPage);
		await waitFor(() => expect(screen.getByPlaceholderText(/Search mail/)).toBeTruthy());

		const unread = screen.getByRole('button', { name: 'Unread' });
		const search = screen.getByPlaceholderText(/Search mail/) as HTMLInputElement;
		const callsBefore = harness.mockFetch.mock.calls.length;
		await fireEvent.click(unread);
		await waitFor(() => expect(harness.mockFetch.mock.calls.length).toBeGreaterThan(callsBefore));
		expect(search.value).toBe('is:unread');
		expect(unread).toHaveAttribute('aria-pressed', 'true');

		await fireEvent.click(unread);
		await waitFor(() => expect(search.value).toBe(''));
		expect(unread).toHaveAttribute('aria-pressed', 'false');
	});

	it('executes typed search, saves it by name, and changes sort direction', async () => {
		const harness = setupInboxTest([testEmail()]);
		await renderAsUser(InboxPage);
		const search = await screen.findByPlaceholderText(/Search mail/);
		await fireEvent.input(search, { target: { value: 'from:sender@test.com' } });
		await fireEvent.keyDown(search, { key: 'Enter' });

		const save = await screen.findByRole('button', { name: 'Save search' });
		await fireEvent.click(save);
		const name = screen.getByLabelText('Name this saved search');
		await fireEvent.input(name, { target: { value: 'Sender mail' } });
		await fireEvent.keyDown(name, { key: 'Enter' });
		await waitFor(() => expect(screen.queryByLabelText('Name this saved search')).toBeNull());

		const sort = screen.getByLabelText(/Sort by/i) as HTMLSelectElement;
		await fireEvent.change(sort, { target: { value: 'subject' } });
		const direction = screen.getByRole('button', { name: /descending/i });
		await fireEvent.click(direction);
		await waitFor(() => {
			const bodies = harness.mockFetch.mock.calls
				.map((c: unknown[]) => (c[1] as RequestInit | undefined)?.body)
				.filter(Boolean)
				.map((b: unknown) => JSON.parse(String(b)));
			expect(bodies.some((b: any) => b.methodCalls?.some((m: any[]) =>
				m[0] === 'Email/query' && m[1]?.sort?.[0]?.property === 'subject'
			))).toBe(true);
		});
	});

	it('archives from the reading pane and restores the same message through undo', async () => {
		clearToasts();
		const harness = setupInboxTest([testEmail()]);
		await renderAsUser(InboxPage);
		await fireEvent.click(await screen.findByText('Test Email'));
		const archive = document.querySelector('.sj-reading-pane__toolbar [aria-label="Archive"]') as HTMLButtonElement;
		expect(archive).toBeTruthy();
		await fireEvent.click(archive);
		await waitFor(() => expect(harness.emailSetRequests.length).toBeGreaterThan(0));
		harness.resolveEmailSet();
		await waitFor(() => expect(toasts.some((toast) => toast.message === 'Conversation archived')).toBe(true));

		const toast = toasts.find((item) => item.message === 'Conversation archived');
		expect(toast?.onAction).toBeTypeOf('function');
		harness.emailSetRequests.length = 0;
		const undo = toast!.onAction!();
		await waitFor(() => expect(harness.emailSetRequests.length).toBeGreaterThan(0));
		harness.resolveEmailSet();
		await undo;
		expect(Object.keys(harness.emailSetRequests[0].body.methodCalls.find((m: any[]) => m[0] === 'Email/set')[1].update)).toContain('e1');
	});

	it('reading pane toolbar renders with action buttons after selection', async () => {
		const emails = [testEmail()];
		setupInboxTest(emails);

		await renderAsUser(InboxPage);
		await waitFor(() => {
			expect(screen.getByText('Test Email')).toBeTruthy();
		});

		// Click the MailRow to select it
		await fireEvent.click(screen.getByText('Test Email'));

		// Reading pane toolbar should render action buttons
		await waitFor(() => {
			const toolbar = document.querySelector('.sj-reading-pane__toolbar');
			expect(toolbar).toBeTruthy();
			// Verify key action buttons exist
			const labels = Array.from(toolbar!.querySelectorAll('[aria-label]')).map((el) => el.getAttribute('aria-label'));
			expect(labels).toContain('Archive');
			expect(labels).toContain('Star');
			expect(labels).toContain('Trash');
		});
	});

	it('email selection opens reading pane', async () => {
		const emails = [testEmail()];
		setupInboxTest(emails);

		await renderAsUser(InboxPage);
		await waitFor(() => {
			expect(screen.getByText('Test Email')).toBeTruthy();
		});

		// Click the email row to select it
		await fireEvent.click(screen.getByText('Test Email'));

		// Reading pane sender block should show the sender name. Scope to the
		// sender block to avoid matching the MailRow sender text.
		await waitFor(() => {
			const senderBlock = document.querySelector('.sj-reading-body__sender');
			expect(senderBlock).toBeTruthy();
			expect(senderBlock!.textContent).toContain('Sender');
		});
	});

	it('inline reply send submits via EmailSubmission and shows a Sending/Cancel toast', async () => {
		clearToasts();
		const harness = setupInboxTest([testEmail()]);

		await renderAsUser(InboxPage);
		await waitFor(() => expect(screen.getByText('Test Email')).toBeTruthy());
		await fireEvent.click(screen.getByText('Test Email'));
		await waitFor(() => expect(document.querySelector('.sj-reading-body__reply')).toBeTruthy());

		// Type a quick reply and click Send.
		const textarea = document.querySelector('.sj-reading-body__reply textarea') as HTMLTextAreaElement;
		expect(textarea).toBeTruthy();
		await fireEvent.input(textarea, { target: { value: 'Got it, thanks!' } });
		const sendBtn = document.querySelector('.sj-reading-body__reply [aria-label="Send"]') as HTMLButtonElement;
		expect(sendBtn).toBeTruthy();
		expect(sendBtn.disabled).toBe(false);
		await fireEvent.click(sendBtn);

		// The draft Email/set is the controlled promise — resolve it so the
		// submission step can proceed.
		await waitFor(() => expect(harness.emailSetRequests.length).toBeGreaterThan(0));
		harness.resolveEmailSet({ created: { 'reply-1': { id: 'reply-1' } } });

		// kit §8: in-flight send shows "Sending in 5s…" with a Cancel action,
		// NOT the old "Reply opened in composer" compose hand-off.
		await waitFor(() => {
			expect(toasts.some((tt) => /Sending in 5s/i.test(tt.message))).toBe(true);
		});
		const sendToast = toasts.find((tt) => /Sending in 5s/i.test(tt.message));
		expect(sendToast?.actionLabel).toBe('Cancel');
		expect(toasts.some((tt) => tt.message === 'Reply opened in composer')).toBe(false);

		// An EmailSubmission/set must have been issued (not a compose-store open).
		const submissionCall = harness.mockFetch.mock.calls.find((c: unknown[]) => {
			const init = c[1] as RequestInit | undefined;
			if (!init?.body) return false;
			try {
				const b = JSON.parse(init.body as string);
				return (b.methodCalls || []).some((mc: string[]) => mc[0] === 'EmailSubmission/set');
			} catch {
				return false;
			}
		});
		expect(submissionCall).toBeTruthy();
	});

	it('Flat tab renders one row per email; Threaded tab groups them', async () => {
		// Two messages in the same thread.
		const e1 = testEmail({ id: 'e1', subject: 'Thread root', threadId: 'tA' });
		const e2 = testEmail({ id: 'e2', subject: 'Thread reply', threadId: 'tA' });
		setupInboxTest([e1, e2]);

		await renderAsUser(InboxPage);
		await waitFor(() => {
			expect(screen.getByText('Thread root')).toBeTruthy();
		});

		// Default (threaded): a multi-message thread collapses into a thread header,
		// so the reply subject is not directly visible as its own row.
		await waitFor(() => {
			expect(document.querySelector('.sj-msglist__thread-header')).toBeTruthy();
		});

		// Switch to Flat: both messages must render as individual rows, no thread header.
		const flatTab = screen.getByText('Flat');
		await fireEvent.click(flatTab);
		await waitFor(() => {
			expect(document.querySelector('.sj-msglist__thread-header')).toBeNull();
		});
		const rows = document.querySelectorAll('.sj-mailrow');
		expect(rows.length).toBe(2);

		// Switch back to Threaded: thread header returns.
		const threadedTab = screen.getByText('Threaded');
		await fireEvent.click(threadedTab);
		await waitFor(() => {
			expect(document.querySelector('.sj-msglist__thread-header')).toBeTruthy();
		});
	});

	it('snooze undo targets the snoozed email even though selection was cleared', async () => {
		clearToasts();
		const harness = setupInboxTest([testEmail()]);

		await renderAsUser(InboxPage);
		await waitFor(() => {
			expect(screen.getByText('Test Email')).toBeTruthy();
		});

		// Open the reading pane.
		await fireEvent.click(screen.getByText('Test Email'));
		await waitFor(() => {
			expect(document.querySelector('.sj-reading-pane__toolbar')).toBeTruthy();
		});

		// Open the snooze picker and pick the first preset.
		const snoozeBtn = document.querySelector('[aria-label="Snooze"]') as HTMLButtonElement;
		expect(snoozeBtn).toBeTruthy();
		await fireEvent.click(snoozeBtn);
		await waitFor(() => {
			expect(document.querySelector('.sj-snooze')).toBeTruthy();
		});
		const preset = document.querySelector('.sj-snooze__item') as HTMLButtonElement;
		expect(preset).toBeTruthy();
		await fireEvent.click(preset);
		// Resolve the snooze write (Email/set with snoozeUntil).
		await waitFor(() => expect(harness.emailSetRequests.length).toBeGreaterThan(0));
		harness.resolveEmailSet();

		// An undoable toast should be registered (selectedEmail is now null).
		await waitFor(() => {
			expect(toasts.some((t) => t.message.startsWith('Snoozed until'))).toBe(true);
		});

		// Clear prior emailSet requests so we observe only the undo write.
		harness.emailSetRequests.length = 0;

		// Trigger the undo — this must NOT throw on a null selectedEmail, and the
		// emailSet must target the snoozed email's id.
		const undoToast = toasts.find((t) => t.message.startsWith('Snoozed until'));
		expect(undoToast?.onAction).toBeTypeOf('function');
		const undoPromise = undoToast!.onAction!();
		await waitFor(() => expect(harness.emailSetRequests.length).toBeGreaterThan(0));
		harness.resolveEmailSet();
		await undoPromise;

		const undoCall = harness.emailSetRequests[0].body;
		const emailSetMethod = undoCall.methodCalls.find((mc: string[]) => mc[0] === 'Email/set');
		expect(emailSetMethod).toBeTruthy();
		// The update map must be keyed by the snoozed email's id ('e1').
		expect(Object.keys(emailSetMethod[1].update ?? {})).toContain('e1');
	});
});
