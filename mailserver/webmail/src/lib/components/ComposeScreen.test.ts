import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, fireEvent, screen, waitFor, within } from '@testing-library/svelte/svelte5';
import { stubFetchRoutes } from '$lib/test-utils';
import { tick } from 'svelte';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { JmapMethodResponse } from '$lib/types/jmap';
import { composeStore } from '$lib/stores/compose';
import { jmapSession } from '$lib/stores/session';
import { user } from '$lib/stores/auth';
import { recordSend, suggestRecipients } from '$lib/utils/contactRanking';
import { assistComplete, emailGet, mailboxGet } from '$lib/jmap/client';
import type { DelegatedAccount } from '$lib/jmap/client';
import { ComposeStore } from '$lib/stores/composeStore.svelte';
import { get } from 'svelte/store';
import ComposeScreen from './ComposeScreen.svelte';

// Capture the email create payload so the plain-text-only HTML-drop is asserted at
// the JMAP boundary (the load-bearing behavior). Mocks are file-wide but inert for
// the render-only tests (they never reach handleSend).
const emailSetMock = vi.fn(async (
	create: Record<string, unknown> | null,
	_update?: Record<string, unknown> | null,
	_destroy?: string[] | null,
	_accountId?: string | null,
) => {
	void create;
	return { created: { 'email-1': { id: 'eid-1' } }, notCreated: {} };
});
const emailSubmissionSetMock = vi.fn(
	async (create: Record<string, unknown>): Promise<JmapMethodResponse | { offline: true }> => {
		void create;
		return { created: { 'sub-1': { id: 'sid-1' } } };
	}
);
const getDelegatedAccountsMock = vi.hoisted(
	() => vi.fn<() => Promise<DelegatedAccount[]>>(async () => []),
);

vi.mock('$lib/jmap/offline-client', () => ({
	emailSet: (...args: unknown[]) => emailSetMock(...(args as Parameters<typeof emailSetMock>)),
	emailSubmissionSet: (...args: unknown[]) => emailSubmissionSetMock(...(args as [Record<string, unknown>])),
}));

vi.mock('$lib/jmap/client', async (orig) => {
	const actual = (await orig()) as Record<string, unknown>;
	return {
		...actual,
		loadSession: vi.fn(async () => ({})),
		mailboxGet: vi.fn(async () => [{ id: 'drafts-mb', role: 'drafts', name: 'Drafts' }]),
		emailGet: vi.fn(async () => []),
		galSearch: vi.fn(async () => []),
		uploadBlob: vi.fn(async () => ({ blobId: 'b1', size: 1 })),
		emailSubmissionCancel: vi.fn(async () => ({})),
		assistComplete: vi.fn(async () => ''),
		getDelegatedAccounts: getDelegatedAccountsMock,
	};
});

function lastEmailCreatePayload(): {
	bodyValues?: Record<string, unknown>;
	from?: Array<{ email: string }>;
} | undefined {
	const calls = emailSetMock.mock.calls;
	for (let i = calls.length - 1; i >= 0; i--) {
		const create = calls[i][0] as Record<string, { bodyValues?: Record<string, unknown> }> | null;
		if (create && create['email-1']) return create['email-1'];
	}
	return undefined;
}

function openCompose(opts = {}) {
	composeStore.open(opts);
}

function closeCompose() {
	// Multi-compose: reset ALL sessions so none leak across tests.
	composeStore.reset();
}

function setAssist(enabled: boolean) {
	// Drives the effectiveCaps derived store (assist gate) via the raw session payload.
	jmapSession.set({ effectiveCapabilities: { features: { assist: enabled } } } as never);
}

function setExternalLabels(enabled: boolean) {
	jmapSession.set({
		effectiveCapabilities: {
			apps: {},
			features: { assist: false, bundles: false, external_labels: enabled },
		},
	} as never);
}

function deferred<T>() {
	let resolve!: (value: T) => void;
	let reject!: (reason?: unknown) => void;
	const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; });
	return { promise, resolve, reject };
}

function draftEmail(id: string, subject: string, bodyText: string, to = 'loaded@example.test') {
	return {
		id,
		from: [{ email: 'draft-sender@example.test' }],
		to: [{ email: to }],
		cc: [], bcc: [], replyTo: [], subject, bodyText,
		priority: 0, sensitivity: 'normal', readReceiptRequested: false,
		scheduledAt: null, voteOptions: [],
	} as never;
}

describe('ComposeScreen', () => {
	beforeEach(() => {
		closeCompose();
		jmapSession.set(null);
		user.set({ email: 'alice@test.local', isAdmin: false, hasMailbox: true });
		getDelegatedAccountsMock.mockReset();
		getDelegatedAccountsMock.mockResolvedValue([]);
		// Compose-open side-effect fetches; more-specific /auth/me/* before /auth/me.
		stubFetchRoutes([
			['/auth/me/smime/certs', { certs: [] }],
			['/auth/me/mailtips', { warnings: [] }],
			['/auth/me/dlp-check', { violated: false }],
			['/auth/me', { email: 'alice@test.local', delegates: [], aliases: [] }],
			['/api/settings/signatures-list', []],
			['/api/calendar/rooms', { rooms: [] }],
			['/jmap', { methodResponses: [] }],
		]);
	});

	afterEach(() => {
		user.set(null);
	});

	it('renders nothing when composeStore is closed', () => {
		render(ComposeScreen);
		expect(screen.queryByTestId('compose-screen')).toBeNull();
	});

	it('renders compose screen overlay when composeStore is open', () => {
		openCompose();
		render(ComposeScreen);
		expect(screen.getByTestId('compose-screen')).toBeInTheDocument();
	});

	it('has position: absolute; inset: 0 on the overlay', () => {
		openCompose();
		render(ComposeScreen);
		const el = screen.getByTestId('compose-screen');
		expect(el.style.position).toBe('absolute');
		expect(['0', '0px']).toContain(el.style.inset);
	});

	it('has role="dialog" and aria-modal="true"', () => {
		openCompose();
		render(ComposeScreen);
		const el = screen.getByTestId('compose-screen');
		expect(el).toHaveAttribute('role', 'dialog');
		expect(el).toHaveAttribute('aria-modal', 'true');
	});

	it('header contains close button that calls composeStore.close()', async () => {
		openCompose();
		render(ComposeScreen);
		const closeBtn = screen.getByLabelText('Close');
		expect(closeBtn).toBeInTheDocument();
		await fireEvent.click(closeBtn);
		expect(screen.queryByTestId('compose-screen')).toBeNull();
	});

	// Multi-compose (QoL #18): minimize keeps the window MOUNTED (CSS-hidden), never
	// unmounts it — so in-flight uploads + editor content survive. The dock bar itself
	// is rendered by ComposeDock (see ComposeDock.test.ts), not by ComposeScreen.
	it('minimize button hides the screen via CSS (stays mounted)', async () => {
		openCompose();
		render(ComposeScreen);
		const minimizeBtn = screen.getByLabelText('Minimize');
		expect(minimizeBtn).toBeInTheDocument();
		await fireEvent.click(minimizeBtn);
		await tick();
		const el = screen.getByTestId('compose-screen'); // still in the DOM
		expect(el.style.display).toBe('none');
	});

	it('CSS-hides the screen when the session is minimized', async () => {
		openCompose();
		render(ComposeScreen);
		composeStore.minimize();
		await tick();
		expect(screen.getByTestId('compose-screen').style.display).toBe('none');
	});

	it('restore re-shows the maximized screen', async () => {
		const id = composeStore.open()!;
		composeStore.minimize(id);
		render(ComposeScreen);
		expect(screen.getByTestId('compose-screen').style.display).toBe('none');
		composeStore.restore(id);
		await tick();
		expect(screen.getByTestId('compose-screen').style.display).toBe('flex');
	});

	it('renders header with compose title', () => {
		openCompose({ subject: 'Test' });
		render(ComposeScreen);
		expect(screen.getByText('New message')).toBeInTheDocument();
	});

	it('renders body area with sj-compose-body class', () => {
		openCompose();
		render(ComposeScreen);
		const body = document.querySelector('.sj-compose-body');
		expect(body).not.toBeNull();
	});

	describe('message column', () => {
		it('renders To input with value from composeStore opts', () => {
			openCompose({ to: 'a@b.com', subject: 'Hi' });
			render(ComposeScreen);
			const toInput = screen.getByPlaceholderText('alice@example.com, bob@example.com') as HTMLInputElement;
			expect(toInput.value).toBe('a@b.com');
		});

		it('renders Subject input with value from composeStore opts', () => {
			openCompose({ to: 'a@b.com', subject: 'Hi' });
			render(ComposeScreen);
			const subjectInput = screen.getByLabelText('Subject') as HTMLInputElement;
			expect(subjectInput.value).toBe('Hi');
		});

		it('shows Cc reveal button when Cc is hidden', () => {
			openCompose({ to: 'a@b.com' });
			render(ComposeScreen);
			expect(screen.getByText('Cc')).toBeInTheDocument();
		});

		it('does not show Cc input field when Cc is hidden', () => {
			openCompose({ to: 'a@b.com' });
			render(ComposeScreen);
			expect(screen.queryByLabelText('Cc')).toBeNull();
		});

		it('shows Cc input field after clicking Cc reveal button', async () => {
			openCompose({ to: 'a@b.com' });
			render(ComposeScreen);
			await fireEvent.click(screen.getByText('Cc'));
			expect(screen.getByLabelText('Cc')).toBeInTheDocument();
		});

		it('shows Bcc input field after clicking Bcc reveal button', async () => {
			openCompose({ to: 'a@b.com' });
			render(ComposeScreen);
			await fireEvent.click(screen.getByText('Bcc'));
			expect(screen.getByLabelText('Bcc')).toBeInTheDocument();
		});

		it('renders From select', () => {
			openCompose();
			render(ComposeScreen);
			expect(screen.getByLabelText('From')).toBeInTheDocument();
		});

		it('defaults the From selector and submitted message to the primary address', async () => {
			emailSetMock.mockClear();
			openCompose({ to: 'bob@test.local', subject: 'Primary sender' });
			render(ComposeScreen);

			const from = screen.getByLabelText('From') as HTMLSelectElement;
			expect(from.value).toBe('own');
			expect(from.selectedOptions[0]?.textContent).toBe('alice@test.local');
			await waitFor(() => {
				expect(fetch).toHaveBeenCalledWith('/auth/me', { credentials: 'include' });
			});

			await fireEvent.click(screen.getByText('Send'));
			await waitFor(() => {
				expect(lastEmailCreatePayload()?.from).toEqual([{ email: 'alice@test.local' }]);
			});
		});

		it('offers owned aliases and submits the selected alias as From', async () => {
			emailSetMock.mockClear();
			stubFetchRoutes([
				['/auth/me/smime/certs', { certs: [] }],
				['/auth/me/mailtips', { warnings: [] }],
				['/auth/me/dlp-check', { violated: false }],
				['/auth/me', {
					email: 'alice@test.local',
					delegates: [],
					aliases: [{ email: 'alice.sales@test.local' }],
				}],
				['/api/settings/signatures-list', []],
				['/api/calendar/rooms', { rooms: [] }],
				['/jmap', { methodResponses: [] }],
			]);
			openCompose({ to: 'bob@test.local', subject: 'Alias sender' });
			render(ComposeScreen);

			const from = screen.getByLabelText('From') as HTMLSelectElement;
			await waitFor(() => {
				expect(screen.getByRole('option', { name: 'alice.sales@test.local' })).toBeInTheDocument();
			});
			await fireEvent.change(from, { target: { value: 'a:alice.sales@test.local' } });
			expect(from.value).toBe('a:alice.sales@test.local');

			await fireEvent.click(screen.getByText('Send'));
			await waitFor(() => {
				expect(lastEmailCreatePayload()?.from).toEqual([{ email: 'alice.sales@test.local' }]);
			});
		});

		it('offers a shared-mailbox alias to send-as delegates and pins submission to that account', async () => {
			emailSetMock.mockClear();
			getDelegatedAccountsMock.mockResolvedValue([{
				id: '9200',
				name: 'shared@test.local',
				isReadOnly: true,
				grants: ['send_as'],
				sendAsAliases: ['sales@test.local'],
			}]);
			openCompose({ to: 'bob@test.local', subject: 'Shared alias sender' });
			render(ComposeScreen);

			const from = screen.getByLabelText('From') as HTMLSelectElement;
			await waitFor(() => {
				expect(screen.getByRole('option', { name: 'sales@test.local' })).toBeInTheDocument();
			});
			await fireEvent.change(from, {
				target: { value: 's:9200:alias:' + encodeURIComponent('sales@test.local') },
			});

			await fireEvent.click(screen.getByText('Send'));
			await waitFor(() => {
				expect(lastEmailCreatePayload()?.from).toEqual([{ email: 'sales@test.local' }]);
				expect(emailSetMock.mock.calls.at(-1)?.[3]).toBe('9200');
			});
		});

		it('restores a shared-alias preset with the matching visible From option', async () => {
			getDelegatedAccountsMock.mockResolvedValue([{
				id: '9200',
				name: 'shared@test.local',
				isReadOnly: true,
				grants: ['full_access'],
				sendAsAliases: ['sales@test.local'],
			}]);
			openCompose({
				accountId: '9200',
				from: 'sales@test.local',
				to: 'bob@test.local',
				subject: 'Reply from shared alias',
			});
			render(ComposeScreen);

			const from = screen.getByLabelText('From') as HTMLSelectElement;
			await waitFor(() => {
				expect(from.value).toBe('s:9200:alias:' + encodeURIComponent('sales@test.local'));
				expect(from.selectedOptions[0]?.textContent).toBe('sales@test.local');
			});
		});

		it('renders send button with Send label', () => {
			openCompose({ to: 'a@b.com', subject: 'Hi' });
			render(ComposeScreen);
			expect(screen.getByText('Send')).toBeInTheDocument();
		});

		it('disables send button when To is empty', () => {
			openCompose();
			render(ComposeScreen);
			const sendBtn = screen.getByText('Send').closest('button')!;
			expect(sendBtn.disabled).toBe(true);
		});

		it('shows a localized External label for an external recipient when enabled', async () => {
			setExternalLabels(true);
			stubFetchRoutes([
				['/auth/me/smime/certs', { certs: [] }],
				['/auth/me/mailtips', { warnings: [{ type: 'external_recipient', recipient: 'outside@example.net', domain: 'example.net' }] }],
				['/auth/me/dlp-check', { violated: false }],
				['/auth/me', { email: 'alice@test.local', delegates: [], aliases: [] }],
				['/api/settings/signatures-list', []],
				['/api/calendar/rooms', { rooms: [] }],
				['/jmap', { methodResponses: [] }],
			]);
			openCompose({ to: 'outside@example.net' });
			render(ComposeScreen);

			expect(await screen.findByText('[EXTERNAL] outside@example.net', {}, { timeout: 1500 })).toBeInTheDocument();
		});

		it('filters a stale external-recipient warning when the capability is off', async () => {
			setExternalLabels(false);
			stubFetchRoutes([
				['/auth/me/smime/certs', { certs: [] }],
				['/auth/me/mailtips', { warnings: [{ type: 'external_recipient', recipient: 'outside@example.net', domain: 'example.net' }] }],
				['/auth/me/dlp-check', { violated: false }],
				['/auth/me', { email: 'alice@test.local', delegates: [], aliases: [] }],
				['/api/settings/signatures-list', []],
				['/api/calendar/rooms', { rooms: [] }],
				['/jmap', { methodResponses: [] }],
			]);
			openCompose({ to: 'outside@example.net' });
			render(ComposeScreen);

			await new Promise((resolve) => setTimeout(resolve, 650));
			expect(screen.queryByText('[EXTERNAL] outside@example.net')).toBeNull();
		});
	});

	describe('options sidebar', () => {
		it('renders options sidebar with data-testid', () => {
			openCompose();
			render(ComposeScreen);
			expect(screen.getByTestId('compose-options')).toBeInTheDocument();
		});

		it('renders Delivery section head', () => {
			openCompose();
			render(ComposeScreen);
			expect(screen.getByText('Delivery')).toBeInTheDocument();
		});

		it('renders read receipt switch', () => {
			openCompose();
			render(ComposeScreen);
			expect(screen.getByText('Read receipt')).toBeInTheDocument();
		});

		it('renders When schedule select with Send now option', () => {
			openCompose();
			render(ComposeScreen);
			expect(screen.getByText('Send now')).toBeInTheDocument();
		});

		it('renders Meeting section head', () => {
			openCompose();
			render(ComposeScreen);
			expect(screen.getByText('Meeting')).toBeInTheDocument();
		});

		it('renders meeting invite switch unchecked by default', () => {
			openCompose();
			render(ComposeScreen);
			const meetingSwitch = screen.getByText('Include meeting invite').closest('label')?.querySelector('input');
			expect(meetingSwitch).not.toBeChecked();
		});

		it('renders Tag on send section head', () => {
			openCompose();
			render(ComposeScreen);
			expect(screen.getByText('Tag on send')).toBeInTheDocument();
		});

		it('renders More disclosure button', () => {
			openCompose();
			render(ComposeScreen);
			expect(screen.getByText('More')).toBeInTheDocument();
		});

		it('reveals priority/sensitivity/S-MIME controls after clicking More', async () => {
			openCompose();
			render(ComposeScreen);
			expect(screen.queryByText('Priority')).toBeNull();
			await fireEvent.click(screen.getByText('More'));
			expect(screen.getByText('Priority')).toBeInTheDocument();
			expect(screen.getByText('Sensitivity')).toBeInTheDocument();
			expect(screen.getByText('Encrypt (S/MIME)')).toBeInTheDocument();
		});

		it('reveals meeting scheduling fields when meeting invite is enabled', async () => {
			openCompose({ to: 'guest@example.com' });
			render(ComposeScreen);
			const meeting = screen.getByText('Include meeting invite').closest('label')!.querySelector('input')!;
			await fireEvent.click(meeting);
			expect(screen.getByLabelText('Meeting date')).toBeInTheDocument();
			expect(screen.getByText('Rooms free at that time')).toBeInTheDocument();
		});

		it('adds, edits, and removes voting options', async () => {
			openCompose({ voteOptions: ['Approve'] });
			render(ComposeScreen);
			await fireEvent.click(screen.getByText('More'));
			const first = screen.getByLabelText('Voting option 1') as HTMLInputElement;
			expect(first.value).toBe('Approve');
			await fireEvent.click(screen.getByRole('button', { name: '+ Add option' }));
			const second = screen.getByLabelText('Voting option 2');
			await fireEvent.change(second, { target: { value: 'Reject' } });
			expect((second as HTMLInputElement).value).toBe('Reject');
			const removes = screen.getAllByRole('button', { name: 'Remove option' });
			await fireEvent.click(removes[0]);
			expect(screen.getByLabelText('Voting option 1')).toHaveValue('Reject');
		});
	});

	describe('Assist panel (feature.assist gate)', () => {
		it('does not render the Assist section when feature.assist is false', () => {
			setAssist(false);
			openCompose();
			render(ComposeScreen);
			expect(screen.queryByText('Assist')).toBeNull();
			expect(screen.queryByText('Draft it')).toBeNull();
		});

		it('renders four Assist action buttons when feature.assist is true', async () => {
			setAssist(true);
			openCompose();
			render(ComposeScreen);
			await tick();
			expect(screen.getByText('Assist')).toBeInTheDocument();
			expect(screen.getByText('Draft it')).toBeInTheDocument();
			expect(screen.getByText('Polish')).toBeInTheDocument();
			expect(screen.getByText('Translate to 中文')).toBeInTheDocument();
			expect(screen.getByText('Shorten')).toBeInTheDocument();
		});

		it('Assist action buttons are enabled when not busy', async () => {
			setAssist(true);
			openCompose();
			render(ComposeScreen);
			await tick();
			for (const label of ['Draft it', 'Polish', 'Translate to 中文', 'Shorten']) {
				const btn = screen.getByText(label).closest('button')!;
				expect(btn.disabled).toBe(false);
			}
		});

		it('runs Assist with the subject and restores controls after completion', async () => {
			vi.mocked(assistComplete).mockResolvedValueOnce('A concise draft');
			setAssist(true);
			openCompose({ subject: 'Quarterly update' });
			render(ComposeScreen);
			await fireEvent.click(await screen.findByText('Draft it'));
			await waitFor(() => expect(assistComplete).toHaveBeenCalledWith(
				expect.arrayContaining([expect.objectContaining({ content: expect.stringContaining('Quarterly update') })]),
				expect.any(String),
			));
			await waitFor(() => expect(screen.getByText('Draft it').closest('button')).not.toBeDisabled());
		});
	});

	it('renders failed attachment state and blocks send until it is removed or retried', async () => {
		openCompose({
			to: 'a@b.com',
			subject: 'Report',
			attachments: [{ name: 'report.pdf', size: 42, type: 'application/pdf', blobId: '', uploadId: 'up-1', status: 'failed', progress: 0 }],
		});
		render(ComposeScreen);
		emailSetMock.mockClear();
		expect(screen.getByText('report.pdf')).toBeInTheDocument();
		expect(screen.getByText('Failed')).toBeInTheDocument();
		expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument();
		await fireEvent.click(screen.getByText('Send'));
		expect(await screen.findByText(/failed to upload/i)).toBeInTheDocument();
		expect(emailSetMock).not.toHaveBeenCalled();
	});

	it('requires a second confirmation when the subject promises an attachment', async () => {
		openCompose({ to: 'a@b.com', subject: 'Attached report' });
		render(ComposeScreen);
		await fireEvent.click(screen.getByText('Send'));
		expect(await screen.findByText(/attachment/i)).toBeInTheDocument();
		expect(emailSetMock).not.toHaveBeenCalled();
	});

	describe('Delivery — custom schedule', () => {
		it('does not render a DateTimePicker by default', () => {
			openCompose();
			render(ComposeScreen);
			// DateTimePicker uses a Date label inside its panel
			expect(screen.queryByLabelText('Date')).toBeNull();
		});

		it('renders DateTimePicker inline when schedule mode is Custom', async () => {
			openCompose();
			render(ComposeScreen);
			const select = screen.getByText('Send now').closest('select') as HTMLSelectElement;
			await fireEvent.change(select, { target: { value: 'custom' } });
			expect(screen.getByLabelText('Date')).toBeInTheDocument();
			expect(screen.getByLabelText('Time')).toBeInTheDocument();
		});
	});

	describe('header affordances', () => {
		it('minimize button uses an accessible label', () => {
			openCompose();
			render(ComposeScreen);
			expect(screen.getByLabelText('Minimize')).toBeInTheDocument();
		});
	});

	describe('accessibility — escape closes the dialog', () => {
		it('Escape on the overlay closes compose', async () => {
			openCompose();
			render(ComposeScreen);
			const dialog = screen.getByTestId('compose-screen');
			await fireEvent.keyDown(dialog, { key: 'Escape' });
			expect(screen.queryByTestId('compose-screen')).toBeNull();
		});
	});

	// ── A4: recipient auto-complete cache + per-entry remove ──
	describe('recipient auto-complete cache (A4)', () => {
		beforeEach(() => {
			localStorage.clear();
		});

		it('surfaces a cached past recipient in the To autocomplete', async () => {
			recordSend('alice@x.test', 'Alice Smith');
			openCompose();
			render(ComposeScreen);
			const toInput = screen.getByPlaceholderText(
				'alice@example.com, bob@example.com'
			) as HTMLInputElement;
			await fireEvent.input(toInput, { target: { value: 'ali' } });
			expect(await screen.findByText('Alice Smith')).toBeInTheDocument();
		});

		it('removing a cached suggestion forgets it for next time', async () => {
			recordSend('dave@x.test', 'Dave');
			openCompose();
			render(ComposeScreen);
			const toInput = screen.getByPlaceholderText(
				'alice@example.com, bob@example.com'
			) as HTMLInputElement;
			await fireEvent.input(toInput, { target: { value: 'dave' } });
			const x = await screen.findByLabelText('Remove dave@x.test from suggestions');
			await fireEvent.click(x);
			expect(suggestRecipients('dave')).toHaveLength(0);
		});
	});

		describe('guarded draft hydration (R7)', () => {
		beforeEach(() => {
			vi.mocked(emailGet).mockReset();
			vi.mocked(emailGet).mockResolvedValue([]);
			vi.mocked(mailboxGet).mockReset();
			vi.mocked(mailboxGet).mockResolvedValue([
				{ id: 'drafts-mb', role: 'drafts', name: 'Drafts' },
				{ id: 'sent-mb', role: 'sent', name: 'Sent' },
			] as never);
		});

		it('does not overwrite store fields or the real editor when the user edits before emailGet resolves', async () => {
			const response = deferred<never[]>();
			vi.mocked(emailGet).mockReturnValueOnce(response.promise);
			openCompose({ draftId: 'draft-stale' });
			render(ComposeScreen);
			await waitFor(() => expect(emailGet).toHaveBeenCalledTimes(1));

			const subject = screen.getByLabelText('Subject') as HTMLInputElement;
			await fireEvent.input(subject, { target: { value: 'typed while loading' } });
			response.resolve([draftEmail('draft-stale', 'server subject', 'server body')] as never);
			await tick();
			await tick();

			expect(subject.value).toBe('typed while loading');
			expect(document.querySelector('.tiptap-editor')?.textContent).not.toContain('server body');
		});

		it('allows background mailbox/From initialization while delayed draft hydration remains current', async () => {
			const response = deferred<never[]>();
			vi.mocked(emailGet).mockReturnValueOnce(response.promise);
			openCompose({ draftId: 'draft-background-from' });
			render(ComposeScreen);
			await waitFor(() => expect(emailGet).toHaveBeenCalledTimes(1));
			await waitFor(() => expect(fetch).toHaveBeenCalledWith('/auth/me', { credentials: 'include' }));

			response.resolve([draftEmail('draft-background-from', 'background-safe', 'background body')] as never);
			await waitFor(() => expect(screen.getByLabelText('Subject')).toHaveValue('background-safe'));
			await waitFor(() => expect(document.querySelector('.tiptap-editor')?.textContent).toContain('background body'));
		});

		it('treats a manual From selection as intent and drops the older delayed draft response', async () => {
			stubFetchRoutes([
				['/auth/me/smime/certs', { certs: [] }],
				['/auth/me/mailtips', { warnings: [] }],
				['/auth/me/dlp-check', { violated: false }],
				['/auth/me', { email: 'alice@test.local', delegates: [], aliases: [{ email: 'alias@test.local' }] }],
				['/api/settings/signatures-list', []],
				['/api/calendar/rooms', { rooms: [] }],
				['/jmap', { methodResponses: [] }],
			]);
			const response = deferred<never[]>();
			vi.mocked(emailGet).mockReturnValueOnce(response.promise);
			openCompose({ draftId: 'draft-manual-from', subject: 'keep local' });
			render(ComposeScreen);
			const from = screen.getByLabelText('From') as HTMLSelectElement;
			await waitFor(() => expect(screen.getByRole('option', { name: 'alias@test.local' })).toBeInTheDocument());
			await fireEvent.change(from, { target: { value: 'a:alias@test.local' } });

			response.resolve([draftEmail('draft-manual-from', 'stale server', 'stale body')] as never);
			await tick();
			await tick();
			expect(from.value).toBe('a:alias@test.local');
			expect(screen.getByLabelText('Subject')).toHaveValue('keep local');
			expect(document.querySelector('.tiptap-editor')?.textContent).not.toContain('stale body');
		});

		it.each(['reset', 'edit'] as const)(
			'does not write stale body into the editor when %s happens after store apply but before tick',
			async (action) => {
				const original = ComposeStore.prototype.applyHydration;
				const applySpy = vi.spyOn(ComposeStore.prototype, 'applyHydration').mockImplementation(function (this: ComposeStore, ticket, apply) {
					const editorTicket = original.call(this, ticket, apply);
					if (editorTicket) {
						if (action === 'reset') this.resetOwnedState();
						else this.subject = 'typed after store apply';
					}
					return editorTicket;
				});
				vi.mocked(emailGet).mockResolvedValueOnce([draftEmail('draft-current', 'server subject', 'server body')]);
				openCompose({ draftId: 'draft-current' });
				render(ComposeScreen);

				await waitFor(() => expect(applySpy).toHaveBeenCalledTimes(1));
				await tick();
				expect(document.querySelector('.tiptap-editor')?.textContent).not.toContain('server body');
				expect((screen.getByLabelText('Subject') as HTMLInputElement).value)
					.toBe(action === 'reset' ? '' : 'typed after store apply');
				applySpy.mockRestore();
			},
		);

		it('isolates two compose instances while their draft responses resolve independently', async () => {
			const firstResponse = deferred<never[]>();
			const secondResponse = deferred<never[]>();
			vi.mocked(emailGet).mockImplementation((ids) =>
				ids[0] === 'draft-one' ? firstResponse.promise : secondResponse.promise
			);
			const firstId = composeStore.open({ draftId: 'draft-one' })!;
			const secondId = composeStore.open({ draftId: 'draft-two' })!;
			const sessions = get(composeStore).sessions;
			render(ComposeScreen, { props: { session: sessions.find((item) => item.id === firstId)! } });
			render(ComposeScreen, { props: { session: sessions.find((item) => item.id === secondId)! } });
			await waitFor(() => expect(emailGet).toHaveBeenCalledTimes(2));

			secondResponse.resolve([draftEmail('draft-two', 'second subject', 'second body')] as never);
			await waitFor(() => expect(document.querySelector<HTMLInputElement>(`#cmp-${secondId}-subject`)?.value).toBe('second subject'));
			expect(document.querySelector<HTMLInputElement>(`#cmp-${firstId}-subject`)?.value).toBe('');

			firstResponse.resolve([draftEmail('draft-one', 'first subject', 'first body')] as never);
			await waitFor(() => expect(document.querySelector<HTMLInputElement>(`#cmp-${firstId}-subject`)?.value).toBe('first subject'));
			for (const [id, text] of [[firstId, 'first body'], [secondId, 'second body']] as const) {
				const input = document.querySelector<HTMLInputElement>(`#cmp-${id}-subject`)!;
				const dialog = input.closest('[data-testid="compose-screen"]') as HTMLElement;
				expect(within(dialog).getByText(text)).toBeInTheDocument();
			}
		});

		it('applies a current response to the store and real editor exactly once', async () => {
			const applySpy = vi.spyOn(ComposeStore.prototype, 'applyHydration');
			vi.mocked(emailGet).mockResolvedValueOnce([draftEmail('draft-current', 'loaded once', 'body once')]);
			openCompose({ draftId: 'draft-current' });
			render(ComposeScreen);

			await waitFor(() => expect((screen.getByLabelText('Subject') as HTMLInputElement).value).toBe('loaded once'));
			await waitFor(() => expect(document.querySelector('.tiptap-editor')?.textContent).toContain('body once'));
			expect(applySpy).toHaveBeenCalledTimes(1);
			expect(emailGet).toHaveBeenCalledTimes(1);
			expect(document.querySelectorAll('.tiptap-editor p')).toHaveLength(1);
			applySpy.mockRestore();
		});

		it('suppresses a stale hydration failure but reports a current failure without clearing the draft', async () => {
			const stale = deferred<never[]>();
			const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
			vi.mocked(emailGet).mockReturnValueOnce(stale.promise);
			openCompose({ draftId: 'draft-stale', to: 'keep@example.test', subject: 'keep subject' });
			const staleView = render(ComposeScreen);
			await waitFor(() => expect(emailGet).toHaveBeenCalledTimes(1));
			await fireEvent.input(screen.getByLabelText('Subject'), { target: { value: 'newer edit' } });
			stale.reject(new Error('old failure'));
			await tick();
			expect(screen.queryByText('Could not load draft.')).toBeNull();
			expect(screen.getByLabelText('Subject')).toHaveValue('newer edit');

			staleView.unmount();
			closeCompose();
			vi.mocked(emailGet).mockRejectedValueOnce(new Error('current failure'));
			openCompose({ draftId: 'draft-current', to: 'keep@example.test', subject: 'keep current' });
			render(ComposeScreen);
			await waitFor(() => expect(screen.getByText('Could not load draft.')).toBeInTheDocument());
			expect(screen.getAllByLabelText('Subject').at(-1)).toHaveValue('keep current');
			expect(screen.getAllByPlaceholderText('alice@example.com, bob@example.com').at(-1)).toHaveValue('keep@example.test');
			consoleSpy.mockRestore();
		});

		it('preserves draft, focus and announcement state on validation failure', async () => {
			const resetSpy = vi.spyOn(ComposeStore.prototype, 'resetOwnedState');
			openCompose({ to: 'keep@example.test', subject: '' });
			render(ComposeScreen);
			const subject = screen.getByLabelText('Subject') as HTMLInputElement;
			await tick();
			await tick();
			subject.focus();
			const liveBefore = document.querySelectorAll('[aria-live]').length;
			(screen.getByText('Send').closest('button') as HTMLButtonElement).click();
			await tick();

			expect(resetSpy).not.toHaveBeenCalled();
			expect(subject.value).toBe('');
			expect(document.activeElement).toBe(subject);
			expect(document.querySelectorAll('[aria-live]')).toHaveLength(liveBefore);
			resetSpy.mockRestore();
		});

		it('preserves draft and focus while using the existing announcement on upload failure', async () => {
			const resetSpy = vi.spyOn(ComposeStore.prototype, 'resetOwnedState');
			openCompose({
				to: 'keep@example.test', subject: 'keep upload',
				attachments: [{ name: 'failed.pdf', size: 4, type: 'application/pdf', blobId: '', uploadId: 'failed-1', status: 'failed', progress: 0 }],
			});
			render(ComposeScreen);
			const subject = screen.getByLabelText('Subject') as HTMLInputElement;
			await tick();
			await tick();
			subject.focus();
			(screen.getByText('Send').closest('button') as HTMLButtonElement).click();
			await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(/failed to upload/i));

			expect(resetSpy).not.toHaveBeenCalled();
			expect(subject).toHaveValue('keep upload');
			expect(document.activeElement).toBe(subject);
			resetSpy.mockRestore();
		});

		it('preserves draft and focus while using the existing announcement on submission failure', async () => {
			const resetSpy = vi.spyOn(ComposeStore.prototype, 'resetOwnedState');
			emailSetMock.mockClear();
			emailSubmissionSetMock.mockRejectedValueOnce(new Error('send failed'));
			openCompose({ to: 'keep@example.test', subject: 'keep send' });
			render(ComposeScreen);
			await waitFor(() => expect(mailboxGet).toHaveBeenCalled());
			const subject = screen.getByLabelText('Subject') as HTMLInputElement;
			await tick();
			await tick();
			subject.focus();
			(screen.getByText('Send').closest('button') as HTMLButtonElement).click();
			await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('send failed'));

			expect(resetSpy).not.toHaveBeenCalled();
			expect(subject).toHaveValue('keep send');
			expect(document.activeElement).toBe(subject);
			resetSpy.mockRestore();
		});

		it.each([
			['success', false],
			['held', true],
		] as const)('resets owned state exactly once after %s acceptance', async (_name, held) => {
			const resetSpy = vi.spyOn(ComposeStore.prototype, 'resetOwnedState');
			emailSetMock.mockClear();
			emailSubmissionSetMock.mockResolvedValueOnce({
				created: { 'sub-1': { id: 'sid-r7', heldForApproval: held } },
			} as never);
			openCompose({ to: 'send@example.test', subject: `accepted ${held}` });
			render(ComposeScreen);
			await waitFor(() => expect(mailboxGet).toHaveBeenCalled());
			(screen.getByText('Send').closest('button') as HTMLButtonElement).click();
			await waitFor(() => expect(resetSpy).toHaveBeenCalledTimes(1));
			expect(resetSpy).toHaveBeenCalledTimes(1);
			resetSpy.mockRestore();
		});

		it('resets owned state exactly once on explicit discard', async () => {
			const resetSpy = vi.spyOn(ComposeStore.prototype, 'resetOwnedState');
			openCompose({ to: 'discard@example.test', subject: 'discard me' });
			render(ComposeScreen);
			await fireEvent.click(screen.getByLabelText('Discard'));
			expect(resetSpy).toHaveBeenCalledTimes(1);
			resetSpy.mockRestore();
		});
	});
});

describe('ComposeScreen — inline compose-control a11y (H2 floor)', () => {
	// jsdom does not apply scoped <style>, so assert the a11y floor at the source level
	// (same approach as theme/tokens.test.ts). These are the minimum requirements the UI
	// review fixed on the kept borderless native From-select + To/Cc/Bcc/Subject inputs.
	const source = readFileSync(
		join(__dirname, 'ComposeScreen.svelte'),
		'utf-8'
	);

	it('From-select carries a custom caret (appearance:none must not hide the dropdown affordance)', () => {
		// appearance:none removes the native arrow; a custom caret must be rendered in its place.
		expect(source).toContain('cp-select-caret');
		expect(source).toContain('aria-hidden="true"');
	});

	it('the borderless text inputs get a visible :focus-visible ring', () => {
		// .cp-input suppresses the native outline; it must replace it with the standard focus ring.
		expect(source).toMatch(/\.cp-input:focus-visible\s*\{[^}]*box-shadow:\s*var\(--focus-ring\)/);
	});

	it('the From-select gets the same :focus-visible ring as the other controls', () => {
		expect(source).toMatch(
			/\.cp-input--select:focus-visible\s*\{[^}]*box-shadow:\s*var\(--focus-ring\)/
		);
	});
});

// ── A1 compose additions: Insert Signature + S/MIME Sign (Task 4) ──
describe('ComposeScreen — Insert Signature + S/MIME Sign (Task 4)', () => {
	beforeEach(() => {
		closeCompose();
		jmapSession.set(null);
		vi.stubGlobal('fetch', vi.fn((url: string) => {
			if (url === '/api/settings/signatures-list')
				return Promise.resolve({ ok: true, status: 200, json: async () => ([
					{ id: 1, alias_email: 'me@corp.test', signature_html: '<p>Best, Me</p>',
					  signature_text: 'Best, Me', is_default: true, default_for: 'new' },
				]), text: async () => '' });
			return Promise.resolve({ ok: true, status: 200, json: async () => ({ delegates: [], email: 'me@corp.test' }), text: async () => '' });
		}));
	});
	afterEach(() => vi.unstubAllGlobals());

	it('renders an Insert Signature control', async () => {
		openCompose();
		render(ComposeScreen);
		await waitFor(() => screen.getByTestId('compose-screen'));
		expect(screen.getByTestId('insert-signature-btn')).toBeInTheDocument();
	});

	it('renders an S/MIME Sign toggle alongside Encrypt', async () => {
		openCompose();
		render(ComposeScreen);
		await waitFor(() => screen.getByTestId('compose-screen'));
		await fireEvent.click(screen.getByText('More'));
		expect(screen.getByText('Sign (S/MIME)')).toBeInTheDocument();
	});

	it('renders a Plain text only toggle in the More panel', async () => {
		openCompose();
		render(ComposeScreen);
		await waitFor(() => screen.getByTestId('compose-screen'));
		await fireEvent.click(screen.getByText('More'));
		expect(screen.getByText('Plain text only')).toBeInTheDocument();
	});

	it('opens the signature menu and lists signatures by alias', async () => {
		openCompose();
		render(ComposeScreen);
		await waitFor(() => screen.getByTestId('compose-screen'));
		// Allow loadSignatures() to resolve.
		await waitFor(() => expect((globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls
			.some(([u]) => u === '/api/settings/signatures-list')).toBe(true));
		await fireEvent.click(screen.getByTestId('insert-signature-btn'));
		await waitFor(() => expect(screen.getByText('me@corp.test')).toBeInTheDocument());
	});
});

// ── A1: new-vs-reply default signature auto-selection (default_for) ──
describe('ComposeScreen — default_for auto-selection', () => {
	// Signatures whose alias does NOT match the From address, forcing the
	// role-based fallback in pickSignatureForAlias. 'new' default vs 'reply'
	// default are distinct rows so the discriminator is actually exercised.
	function stubSignaturesFetch() {
		vi.stubGlobal('fetch', vi.fn((url: string) => {
			if (url === '/api/settings/signatures-list')
				return Promise.resolve({ ok: true, status: 200, json: async () => ([
					{ id: 10, alias_email: 'newsig@other.test', signature_html: '<p>New default</p>',
					  signature_text: 'New default', is_default: false, default_for: 'new' },
					{ id: 20, alias_email: 'replysig@other.test', signature_html: '<p>Reply default</p>',
					  signature_text: 'Reply default', is_default: false, default_for: 'reply' },
				]), text: async () => '' });
			return Promise.resolve({ ok: true, status: 200, json: async () => ({ delegates: [], email: 'me@corp.test' }), text: async () => '' });
		}));
	}

	beforeEach(() => {
		closeCompose();
		jmapSession.set(null);
		stubSignaturesFetch();
	});
	afterEach(() => vi.unstubAllGlobals());

	it('auto-selects the default_for==="new" signature on a fresh compose', async () => {
		openCompose();
		render(ComposeScreen);
		await waitFor(() => screen.getByTestId('compose-screen'));
		// Let loadSignatures() resolve + run pickSignatureForAlias.
		await waitFor(() => expect((globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls
			.some(([u]) => u === '/api/settings/signatures-list')).toBe(true));
		await fireEvent.click(screen.getByTestId('insert-signature-btn'));
		// The 'new' signature (id 10) is marked current; the 'reply' one (id 20) is not.
		await waitFor(() => expect(screen.getByTestId('sig-item-10')).toHaveAttribute('aria-current', 'true'));
		expect(screen.getByTestId('sig-item-20')).not.toHaveAttribute('aria-current');
	});

	it('auto-selects the default_for==="reply" signature on a reply compose', async () => {
		openCompose({ replyTo: 'msg-1' });
		render(ComposeScreen);
		await waitFor(() => screen.getByTestId('compose-screen'));
		await waitFor(() => expect((globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls
			.some(([u]) => u === '/api/settings/signatures-list')).toBe(true));
		await fireEvent.click(screen.getByTestId('insert-signature-btn'));
		// On a reply, the 'reply' signature (id 20) is marked current instead.
		await waitFor(() => expect(screen.getByTestId('sig-item-20')).toHaveAttribute('aria-current', 'true'));
		expect(screen.getByTestId('sig-item-10')).not.toHaveAttribute('aria-current');
	});
});

// ── C3: signSMIME on submission + no-cert error surfacing ──
describe('ComposeScreen — S/MIME sign submission (C3)', () => {
	function lastSubmissionCreatePayload(): Record<string, unknown> | undefined {
		const calls = emailSubmissionSetMock.mock.calls;
		for (let i = calls.length - 1; i >= 0; i--) {
			const create = calls[i][0] as Record<string, Record<string, unknown>> | undefined;
			if (create && create['sub-1']) return create['sub-1'];
		}
		return undefined;
	}

	beforeEach(() => {
		closeCompose();
		jmapSession.set(null);
		emailSetMock.mockClear();
		emailSubmissionSetMock.mockClear();
		vi.stubGlobal('fetch', vi.fn((url: string) => {
			if (url === '/api/settings/signatures-list')
				return Promise.resolve({ ok: true, status: 200, json: async () => [], text: async () => '' });
			if (url === '/auth/me/smime/certs')
				return Promise.resolve({ ok: true, status: 200, json: async () => ({ certs: [] }), text: async () => '' });
			return Promise.resolve({ ok: true, status: 200, json: async () => ({ delegates: [], email: 'me@corp.test' }), text: async () => '' });
		}));
	});
	afterEach(() => vi.unstubAllGlobals());

	it('does NOT include signSMIME when the Sign toggle is off', async () => {
		openCompose({ to: 'x@corp.test', subject: 'Hi' });
		render(ComposeScreen);
		await waitFor(() => screen.getByTestId('compose-screen'));
		await fireEvent.click(screen.getByText('Send'));
		await waitFor(() => {
			const sub = lastSubmissionCreatePayload();
			expect(sub).toBeDefined();
			expect(sub!['signSMIME']).toBeUndefined();
		});
	});

	it('includes signSMIME: true on the submission create object when the Sign toggle is on', async () => {
		openCompose({ to: 'x@corp.test', subject: 'Hi' });
		render(ComposeScreen);
		await waitFor(() => screen.getByTestId('compose-screen'));
		await fireEvent.click(screen.getByText('More'));
		await fireEvent.click(screen.getByText('Sign (S/MIME)'));
		await fireEvent.click(screen.getByText('Send'));
		await waitFor(() => {
			const sub = lastSubmissionCreatePayload();
			expect(sub).toBeDefined();
			expect(sub!['signSMIME']).toBe(true);
		});
	});

	// F1: marker-based error mapping (D5) — replaces brittle regex description-match

	it('shows smime_no_cert message when notCreated type is smime_no_cert', async () => {
		emailSubmissionSetMock.mockResolvedValueOnce({
			notCreated: {
				'sub-1': { type: 'smime_no_cert', description: 'S/MIME signing was requested but you have no usable signing certificate.' }
			}
		});
		openCompose({ to: 'x@corp.test', subject: 'Hi' });
		render(ComposeScreen);
		await waitFor(() => screen.getByTestId('compose-screen'));
		await fireEvent.click(screen.getByText('More'));
		await fireEvent.click(screen.getByText('Sign (S/MIME)'));
		await fireEvent.click(screen.getByText('Send'));
		await waitFor(() => {
			expect(screen.getByText('Add an S/MIME certificate in Settings → Security to sign mail.')).toBeInTheDocument();
		});
	});

	it('shows smime_encrypt_no_cert message NAMING the recipients when encrypt is on (fail-closed)', async () => {
		emailSubmissionSetMock.mockResolvedValueOnce({
			notCreated: {
				'sub-1': { type: 'smime_encrypt_no_cert', description: 'server prose ignored', addresses: ['nocert@ext.example', 'also@ext.example'] }
			}
		});
		openCompose({ to: 'nocert@ext.example', subject: 'Secret' });
		render(ComposeScreen);
		await waitFor(() => screen.getByTestId('compose-screen'));
		await fireEvent.click(screen.getByText('More'));
		await fireEvent.click(screen.getByText('Encrypt (S/MIME)'));
		await fireEvent.click(screen.getByText('Send'));
		await waitFor(() => {
			// The error names EVERY missing-cert recipient (D-F2) via the stable marker,
			// not the raw server description — proving fail-closed surfaces actionably.
			const el = screen.getByText((content) =>
				content.includes("Can't encrypt to") && content.includes('nocert@ext.example') && content.includes('also@ext.example')
			);
			expect(el).toBeInTheDocument();
			expect(screen.queryByText(/server prose ignored/)).toBeNull();
		});
	});

	it('shows smime_no_matching_cert message when notCreated type is smime_no_matching_cert', async () => {
		emailSubmissionSetMock.mockResolvedValueOnce({
			notCreated: {
				'sub-1': { type: 'smime_no_matching_cert', description: 'S/MIME signing was requested but none of your certificates matches the From address.' }
			}
		});
		openCompose({ to: 'x@corp.test', subject: 'Hi' });
		render(ComposeScreen);
		await waitFor(() => screen.getByTestId('compose-screen'));
		await fireEvent.click(screen.getByText('More'));
		await fireEvent.click(screen.getByText('Sign (S/MIME)'));
		await fireEvent.click(screen.getByText('Send'));
		await waitFor(() => {
			// The message includes the from address or a generic no-matching-cert copy
			const el = screen.getByText((content) =>
				content.includes("can't sign") || content.includes("Can't sign") || content.includes('no certificate for that address')
			);
			expect(el).toBeInTheDocument();
		});
	});

	it('shows smime_sign_failed message when notCreated type is smime_sign_failed', async () => {
		emailSubmissionSetMock.mockResolvedValueOnce({
			notCreated: {
				'sub-1': { type: 'smime_sign_failed', description: 'S/MIME signing was requested but the message could not be signed.' }
			}
		});
		openCompose({ to: 'x@corp.test', subject: 'Hi' });
		render(ComposeScreen);
		await waitFor(() => screen.getByTestId('compose-screen'));
		await fireEvent.click(screen.getByText('More'));
		await fireEvent.click(screen.getByText('Sign (S/MIME)'));
		await fireEvent.click(screen.getByText('Send'));
		await waitFor(() => {
			expect(screen.getByText("Couldn't sign this message. Try again.")).toBeInTheDocument();
		});
	});

	// F4: unknown/other notCreated → generic message, NEVER raw server description

	it('shows a generic send-failed message on unknown notCreated type (not raw description)', async () => {
		emailSubmissionSetMock.mockResolvedValueOnce({
			notCreated: {
				'sub-1': { type: 'serverFail', description: 'Quota exceeded' }
			}
		});
		openCompose({ to: 'x@corp.test', subject: 'Hi' });
		render(ComposeScreen);
		await waitFor(() => screen.getByTestId('compose-screen'));
		await fireEvent.click(screen.getByText('Send'));
		await waitFor(() => {
			// Must NOT show the raw description
			expect(screen.queryByText('Quota exceeded')).not.toBeInTheDocument();
			// Must show a generic localized message
			expect(screen.getByText("Couldn't send this message. Please try again.")).toBeInTheDocument();
		});
	});

	// F2: toggle-time no-cert hint

	it('shows no-cert hint near Sign toggle when smimeSign is on but user has no default cert', async () => {
		vi.stubGlobal('fetch', vi.fn((url: string) => {
			if (url === '/api/settings/signatures-list')
				return Promise.resolve({ ok: true, status: 200, json: async () => [], text: async () => '' });
			if (url === '/auth/me/smime/certs')
				return Promise.resolve({ ok: true, status: 200, json: async () => ({ certs: [] }), text: async () => '' });
			return Promise.resolve({ ok: true, status: 200, json: async () => ({ delegates: [], email: 'me@corp.test' }), text: async () => '' });
		}));
		openCompose({ to: 'x@corp.test', subject: 'Hi' });
		render(ComposeScreen);
		await waitFor(() => screen.getByTestId('compose-screen'));
		await fireEvent.click(screen.getByText('More'));
		await fireEvent.click(screen.getByText('Sign (S/MIME)'));
		await waitFor(() => {
			expect(screen.getByText('No signing certificate yet — add one in Settings → Security.')).toBeInTheDocument();
		});
	});

	it('does not show no-cert hint when user has a default cert', async () => {
		vi.stubGlobal('fetch', vi.fn((url: string) => {
			if (url === '/api/settings/signatures-list')
				return Promise.resolve({ ok: true, status: 200, json: async () => [], text: async () => '' });
			if (url === '/auth/me/smime/certs')
				return Promise.resolve({ ok: true, status: 200, json: async () => ({ certs: [{ id: 'c1', label: 'My cert', isDefault: true, issuedAt: '', expiresAt: '' }] }), text: async () => '' });
			return Promise.resolve({ ok: true, status: 200, json: async () => ({ delegates: [], email: 'me@corp.test' }), text: async () => '' });
		}));
		openCompose({ to: 'x@corp.test', subject: 'Hi' });
		render(ComposeScreen);
		await waitFor(() => screen.getByTestId('compose-screen'));
		await fireEvent.click(screen.getByText('More'));
		await fireEvent.click(screen.getByText('Sign (S/MIME)'));
		await waitFor(() => screen.getByText('Sign (S/MIME)'));
		expect(screen.queryByText('No signing certificate yet — add one in Settings → Security.')).not.toBeInTheDocument();
	});
});

// ── P4-5: smimeEncrypt marker mapping (D-F2) ──
describe('ComposeScreen — S/MIME encrypt notCreated marker mapping (P4-5)', () => {
	function lastSubmissionCreatePayload(): Record<string, unknown> | undefined {
		const calls = emailSubmissionSetMock.mock.calls;
		for (let i = calls.length - 1; i >= 0; i--) {
			const create = calls[i][0] as Record<string, Record<string, unknown>> | undefined;
			if (create && create['sub-1']) return create['sub-1'];
		}
		return undefined;
	}

	beforeEach(() => {
		closeCompose();
		jmapSession.set(null);
		emailSetMock.mockClear();
		emailSubmissionSetMock.mockClear();
		vi.stubGlobal('fetch', vi.fn((url: string) => {
			if (url === '/api/settings/signatures-list')
				return Promise.resolve({ ok: true, status: 200, json: async () => [], text: async () => '' });
			if (url === '/auth/me/smime/certs')
				return Promise.resolve({ ok: true, status: 200, json: async () => ({ certs: [] }), text: async () => '' });
			return Promise.resolve({ ok: true, status: 200, json: async () => ({ delegates: [], email: 'me@corp.test' }), text: async () => '' });
		}));
	});
	afterEach(() => vi.unstubAllGlobals());

	it('shows smime_encrypt_no_cert message naming the recipients when that marker is returned', async () => {
		emailSubmissionSetMock.mockResolvedValueOnce({
			notCreated: {
				'sub-1': {
					type: 'smime_encrypt_no_cert',
					description: 'no cert',
					addresses: ['alice@ext.test', 'bob@ext.test']
				}
			}
		});
		openCompose({ to: 'alice@ext.test,bob@ext.test', subject: 'Sec' });
		render(ComposeScreen);
		await waitFor(() => screen.getByTestId('compose-screen'));
		await fireEvent.click(screen.getByText('More'));
		await fireEvent.click(screen.getByText('Encrypt (S/MIME)'));
		await fireEvent.click(screen.getByText('Send'));
		await waitFor(() => {
			// Must name the addresses; must NOT show the raw server description.
			const errEl = screen.queryByText((c) => c.includes('alice@ext.test'));
			expect(errEl).toBeInTheDocument();
			expect(screen.queryByText('no cert')).not.toBeInTheDocument();
		});
	});

	it('shows smime_encrypt_no_sender_cert message directing user to Settings', async () => {
		emailSubmissionSetMock.mockResolvedValueOnce({
			notCreated: {
				'sub-1': { type: 'smime_encrypt_no_sender_cert', description: 'no sender cert' }
			}
		});
		openCompose({ to: 'x@corp.test', subject: 'Sec' });
		render(ComposeScreen);
		await waitFor(() => screen.getByTestId('compose-screen'));
		await fireEvent.click(screen.getByText('More'));
		await fireEvent.click(screen.getByText('Encrypt (S/MIME)'));
		await fireEvent.click(screen.getByText('Send'));
		await waitFor(() => {
			const msg = screen.getByText((c) =>
				c.includes('Settings') && c.includes('Security') && c.includes('Sent copy'));
			expect(msg).toBeInTheDocument();
			expect(screen.queryByText('no sender cert')).not.toBeInTheDocument();
		});
	});

	it('shows smime_encrypt_no_journal_cert message routing to admin (not blaming user)', async () => {
		emailSubmissionSetMock.mockResolvedValueOnce({
			notCreated: {
				'sub-1': { type: 'smime_encrypt_no_journal_cert', description: 'no journal cert' }
			}
		});
		openCompose({ to: 'x@corp.test', subject: 'Sec' });
		render(ComposeScreen);
		await waitFor(() => screen.getByTestId('compose-screen'));
		await fireEvent.click(screen.getByText('More'));
		await fireEvent.click(screen.getByText('Encrypt (S/MIME)'));
		await fireEvent.click(screen.getByText('Send'));
		await waitFor(() => {
			// Must mention admin, not blame the user.
			const msg = screen.getByText((c) =>
				c.toLowerCase().includes('admin') || c.toLowerCase().includes('administrator'));
			expect(msg).toBeInTheDocument();
			expect(screen.queryByText('no journal cert')).not.toBeInTheDocument();
		});
	});

	it('unknown encrypt notCreated type falls through to the generic send-failed message', async () => {
		emailSubmissionSetMock.mockResolvedValueOnce({
			notCreated: { 'sub-1': { type: 'smime_encrypt_unknown_future', description: 'raw text' } }
		});
		openCompose({ to: 'x@corp.test', subject: 'Sec' });
		render(ComposeScreen);
		await waitFor(() => screen.getByTestId('compose-screen'));
		await fireEvent.click(screen.getByText('More'));
		await fireEvent.click(screen.getByText('Encrypt (S/MIME)'));
		await fireEvent.click(screen.getByText('Send'));
		await waitFor(() => {
			expect(screen.queryByText('raw text')).not.toBeInTheDocument();
			expect(screen.getByText("Couldn't send this message. Please try again.")).toBeInTheDocument();
		});
	});

	it('does NOT include encryptSMIME when the Encrypt toggle is off', async () => {
		openCompose({ to: 'x@corp.test', subject: 'Hi' });
		render(ComposeScreen);
		await waitFor(() => screen.getByTestId('compose-screen'));
		await fireEvent.click(screen.getByText('Send'));
		await waitFor(() => {
			const sub = lastSubmissionCreatePayload();
			expect(sub).toBeDefined();
			expect(sub!['encryptSMIME']).toBeUndefined();
		});
	});

	it('includes encryptSMIME: true on the submission create object when the Encrypt toggle is on', async () => {
		openCompose({ to: 'x@corp.test', subject: 'Hi' });
		render(ComposeScreen);
		await waitFor(() => screen.getByTestId('compose-screen'));
		await fireEvent.click(screen.getByText('More'));
		await fireEvent.click(screen.getByText('Encrypt (S/MIME)'));
		await fireEvent.click(screen.getByText('Send'));
		await waitFor(() => {
			const sub = lastSubmissionCreatePayload();
			expect(sub!['encryptSMIME']).toBe(true);
		});
	});
});

// ── A1: plain-text-only drops the HTML body part (Task 7) ──
describe('ComposeScreen — plain-text-only send (Task 7)', () => {
	beforeEach(() => {
		closeCompose();
		jmapSession.set(null);
		emailSetMock.mockClear();
		emailSubmissionSetMock.mockClear();
		vi.stubGlobal('fetch', vi.fn((url: string) => {
			if (url === '/api/settings/signatures-list')
				return Promise.resolve({ ok: true, status: 200, json: async () => [], text: async () => '' });
			return Promise.resolve({ ok: true, status: 200, json: async () => ({ delegates: [], email: 'me@corp.test' }), text: async () => '' });
		}));
	});
	afterEach(() => vi.unstubAllGlobals());

	it('keeps an HTML body part by default', async () => {
		openCompose({ to: 'x@corp.test', subject: 'Hi', body: '<p>rich</p>' });
		render(ComposeScreen);
		await waitFor(() => screen.getByTestId('compose-screen'));
		await fireEvent.click(screen.getByText('Send'));
		await waitFor(() => {
			const msg = lastEmailCreatePayload();
			expect(msg).toBeDefined();
			expect(msg!.bodyValues?.html).toBeDefined();
			expect(msg!.bodyValues?.text).toBeDefined();
		});
	});

	it('drops the HTML body part when plain-text-only is on', async () => {
		openCompose({ to: 'x@corp.test', subject: 'Hi', body: '<p>rich</p>' });
		render(ComposeScreen);
		await waitFor(() => screen.getByTestId('compose-screen'));
		await fireEvent.click(screen.getByText('More'));
		await fireEvent.click(screen.getByText('Plain text only'));
		await fireEvent.click(screen.getByText('Send'));
		await waitFor(() => {
			const msg = lastEmailCreatePayload();
			expect(msg).toBeDefined();
			expect(msg!.bodyValues?.html).toBeUndefined();
			expect(msg!.bodyValues?.text).toBeDefined();
		});
	});
});

// ── DLP compose-time policy tip (dry-run of send-time DLP) ──
describe('ComposeScreen DLP compose tip', () => {
	afterEach(() => {
		vi.useRealTimers();
	});

	function stubWithDlp(dlpResponse: unknown) {
		stubFetchRoutes([
			['/auth/me/smime/certs', { certs: [] }],
			['/auth/me/mailtips', { warnings: [] }],
			['/auth/me/dlp-check', dlpResponse],
			['/auth/me', { email: 'alice@test.local', delegates: [], aliases: [] }],
			['/api/settings/signatures-list', []],
			['/api/calendar/rooms', { rooms: [] }],
			['/jmap', { methodResponses: [] }],
		]);
	}

	async function typeSubject(value: string) {
		await fireEvent.input(screen.getByLabelText('Subject'), { target: { value } });
		await vi.advanceTimersByTimeAsync(1000);
	}

	it('renders a warn tip (role=status) with the policy name; Send stays enabled', async () => {
		vi.useFakeTimers();
		stubWithDlp({ violated: true, policyId: 1, policyName: 'Card Numbers', action: 'warn', reasonKind: 'content' });
		openCompose({ to: 'a@b.com' });
		render(ComposeScreen);

		await typeSubject('card 4111111111111111');

		const tipText = await screen.findByText(/Card Numbers/);
		expect(tipText.closest('[role="status"]')).not.toBeNull();
		expect(screen.getByText('Send')).not.toBeDisabled();
	});

	it('renders a block tip (role=alert) and disables Send with a reason', async () => {
		vi.useFakeTimers();
		stubWithDlp({ violated: true, policyId: 2, policyName: 'SSN Policy', action: 'block', reasonKind: 'content' });
		openCompose({ to: 'a@b.com' });
		render(ComposeScreen);

		await typeSubject('ssn 123-45-6789');

		const tipText = await screen.findByText(/SSN Policy/);
		expect(tipText.closest('[role="alert"]')).not.toBeNull();
		expect(screen.getByText('Send')).toBeDisabled();
	});

	it('quarantine/notify_admin actions render as the warn tier (advisory, Send stays enabled)', async () => {
		vi.useFakeTimers();
		stubWithDlp({ violated: true, policyId: 6, policyName: 'Quarantine Policy', action: 'quarantine', reasonKind: 'content' });
		openCompose({ to: 'a@b.com' });
		render(ComposeScreen);

		await typeSubject('trigger quarantine');

		const tipText = await screen.findByText(/Quarantine Policy/);
		expect(tipText.closest('[role="alert"]')).toBeNull();
		expect(tipText.closest('[role="status"]')).not.toBeNull();
		expect(screen.getByText('Send')).not.toBeDisabled();
	});

	it('clears the tip when the store returns clean after a previous violation', async () => {
		vi.useFakeTimers();
		stubWithDlp({ violated: true, policyId: 3, policyName: 'Temp Policy', action: 'warn', reasonKind: 'content' });
		openCompose({ to: 'a@b.com' });
		render(ComposeScreen);

		await typeSubject('trigger');
		await screen.findByText(/Temp Policy/);

		stubWithDlp({ violated: false });
		await typeSubject('clean now');

		expect(screen.queryByText(/Temp Policy/)).toBeNull();
	});

	it('a dismissed warn tip does not resurface for the SAME policy but does for a NEW one', async () => {
		vi.useFakeTimers();
		stubWithDlp({ violated: true, policyId: 4, policyName: 'Alpha Policy', action: 'warn', reasonKind: 'content' });
		openCompose({ to: 'a@b.com' });
		render(ComposeScreen);

		await typeSubject('alpha trigger');
		await screen.findByText(/Alpha Policy/);

		await fireEvent.click(screen.getByLabelText('Dismiss data-protection notice'));
		expect(screen.queryByText(/Alpha Policy/)).toBeNull();

		// Same policy hit again (e.g. a mailtips refocus refetch) — stays dismissed.
		await typeSubject('alpha trigger again');
		expect(screen.queryByText(/Alpha Policy/)).toBeNull();

		// A NEW policy hit re-surfaces (not the same suppressed policyId).
		stubWithDlp({ violated: true, policyId: 5, policyName: 'Beta Policy', action: 'warn', reasonKind: 'content' });
		await typeSubject('beta trigger');
		expect(await screen.findByText(/Beta Policy/)).toBeInTheDocument();
	});
});

// ── occ_b60bbe1192d7e36f597f1d56: plain-text reply/draft content is TEXT,
// never markup — the editor boundary must entity-encode it (escapeHTML) so
// attacker text (`<img src="https://…">`) cannot become real HTML and bypass
// the remote-image gate sanitizeHTML enforces on the HTML branch. ──
describe('ComposeScreen — plain-text reply/draft boundary', () => {
	const attackText = 'see attachment\n<img src="https://attacker.example/px" onerror="bad()">';

	function plainTextEmail(id: string) {
		return {
			id,
			from: [{ email: 'sender@example.test' }],
			to: [{ email: 'alice@test.local' }],
			cc: [], bcc: [], replyTo: [], subject: 'plain only',
			bodyText: attackText,
			bodyHTML: '',
			priority: 0, sensitivity: 'normal', readReceiptRequested: false,
			scheduledAt: null, voteOptions: [],
		} as never;
	}

	beforeEach(() => {
		closeCompose();
		jmapSession.set(null);
		vi.mocked(emailGet).mockReset();
		vi.mocked(mailboxGet).mockReset();
		vi.mocked(mailboxGet).mockResolvedValue([
			{ id: 'drafts-mb', role: 'drafts', name: 'Drafts' },
		] as never);
	});

	it('a text-only reply quote lands as inert text, not markup', async () => {
		vi.mocked(emailGet).mockResolvedValueOnce([plainTextEmail('msg-plain')]);
		openCompose({ replyTo: 'msg-plain' });
		render(ComposeScreen);
		await waitFor(() => expect(emailGet).toHaveBeenCalledTimes(1));

		const editor = document.querySelector('.tiptap-editor')!;
		await waitFor(() => expect(editor.innerHTML).toContain('--- Original message ---'));
		// The pixel text survives AS TEXT (angle brackets entity-encoded;
		// quotes stay literal in element content), never as a live tag.
		expect(editor.innerHTML).toContain('&lt;img src="https://attacker.example/px"');
		expect(editor.innerHTML).not.toMatch(/<img\b/);
	});

	it('a draft whose text body carries markup lands as inert text too', async () => {
		vi.mocked(emailGet).mockResolvedValueOnce([plainTextEmail('draft-plain')]);
		openCompose({ draftId: 'draft-plain' });
		render(ComposeScreen);
		await waitFor(() => expect(emailGet).toHaveBeenCalledTimes(1));

		const editor = document.querySelector('.tiptap-editor')!;
		await waitFor(() => expect(editor.innerHTML).toContain('&lt;img src="https://attacker.example/px"'));
		expect(editor.innerHTML).not.toMatch(/<img\b/);
	});
});
