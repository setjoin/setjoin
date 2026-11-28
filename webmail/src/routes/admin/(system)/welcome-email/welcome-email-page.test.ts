import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor, within } from '@testing-library/svelte/svelte5';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { jmapSession } from '$lib/stores/session';

const api = vi.hoisted(() => ({ get: vi.fn(), put: vi.fn(), send: vi.fn() }));
vi.mock('$lib/admin/client', () => ({
	adminGetWelcomeEmail: api.get,
	adminPutWelcomeEmail: api.put,
	adminTestSendWelcomeEmail: api.send,
}));
vi.mock('$app/navigation', () => ({ beforeNavigate: vi.fn() }));

import Page from './+page.svelte';

const config = {
	enabled: true,
	default_locale: 'en',
	locales: {
		en: { subject: 'Welcome {{DisplayName}}', body_text: 'Open {{WebmailURL}}', body_html: '<p>Welcome</p>' },
		zh: { subject: '', body_text: '', body_html: '' },
		de: { subject: 'Willkommen', body_text: 'Hallo', body_html: '' },
	}
};

function grant() {
	jmapSession.set({ accounts: {}, primaryAccounts: {}, branding: { name: 'Setjoin Test' }, capabilities: {
		'urn:setjoin:params:jmap:mail': { admin: { consoles: ['system'], permissions: ['system.config'] } }
	} } as never);
}

async function renderPage() {
	await renderAsUser(Page, {}, { userId: 1, email: 'admin@example.test', isAdmin: true });
	grant();
	await waitFor(() => expect(screen.queryByText('Loading…')).not.toBeInTheDocument());
}

describe('admin welcome email page', () => {
	beforeEach(() => {
		resetStores();
		vi.clearAllMocks();
		api.get.mockResolvedValue(structuredClone(config));
		api.put.mockResolvedValue(undefined);
		api.send.mockResolvedValue(undefined);
	});
	afterEach(() => resetStores());

	it('edits locales, inserts placeholders, discards, and keyboard-navigates tabs', async () => {
		await renderPage();
		const tabs = screen.getAllByRole('tab');
		await fireEvent.keyDown(tabs[0], { key: 'End' });
		expect(tabs[2]).toHaveFocus();
		await fireEvent.keyDown(tabs[2], { key: 'ArrowRight' });
		expect(tabs[0]).toHaveFocus();
		await fireEvent.click(tabs[1]);
		expect(screen.getAllByRole('note').some((note) => note.textContent?.includes('Chinese is empty'))).toBe(true);

		const subject = screen.getByLabelText('Subject');
		await fireEvent.input(subject, { target: { value: '你好 {{Unknown}}' } });
		expect(screen.getByText(/Unknown placeholder \{\{Unknown\}\}/)).toBeInTheDocument();
		await fireEvent.focus(subject);
		await fireEvent.click(screen.getByRole('button', { name: /\{\{Email\}\}/ }));
		expect((subject as HTMLInputElement).value).toContain('{{Email}}');
		expect(screen.getByText(/Inserted/)).toBeInTheDocument();

		await fireEvent.click(screen.getByRole('button', { name: 'Discard changes' }));
		const dialog = screen.getByRole('dialog');
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Discard changes' }));
		expect(screen.getByLabelText('Subject')).toHaveValue('');
	});

	it('validates, saves with Ctrl+S, sends a test, and confirms disablement', async () => {
		await renderPage();
		const subject = screen.getByLabelText('Subject');
		await fireEvent.input(subject, { target: { value: '' } });
		await fireEvent.input(screen.getByLabelText('Body (plain text)'), { target: { value: '' } });
		await fireEvent.keyDown(window, { key: 's', ctrlKey: true });
		expect(await screen.findByText('Subject is required for English')).toBeInTheDocument();

		await fireEvent.input(subject, { target: { value: 'Updated welcome' } });
		await fireEvent.input(screen.getByLabelText('Body (plain text)'), { target: { value: 'Updated body' } });
		await fireEvent.change(screen.getByRole('combobox'), { target: { value: 'de' } });
		await fireEvent.keyDown(window, { key: 's', ctrlKey: true });
		await waitFor(() => expect(api.put).toHaveBeenCalledWith(expect.objectContaining({ default_locale: 'de' })));

		await fireEvent.click(screen.getByRole('button', { name: 'Send test to me' }));
		await waitFor(() => expect(api.send).toHaveBeenCalled());

		const enabled = screen.getByLabelText('Send a welcome email to new mailboxes');
		await fireEvent.click(enabled);
		const dialog = screen.getByRole('dialog');
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Turn off' }));
		expect(enabled).not.toBeChecked();
	});

	it('shows load and action failures without escaping the page', async () => {
		api.get.mockRejectedValueOnce(new Error('welcome unavailable'));
		await renderPage();
		expect(screen.getByRole('alert')).toHaveTextContent('welcome unavailable');
	});
});
