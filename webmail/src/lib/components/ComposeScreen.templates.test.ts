import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, fireEvent, screen, waitFor } from '@testing-library/svelte/svelte5';
import { composeStore } from '$lib/stores/compose';
import { jmapSession } from '$lib/stores/session';
import ComposeScreen from './ComposeScreen.svelte';

// A template body carrying an XSS payload. The security contract is that this
// NEVER reaches the editor raw — it must pass through sanitizeHTML on insert.
const MALICIOUS = '<img src=x onerror="boom()"><p>Hello template</p>';
const CLEAN = '<p>CLEAN_SENTINEL</p>';

// sanitizeHTML is mocked to a recognizable sentinel so we can prove BOTH sides:
// (1) it is called with the RAW template body, and (2) its return — not the raw
// body — is what lands in the editor.
const sanitizeMock = vi.fn((_h: string) => CLEAN);
vi.mock('$lib/sanitize', () => ({ sanitizeHTML: (h: string) => sanitizeMock(h) }));

vi.mock('$lib/jmap/emailTemplates', () => ({
	emailTemplateList: vi.fn(async () => [
		{ id: '1', name: 'Greeting', subject: 'Tpl subject', bodyHtml: MALICIOUS },
	]),
}));

vi.mock('$lib/jmap/offline-client', () => ({
	emailSet: vi.fn(async () => ({ created: {}, notCreated: {} })),
	emailSubmissionSet: vi.fn(async () => ({ created: {} })),
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
	};
});

describe('ComposeScreen — Insert Template (Quick Parts) sanitizes on insert', () => {
	beforeEach(() => {
		composeStore.close();
		jmapSession.set(null);
		sanitizeMock.mockClear();
		vi.stubGlobal('fetch', vi.fn((url: string) => {
			if (url === '/settings/signatures')
				return Promise.resolve({ ok: true, status: 200, json: async () => [], text: async () => '' });
			return Promise.resolve({ ok: true, status: 200, json: async () => ({ delegates: [], email: 'me@corp.test' }), text: async () => '' });
		}));
	});
	afterEach(() => vi.unstubAllGlobals());

	it('routes the template body through sanitizeHTML and inserts the SANITIZED output, never raw', async () => {
		composeStore.open();
		render(ComposeScreen);
		await waitFor(() => screen.getByTestId('compose-screen'));

		// Open the template menu and pick the (only) template.
		await fireEvent.click(screen.getByTestId('insert-template-btn'));
		await waitFor(() => screen.getByTestId('tpl-item-1'));
		await fireEvent.click(screen.getByTestId('tpl-item-1'));

		// (1) sanitizeHTML was called with the RAW malicious body.
		expect(sanitizeMock).toHaveBeenCalledWith(MALICIOUS);

		// (2) The sanitized output — not the raw body — is what reached the editor.
		await waitFor(() => {
			const pm = document.querySelector('.ProseMirror');
			expect(pm?.textContent ?? '').toContain('CLEAN_SENTINEL');
		});
		const pm = document.querySelector('.ProseMirror');
		expect(pm?.innerHTML ?? '').not.toContain('onerror');
		expect(pm?.textContent ?? '').not.toContain('boom');
	});

	it('fills the subject from the template when the compose subject is empty', async () => {
		composeStore.open();
		render(ComposeScreen);
		await waitFor(() => screen.getByTestId('compose-screen'));

		await fireEvent.click(screen.getByTestId('insert-template-btn'));
		await waitFor(() => screen.getByTestId('tpl-item-1'));
		await fireEvent.click(screen.getByTestId('tpl-item-1'));

		const subject = screen.getByLabelText('Subject') as HTMLInputElement;
		await waitFor(() => expect(subject.value).toBe('Tpl subject'));
	});
});
