import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte/svelte5';
import ReadingPane, { type ReadingPaneActions } from './ReadingPane.svelte';
import type { Email, Mailbox } from '$lib/types/jmap';

// Control isNative() so watermark tests can enable the native path.
// Default false — existing tests see no overlay and are unaffected.
vi.mock('$lib/native', () => ({ isNative: vi.fn().mockReturnValue(false) }));

// ReadingPane's only $lib/jmap/client import is assistComplete (Copilot assist,
// WAVE-5 #7) — safe to fully replace rather than importOriginal.
vi.mock('$lib/jmap/client', () => ({ assistComplete: vi.fn(), resetJmapAuthContext: vi.fn() }));

import { isNative } from '$lib/native';
import { offline } from '$lib/offline/state.svelte';
import { assistComplete } from '$lib/jmap/client';
import { jmapSession } from '$lib/stores/session';

// Build the action facade: the 12 required members default to fresh spies; pass
// overrides to supply an asserted spy or an optional member (which gates its
// button's rendering by presence).
function acts(o: Partial<ReadingPaneActions> = {}): ReadingPaneActions {
	return {
		onArchive: vi.fn(),
		onSnooze: vi.fn(),
		onTrash: vi.fn(),
		onMute: vi.fn(),
		onStar: vi.fn(),
		onReply: vi.fn(),
		onForward: vi.fn(),
		onRemoveTag: vi.fn(),
		onAddTag: vi.fn(),
		onCreateTag: vi.fn(),
		onSendReply: vi.fn(),
		onScheduleReply: vi.fn(),
		...o,
	};
}

function makeEmail(overrides: Partial<Email> = {}): Email {
	return {
		id: 'e1',
		threadId: 't1',
		mailboxIds: { mb1: true },
		from: [{ name: 'Alice Smith', email: 'alice@example.com' }],
		to: [{ name: 'Me', email: 'me@setjoin.local' }],
		subject: 'Quarterly report',
		preview: 'Preview text',
		bodyText: 'Hello, please review the report.',
		receivedAt: '2026-06-14T10:00:00Z',
		keywords: { $seen: true },
		...overrides,
	};
}

function makeTag(id: string, name: string, color = 'blue', parentId?: string): Mailbox {
	return { id, name, color, role: undefined, parentId };
}

describe('ReadingPane', () => {
	it('renders the subject in an <h1>', () => {
		const { container } = render(ReadingPane, {
			email: makeEmail(),
			mailboxes: [],
			currentRole: null,
			actions: acts(),
		});
		const h1 = container.querySelector('h1');
		expect(h1).not.toBeNull();
		expect(h1?.textContent?.trim()).toBe('Quarterly report');
	});

	it('renders sender name and email address', () => {
		const { container } = render(ReadingPane, {
			email: makeEmail(),
			mailboxes: [],
			currentRole: null,
			actions: acts(),
		});
		expect(container.textContent).toContain('Alice Smith');
		expect(container.textContent).toContain('alice@example.com');
	});

	it('renders an Avatar', () => {
		const { container } = render(ReadingPane, {
			email: makeEmail(),
			mailboxes: [],
			currentRole: null,
			actions: acts(),
		});
		expect(container.querySelector('.avatar')).not.toBeNull();
	});

	it('toolbar has Archive, Snooze, Trash, Mute and Star IconButtons', async () => {
		const onArchive = vi.fn();
		const onStar = vi.fn();
		const onMute = vi.fn();
		const { container } = render(ReadingPane, {
			email: makeEmail(),
			mailboxes: [],
			currentRole: null,
			actions: acts({ onArchive, onStar, onMute }),
		});

		const archiveBtn = container.querySelector('[aria-label="Archive"]') as HTMLButtonElement;
		expect(archiveBtn).not.toBeNull();
		await fireEvent.click(archiveBtn);
		expect(onArchive).toHaveBeenCalledTimes(1);

		const starBtn = container.querySelector('[aria-label="Star"]') as HTMLButtonElement;
		expect(starBtn).not.toBeNull();
		await fireEvent.click(starBtn);
		expect(onStar).toHaveBeenCalledTimes(1);

		const muteBtn = container.querySelector('[aria-label="Mute"]') as HTMLButtonElement;
		expect(muteBtn).not.toBeNull();
		await fireEvent.click(muteBtn);
		expect(onMute).toHaveBeenCalledTimes(1);
	});

	it('renders removable Tag chips for each tag on the email', async () => {
		const onRemoveTag = vi.fn();
		const mb1 = makeTag('mb1', 'Finance', 'blue');
		const mb2 = makeTag('mb2', 'Work', 'teal');

		const { container } = render(ReadingPane, {
			email: makeEmail({ mailboxIds: { mb1: true, mb2: true } }),
			mailboxes: [mb1, mb2],
			currentRole: null,
			actions: acts({ onRemoveTag }),
		});

		const tags = container.querySelectorAll('.tag');
		expect(tags.length).toBeGreaterThanOrEqual(2);

		// Find a remove button and click it
		const removeBtn = container.querySelector('[aria-label="Remove tag"]') as HTMLButtonElement;
		if (removeBtn) {
			await fireEvent.click(removeBtn);
			expect(onRemoveTag).toHaveBeenCalled();
		}
	});

	it('does not render system location-role mailboxes as removable chips', () => {
		const inbox = makeTag('mb-inbox', 'Inbox', 'gray');
		inbox.role = 'inbox';
		const trash = makeTag('mb-trash', 'Trash', 'gray');
		trash.role = 'trash';
		const finance = makeTag('mb-finance', 'Finance', 'green');

		const { container } = render(ReadingPane, {
			email: makeEmail({ mailboxIds: { 'mb-inbox': true, 'mb-trash': true, 'mb-finance': true } }),
			mailboxes: [inbox, trash, finance],
			currentRole: 'inbox',
			actions: acts(),
		});

		const tagBlock = container.querySelector('.sj-reading-body__tags');
		expect(tagBlock).not.toBeNull();
		// The user tag renders; the system location mailboxes do NOT.
		expect(tagBlock!.textContent).toContain('Finance');
		expect(tagBlock!.textContent).not.toContain('Inbox');
		expect(tagBlock!.textContent).not.toContain('Trash');
	});

	it('renders breadcrumb label for nested tags', () => {
		const parent = makeTag('mb1', 'Finance', 'blue');
		const child = makeTag('mb2', 'Invoices', 'teal', 'mb1');

		const { container } = render(ReadingPane, {
			email: makeEmail({ mailboxIds: { mb2: true } }),
			mailboxes: [parent, child],
			currentRole: null,
			actions: acts(),
		});

		// Nested tag should show breadcrumb "Finance/Invoices"
		expect(container.textContent).toContain('Finance/Invoices');
	});

	it('renders body text when bodyText is set', () => {
		const { container } = render(ReadingPane, {
			email: makeEmail({ bodyText: 'Hello world', bodyHTML: undefined }),
			mailboxes: [],
			currentRole: null,
			actions: acts(),
		});

		expect(container.textContent).toContain('Hello world');
	});

	it('Send button in inline reply is disabled when textarea is empty', () => {
		const onSendReply = vi.fn();
		const { container } = render(ReadingPane, {
			email: makeEmail(),
			mailboxes: [],
			currentRole: null,
			actions: acts({ onSendReply }),
		});

		const sendBtn = container.querySelector('[aria-label="Send"]') as HTMLButtonElement;
		expect(sendBtn).not.toBeNull();
		expect(sendBtn.disabled).toBe(true);

		const textarea = container.querySelector('textarea') as HTMLTextAreaElement;
		expect(textarea).not.toBeNull();
	});

	it('calls onSendReply when Send is clicked with text', async () => {
		const onSendReply = vi.fn();
		const { container } = render(ReadingPane, {
			email: makeEmail(),
			mailboxes: [],
			currentRole: null,
			actions: acts({ onSendReply }),
		});

		// Type text into the native textarea
		const textarea = container.querySelector('textarea') as HTMLTextAreaElement;
		expect(textarea).not.toBeNull();
		await fireEvent.input(textarea, { target: { value: 'Got it, thanks!' } });

		// Click the Send button
		const sendBtn = container.querySelector('[aria-label="Send"]') as HTMLButtonElement;
		expect(sendBtn).not.toBeNull();
		expect(sendBtn.disabled).toBe(false);
		await fireEvent.click(sendBtn);

		expect(onSendReply).toHaveBeenCalledTimes(1);
		expect(onSendReply).toHaveBeenCalledWith('Got it, thanks!');
	});

	it('uses mono font for body for machine-generated (mono) mail', () => {
		// mono is now derived per-card from the message (isMonoBody), not a pane prop.
		const { container } = render(ReadingPane, {
			email: makeEmail({ mono: true, bodyText: 'System alert: disk 80%', bodyHTML: undefined }),
			mailboxes: [],
			currentRole: null,
			actions: acts(),
		});

		const bodyEl = container.querySelector('.sj-reading-body__text');
		expect(bodyEl).not.toBeNull();
		expect(bodyEl?.classList.contains('sj-reading-body__text--mono')).toBe(true);
	});

	it('renders Reply and Forward buttons in sender block', () => {
		const onReply = vi.fn();
		const onForward = vi.fn();
		const { container } = render(ReadingPane, {
			email: makeEmail(),
			mailboxes: [],
			currentRole: null,
			actions: acts({ onReply, onForward }),
		});

		expect(container.querySelector('[aria-label="Reply"]')).not.toBeNull();
		expect(container.querySelector('[aria-label="Forward"]')).not.toBeNull();
	});

	it('shows Not Spam button instead of Trash when currentRole is spam', () => {
		const onNotSpam = vi.fn();
		const { container } = render(ReadingPane, {
			email: makeEmail(),
			mailboxes: [],
			currentRole: 'spam',
			actions: acts({ onNotSpam }),
		});

		expect(container.querySelector('[aria-label="Not Spam"]')).not.toBeNull();
		expect(container.querySelector('[aria-label="Trash"]')).toBeNull();
	});

	it('shows Trash button with Delete permanently label when currentRole is trash', () => {
		const { container } = render(ReadingPane, {
			email: makeEmail(),
			mailboxes: [],
			currentRole: 'trash',
			actions: acts(),
		});

		expect(container.querySelector('[aria-label="Delete permanently"]')).not.toBeNull();
		expect(container.querySelector('[aria-label="Trash"]')).toBeNull();
	});

	it('calls onNotSpam when Not Spam button is clicked', async () => {
		const onNotSpam = vi.fn();
		const { container } = render(ReadingPane, {
			email: makeEmail(),
			mailboxes: [],
			currentRole: 'spam',
			actions: acts({ onNotSpam }),
		});

		const notSpamBtn = container.querySelector('[aria-label="Not Spam"]') as HTMLButtonElement;
		expect(notSpamBtn).not.toBeNull();
		await fireEvent.click(notSpamBtn);
		expect(onNotSpam).toHaveBeenCalledTimes(1);
	});

	it('vote buttons call onVoteResponse when clicked', async () => {
		const onVoteResponse = vi.fn();
		const { container } = render(ReadingPane, {
			email: makeEmail({ voteOptions: ['Approve', 'Reject', 'Abstain'] }),
			mailboxes: [],
			currentRole: null,
			actions: acts({ onVoteResponse }),
		});

		const buttons = container.querySelectorAll('.sj-reading-body__vote-btn');
		expect(buttons.length).toBe(3);
		await fireEvent.click(buttons[0] as HTMLButtonElement);
		expect(onVoteResponse).toHaveBeenCalledTimes(1);
		expect(onVoteResponse).toHaveBeenCalledWith('Approve');
	});

	it('renders a download anchor per non-previewable attachment (href + download + filename)', () => {
		// A non-previewable type (zip) stays a download <a>; image/PDF now open a preview
		// dialog (covered in the "attachment preview" describe below).
		const { container } = render(ReadingPane, {
			email: makeEmail({
				hasAttachment: true,
				attachments: [{ blobId: 'sha1', name: 'archive.zip', type: 'application/zip', disposition: 'attachment', size: 2048 }],
			}),
			mailboxes: [],
			currentRole: null,
			actions: acts(),
			accountId: 'acc1',
		});
		const chip = container.querySelector('a.sj-reading-body__attachment-chip');
		expect(chip).not.toBeNull();
		expect(chip?.getAttribute('href')).toContain('/jmap/download/acc1/sha1/');
		expect(chip?.hasAttribute('download')).toBe(true);
		expect(chip?.querySelector('.sj-reading-body__attachment-name')?.textContent).toBe('archive.zip');
	});

	it('renders one chip per attachment with its filename', () => {
		const { container } = render(ReadingPane, {
			email: makeEmail({
				hasAttachment: true,
				attachments: [
					{ blobId: 's1', name: 'invoice-2384.pdf', disposition: 'attachment' },
					{ blobId: 's2', name: 'notes.txt', disposition: 'attachment' },
				],
			}),
			mailboxes: [],
			currentRole: null,
			actions: acts(),
			accountId: 'acc1',
		});
		const names = container.querySelectorAll('.sj-reading-body__attachment-name');
		expect(names.length).toBe(2);
		expect(names[0].textContent).toBe('invoice-2384.pdf');
		expect(names[1].textContent).toBe('notes.txt');
	});

	it('renders the "Save all" zip anchor only when there is more than one attachment', () => {
		const two = render(ReadingPane, {
			email: makeEmail({
				id: 'm42',
				hasAttachment: true,
				attachments: [
					{ blobId: 's1', name: 'a.pdf', disposition: 'attachment' },
					{ blobId: 's2', name: 'b.pdf', disposition: 'attachment' },
				],
			}),
			mailboxes: [],
			currentRole: null,
			actions: acts(),
			accountId: 'acc1',
		});
		const saveAll = two.container.querySelector('a.sj-reading-body__attachment-saveall');
		expect(saveAll).not.toBeNull();
		expect(saveAll?.getAttribute('href')).toBe('/api/messages/m42/attachments.zip');
		expect(saveAll?.hasAttribute('download')).toBe(true);

		// A single attachment gets no "Save all" affordance.
		const one = render(ReadingPane, {
			email: makeEmail({
				hasAttachment: true,
				attachments: [{ blobId: 's1', name: 'only.pdf', disposition: 'attachment' }],
			}),
			mailboxes: [],
			currentRole: null,
			actions: acts(),
			accountId: 'acc1',
		});
		expect(one.container.querySelector('a.sj-reading-body__attachment-saveall')).toBeNull();
	});

	it('filters out inline attachments — only real attachments get chips', () => {
		const { container } = render(ReadingPane, {
			email: makeEmail({
				hasAttachment: true,
				attachments: [
					{ blobId: 's1', name: 'real.pdf', disposition: 'attachment' },
					{ blobId: 's2', name: 'logo.png', disposition: 'inline' },
				],
			}),
			mailboxes: [],
			currentRole: null,
			actions: acts(),
			accountId: 'acc1',
		});
		const chips = container.querySelectorAll('.sj-reading-body__attachment-chip');
		expect(chips.length).toBe(1);
		expect(container.querySelector('.sj-reading-body__attachment-name')?.textContent).toBe('real.pdf');
	});

	it('renders the HTML body in a locked-down sandbox="" srcdoc iframe (never src, never allow-*)', async () => {
		// Sanitization is now per-card (MessageCard owns it), so no sanitizedHTML prop —
		// the card sanitizes email.bodyHTML itself before rendering the srcdoc iframe.
		const { container } = render(ReadingPane, {
			email: makeEmail({ bodyHTML: '<p>x</p>' }),
			mailboxes: [],
			currentRole: null,
			actions: acts(),
		});

		// Flip the Show-HTML toggle so the iframe branch actually mounts.
		const toggle = container.querySelector('.sj-reading-body__html-toggle') as HTMLButtonElement;
		expect(toggle).not.toBeNull();
		await fireEvent.click(toggle);

		const frame = container.querySelector('iframe[title="Email HTML content"]') as HTMLIFrameElement;
		expect(frame).not.toBeNull();
		// Sandbox must be exactly empty — any token is a loosening.
		expect(frame.getAttribute('sandbox')).toBe('');
		expect(frame.getAttribute('sandbox')).not.toContain('allow-scripts');
		expect(frame.getAttribute('sandbox')).not.toContain('allow-same-origin');
		// srcdoc (inline) not src (same-origin navigation).
		expect(frame.getAttribute('srcdoc')).not.toBeNull();
		expect(frame.getAttribute('src')).toBeNull();
	});

	it('reply textarea placeholder includes sender name', () => {
		const { container } = render(ReadingPane, {
			email: makeEmail(),
			mailboxes: [],
			currentRole: null,
			actions: acts(),
		});

		const textarea = container.querySelector('textarea') as HTMLTextAreaElement;
		expect(textarea).not.toBeNull();
		expect(textarea.placeholder).toContain('Alice Smith');
		expect(textarea.placeholder).not.toContain('{senderName}');
	});
});

describe('ReadingPane — conversation view (thread cards)', () => {
	it('renders one MessageCard per thread message, newest expanded, older collapsed', () => {
		const m1 = makeEmail({ id: 'm1', bodyText: 'body one', preview: 'prev one', receivedAt: '2026-06-14T10:00:00Z' });
		const m2 = makeEmail({ id: 'm2', bodyText: 'body two', preview: 'prev two', receivedAt: '2026-06-14T11:00:00Z' });
		const m3 = makeEmail({ id: 'm3', bodyText: 'body three', preview: 'prev three', receivedAt: '2026-06-14T12:00:00Z' });
		const { container } = render(ReadingPane, {
			email: m3, // context = newest
			emails: [m1, m2, m3], // ascending receivedAt
			mailboxes: [],
			currentRole: null,
			actions: acts(),
		});

		// Three cards.
		expect(container.querySelectorAll('.sj-msg-card').length).toBe(3);

		// Newest (m3) is expanded → its body text is present.
		expect(container.textContent).toContain('body three');

		// m1/m2 are collapsed → their body text is absent (only their preview shows).
		expect(container.textContent).not.toContain('body one');
		expect(container.textContent).not.toContain('body two');
		expect(container.textContent).toContain('prev one');
	});

	it('clicking a collapsed card header expands it and reveals its body', async () => {
		const m1 = makeEmail({ id: 'm1', bodyText: 'body one', preview: 'prev one', receivedAt: '2026-06-14T10:00:00Z' });
		const m2 = makeEmail({ id: 'm2', bodyText: 'body two', preview: 'prev two', receivedAt: '2026-06-14T12:00:00Z' });
		const { container, getByText } = render(ReadingPane, {
			email: m2,
			emails: [m1, m2],
			mailboxes: [],
			currentRole: null,
			actions: acts(),
		});

		expect(container.textContent).not.toContain('body one');

		// The collapsed m1 summary shows its preview; click it to expand.
		await fireEvent.click(getByText('prev one'));
		expect(container.textContent).toContain('body one');
	});

	it('falls back to a single card from the email prop when no emails are given', () => {
		const { container } = render(ReadingPane, {
			email: makeEmail({ bodyText: 'solo body' }),
			mailboxes: [],
			currentRole: null,
			actions: acts(),
		});
		expect(container.querySelectorAll('.sj-msg-card').length).toBe(1);
		expect(container.textContent).toContain('solo body');
	});
});

describe('ReadingPane — A2 triage actions', () => {
	it('renders Reply all only when onReplyAll is provided and fires it', async () => {
		const noBtn = render(ReadingPane, {
			email: makeEmail(), mailboxes: [], currentRole: null, actions: acts(),
		});
		expect(noBtn.container.querySelector('[aria-label="Reply all"]')).toBeNull();

		const onReplyAll = vi.fn();
		const { container } = render(ReadingPane, {
			email: makeEmail(), mailboxes: [], currentRole: null, actions: acts({ onReplyAll }),
		});
		const btn = container.querySelector('[aria-label="Reply all"]') as HTMLButtonElement;
		expect(btn).not.toBeNull();
		await fireEvent.click(btn);
		expect(onReplyAll).toHaveBeenCalledOnce();
	});

	it('shows Mark unread for a read email and toggles to unread', async () => {
		const onToggleRead = vi.fn();
		const { container } = render(ReadingPane, {
			email: makeEmail({ keywords: { $seen: true } }),
			mailboxes: [], currentRole: null, actions: acts({ onToggleRead }),
		});
		const btn = container.querySelector('[aria-label="Mark unread"]') as HTMLButtonElement;
		expect(btn).not.toBeNull();
		await fireEvent.click(btn);
		expect(onToggleRead).toHaveBeenCalledWith(false);
	});

	it('shows Mark read for an unread email and toggles to read', async () => {
		const onToggleRead = vi.fn();
		const { container } = render(ReadingPane, {
			email: makeEmail({ keywords: {} }),
			mailboxes: [], currentRole: null, actions: acts({ onToggleRead }),
		});
		const btn = container.querySelector('[aria-label="Mark read"]') as HTMLButtonElement;
		expect(btn).not.toBeNull();
		await fireEvent.click(btn);
		expect(onToggleRead).toHaveBeenCalledWith(true);
	});

	it('opens the follow-up picker and forwards a due date', async () => {
		const onFollowUp = vi.fn();
		const { container, getByText } = render(ReadingPane, {
			email: makeEmail(), mailboxes: [], currentRole: null, actions: acts({ onFollowUp }),
		});
		const flagBtn = container.querySelector('[aria-label="Flag for follow-up"]') as HTMLButtonElement;
		expect(flagBtn).not.toBeNull();
		await fireEvent.click(flagBtn);
		await fireEvent.click(getByText('Today'));
		expect(onFollowUp).toHaveBeenCalledOnce();
		const sel = onFollowUp.mock.calls[0][0];
		expect(sel.dueAt instanceof Date).toBe(true);
	});

	it('shows a due-date chip when flagDueAt is set', () => {
		const { container } = render(ReadingPane, {
			email: makeEmail({ flagDueAt: '2026-06-20T17:00:00Z' }),
			mailboxes: [], currentRole: null, actions: acts(),
		});
		expect(container.querySelector('.sj-reading-body__followup-chip')).not.toBeNull();
	});

	it('renders a Block sender action only when onBlockSender is provided and fires it', async () => {
		const noBtn = render(ReadingPane, {
			email: makeEmail(), mailboxes: [], currentRole: null, actions: acts(),
		});
		expect(noBtn.container.querySelector('[aria-label="Block sender"]')).toBeNull();

		const onBlockSender = vi.fn();
		const { container } = render(ReadingPane, {
			email: makeEmail(), mailboxes: [], currentRole: null, actions: acts({ onBlockSender }),
		});
		const btn = container.querySelector('[aria-label="Block sender"]') as HTMLButtonElement;
		expect(btn).not.toBeNull();
		await fireEvent.click(btn);
		expect(onBlockSender).toHaveBeenCalledOnce();
	});

	it('renders quick steps and forwards apply', async () => {
		const onApplyQuickStep = vi.fn();
		const { getByText } = render(ReadingPane, {
			email: makeEmail(), mailboxes: [], currentRole: null, actions: acts({ onApplyQuickStep }),
			quickSteps: [{ id: '1', name: 'File it', icon: 'Zap', position: 0, actions: [{ type: 'mark_read' }] }],
		});
		await fireEvent.click(getByText('File it'));
		expect(onApplyQuickStep).toHaveBeenCalledWith('1');
	});
});

describe('ReadingPane — attachment preview (inline image/PDF)', () => {
	it('a previewable image renders a preview <button>, not a download anchor', () => {
		const { container } = render(ReadingPane, {
			email: makeEmail({
				hasAttachment: true,
				attachments: [{ blobId: 'img1', name: 'photo.png', type: 'image/png', disposition: 'attachment', size: 1024 }],
			}),
			mailboxes: [], currentRole: null, actions: acts(), accountId: 'acc1',
		});
		expect(container.querySelector('button.sj-reading-body__attachment-chip')).not.toBeNull();
		expect(container.querySelector('a.sj-reading-body__attachment-chip')).toBeNull();
	});

	it('clicking an image chip opens a dialog with an <img> at the inline URL (no ?type); footer keeps the download', async () => {
		const { container } = render(ReadingPane, {
			email: makeEmail({
				hasAttachment: true,
				attachments: [{ blobId: 'img1', name: 'photo.png', type: 'image/png', disposition: 'attachment' }],
			}),
			mailboxes: [], currentRole: null, actions: acts(), accountId: 'acc1',
		});
		await fireEvent.click(container.querySelector('button.sj-reading-body__attachment-chip') as HTMLButtonElement);

		const img = container.querySelector('.sj-attachment-preview__img') as HTMLImageElement;
		expect(img).not.toBeNull();
		expect(img.getAttribute('src')).toBe('/jmap/download/acc1/img1/photo.png');
		expect(img.getAttribute('src')).not.toContain('?type');

		const dl = container.querySelector('.sj-attachment-preview__download') as HTMLAnchorElement;
		expect(dl).not.toBeNull();
		expect(dl.getAttribute('href')).toBe('/jmap/download/acc1/img1/photo.png?type=application/octet-stream');
		expect(dl.hasAttribute('download')).toBe(true);
	});

	it('a previewable PDF opens a same-origin iframe kept sandbox="" at the inline URL', async () => {
		const { container } = render(ReadingPane, {
			email: makeEmail({
				hasAttachment: true,
				attachments: [{ blobId: 'pdf1', name: 'doc.pdf', type: 'application/pdf', disposition: 'attachment' }],
			}),
			mailboxes: [], currentRole: null, actions: acts(), accountId: 'acc1',
		});
		await fireEvent.click(container.querySelector('button.sj-reading-body__attachment-chip') as HTMLButtonElement);

		const frame = container.querySelector('iframe.sj-attachment-preview__frame') as HTMLIFrameElement;
		expect(frame).not.toBeNull();
		expect(frame.getAttribute('sandbox')).toBe('');
		expect(frame.getAttribute('src')).toBe('/jmap/download/acc1/pdf1/doc.pdf');
		expect(frame.getAttribute('src')).not.toContain('?type');
	});

	it('a non-previewable attachment stays a download anchor with the ?type override', () => {
		const { container } = render(ReadingPane, {
			email: makeEmail({
				hasAttachment: true,
				attachments: [{ blobId: 'z1', name: 'archive.zip', type: 'application/zip', disposition: 'attachment' }],
			}),
			mailboxes: [], currentRole: null, actions: acts(), accountId: 'acc1',
		});
		const anchor = container.querySelector('a.sj-reading-body__attachment-chip') as HTMLAnchorElement;
		expect(anchor).not.toBeNull();
		expect(anchor.getAttribute('href')).toContain('?type=application/octet-stream');
		expect(container.querySelector('button.sj-reading-body__attachment-chip')).toBeNull();
	});
});

describe('ReadingPane — email → task (Feature 4)', () => {
	it('renders a Create task action only when onCreateTask is provided and fires it', async () => {
		const noBtn = render(ReadingPane, {
			email: makeEmail(), mailboxes: [], currentRole: null, actions: acts(),
		});
		expect(noBtn.container.querySelector('[aria-label="Create task"]')).toBeNull();

		const onCreateTask = vi.fn();
		const { container } = render(ReadingPane, {
			email: makeEmail(), mailboxes: [], currentRole: null, actions: acts({ onCreateTask }),
		});
		const btn = container.querySelector('[aria-label="Create task"]') as HTMLButtonElement;
		expect(btn).not.toBeNull();
		await fireEvent.click(btn);
		expect(onCreateTask).toHaveBeenCalledOnce();
	});
});

describe('ReadingPane — print (Feature 2)', () => {
	it('renders a Print action that calls window.open when clicked', async () => {
		const openSpy = vi.spyOn(window, 'open').mockReturnValue(null);
		const { container } = render(ReadingPane, {
			email: makeEmail(), mailboxes: [], currentRole: null, actions: acts(),
		});
		const btn = container.querySelector('[aria-label="Print"]') as HTMLButtonElement;
		expect(btn).not.toBeNull();
		await fireEvent.click(btn);
		expect(openSpy).toHaveBeenCalledWith('', '_blank');
		openSpy.mockRestore();
	});
});

describe('ReadingPane — read-receipt $effect (Track A MDN privacy)', () => {
	// The consent banner is a role="region" labelled by the privacy prompt string.
	const bannerSelector = '[role="region"][aria-label="Send a read receipt?"]';

	it("policy 'always' + receipt requested → auto-fires onReadReceipt(true), no banner", () => {
		const onReadReceipt = vi.fn();
		const { container } = render(ReadingPane, {
			email: makeEmail({ readReceiptRequested: true }),
			mailboxes: [], currentRole: null, actions: acts({ onReadReceipt }),
			readReceiptPolicy: 'always',
		});
		expect(onReadReceipt).toHaveBeenCalledTimes(1);
		expect(onReadReceipt).toHaveBeenCalledWith(true);
		expect(container.querySelector(bannerSelector)).toBeNull();
	});

	// Resolve a button by its visible text WITHIN the consent banner (the inline
	// reply also has a "Send", so scope to the banner region to avoid ambiguity).
	function bannerButton(container: HTMLElement, text: string): HTMLButtonElement {
		const banner = container.querySelector(bannerSelector) as HTMLElement;
		expect(banner).not.toBeNull();
		const btn = Array.from(banner.querySelectorAll('button')).find(
			(b) => b.textContent?.trim() === text,
		) as HTMLButtonElement | undefined;
		expect(btn, `banner button "${text}"`).not.toBeUndefined();
		return btn!;
	}

	it("policy 'ask' + receipt requested → shows consent banner, does NOT auto-fire until the user acts", async () => {
		const onReadReceipt = vi.fn();
		const { container } = render(ReadingPane, {
			email: makeEmail({ readReceiptRequested: true }),
			mailboxes: [], currentRole: null, actions: acts({ onReadReceipt }),
			readReceiptPolicy: 'ask',
		});
		// Banner is visible; nothing sent yet.
		expect(container.querySelector(bannerSelector)).not.toBeNull();
		expect(onReadReceipt).not.toHaveBeenCalled();

		// User opts in → onReadReceipt(true) fires and the banner closes.
		await fireEvent.click(bannerButton(container, 'Send'));
		expect(onReadReceipt).toHaveBeenCalledTimes(1);
		expect(onReadReceipt).toHaveBeenCalledWith(true);
		expect(container.querySelector(bannerSelector)).toBeNull();
	});

	it("policy 'ask' + receipt requested → 'Don't send' relays consent=false (recipient declines)", async () => {
		const onReadReceipt = vi.fn();
		const { container } = render(ReadingPane, {
			email: makeEmail({ readReceiptRequested: true }),
			mailboxes: [], currentRole: null, actions: acts({ onReadReceipt }),
			readReceiptPolicy: 'ask',
		});
		expect(onReadReceipt).not.toHaveBeenCalled();
		await fireEvent.click(bannerButton(container, "Don't send"));
		expect(onReadReceipt).toHaveBeenCalledTimes(1);
		expect(onReadReceipt).toHaveBeenCalledWith(false);
		expect(container.querySelector(bannerSelector)).toBeNull();
	});

	it("policy 'never' + receipt requested → never fires onReadReceipt, no banner", () => {
		const onReadReceipt = vi.fn();
		const { container } = render(ReadingPane, {
			email: makeEmail({ readReceiptRequested: true }),
			mailboxes: [], currentRole: null, actions: acts({ onReadReceipt }),
			readReceiptPolicy: 'never',
		});
		expect(onReadReceipt).not.toHaveBeenCalled();
		expect(container.querySelector(bannerSelector)).toBeNull();
	});

	it('no receipt requested → never fires and shows no banner regardless of policy', () => {
		const onReadReceipt = vi.fn();
		const { container } = render(ReadingPane, {
			email: makeEmail({ readReceiptRequested: false }),
			mailboxes: [], currentRole: null, actions: acts({ onReadReceipt }),
			readReceiptPolicy: 'always',
		});
		expect(onReadReceipt).not.toHaveBeenCalled();
		expect(container.querySelector(bannerSelector)).toBeNull();
	});
});

describe('ReadingPane — S/MIME verdict badge (A10)', () => {
	it('renders "Verified sender" text for a valid-verdict email', () => {
		const { container } = render(ReadingPane, {
			email: makeEmail({ smimeStatus: 'valid', smimeSignerCn: 'ACME Corp' }),
			mailboxes: [], currentRole: null, actions: acts(),
		});
		expect(container.textContent).toContain('Verified sender');
	});

	it('renders the signer CN after the verified text', () => {
		const { container } = render(ReadingPane, {
			email: makeEmail({ smimeStatus: 'valid', smimeSignerCn: 'ACME Corp' }),
			mailboxes: [], currentRole: null, actions: acts(),
		});
		expect(container.textContent).toContain('ACME Corp');
	});

	it('renders signer email when CN is absent', () => {
		const { container } = render(ReadingPane, {
			email: makeEmail({ smimeStatus: 'valid', smimeSignerEmail: 'certs@acme.com' }),
			mailboxes: [], currentRole: null, actions: acts(),
		});
		expect(container.textContent).toContain('certs@acme.com');
	});

	it('renders "Signed — signature not verified" for an untrusted email', () => {
		const { container } = render(ReadingPane, {
			email: makeEmail({ smimeStatus: 'untrusted' }),
			mailboxes: [], currentRole: null, actions: acts(),
		});
		expect(container.textContent).toContain('Signed — signature not verified');
		expect(container.textContent).not.toContain('Verified sender');
	});

	it('renders "Signed — signature not verified" for an invalid email', () => {
		const { container } = render(ReadingPane, {
			email: makeEmail({ smimeStatus: 'invalid' }),
			mailboxes: [], currentRole: null, actions: acts(),
		});
		expect(container.textContent).toContain('Signed — signature not verified');
	});

	it('does NOT render a verified badge for an invalid-verdict email', () => {
		const { container } = render(ReadingPane, {
			email: makeEmail({ smimeStatus: 'invalid' }),
			mailboxes: [], currentRole: null, actions: acts(),
		});
		expect(container.textContent).not.toContain('Verified sender');
	});

	it('renders no S/MIME badge when smimeStatus is absent', () => {
		const { container } = render(ReadingPane, {
			email: makeEmail({ smimeStatus: undefined }),
			mailboxes: [], currentRole: null, actions: acts(),
		});
		expect(container.querySelector('.sj-reading-body__smime-badge')).toBeNull();
	});

	it('verified badge has the --verified modifier class', () => {
		const { container } = render(ReadingPane, {
			email: makeEmail({ smimeStatus: 'valid' }),
			mailboxes: [], currentRole: null, actions: acts(),
		});
		const badge = container.querySelector('.sj-reading-body__smime-badge--verified');
		expect(badge).not.toBeNull();
	});
});

describe('ReadingPane — encrypted read states (D-F1 / D-F4 Lock idiom)', () => {
	it('decrypted: renders a Lock "Encrypted" chip AND the decrypted body', () => {
		const { container } = render(ReadingPane, {
			email: makeEmail({
				cryptoType: 'smime-encrypted', decryptState: 'decrypted',
				bodyText: 'the decrypted body',
			}),
			mailboxes: [], currentRole: null, actions: acts(),
		});
		const chip = container.querySelector('.sj-reading-body__smime-badge--encrypted');
		expect(chip).not.toBeNull();
		expect(chip?.textContent).toContain('Encrypted');
		expect(container.textContent).toContain('the decrypted body');
	});

	it('signed + encrypted: shows BOTH the verified ShieldCheck badge and the Lock chip', () => {
		const { container } = render(ReadingPane, {
			email: makeEmail({
				smimeStatus: 'valid', cryptoType: 'smime-encrypted', decryptState: 'decrypted',
				bodyText: 'signed and encrypted body',
			}),
			mailboxes: [], currentRole: null, actions: acts(),
		});
		expect(container.querySelector('.sj-reading-body__smime-badge--verified')).not.toBeNull();
		expect(container.querySelector('.sj-reading-body__smime-badge--encrypted')).not.toBeNull();
	});

	it('no_key: renders the calm copy + the Settings link, NO body, NO error styling', () => {
		const { container } = render(ReadingPane, {
			email: makeEmail({
				cryptoType: 'smime-encrypted', decryptState: 'no_key',
				bodyText: undefined, preview: 'leaked?',
			}),
			mailboxes: [], currentRole: null, actions: acts(),
		});
		expect(container.textContent).toContain("Your private key isn't on the server");
		expect(container.textContent).toContain('Go to Settings → Security');
		// Calm, never red/error styling.
		expect(container.querySelector('.sj-reading-body__decrypt-state--error')).toBeNull();
		// The plaintext preview must NOT be rendered as the body.
		expect(container.textContent).not.toContain('leaked?');
	});

	it('wrong_key: renders the "certificate you no longer have" copy', () => {
		const { container } = render(ReadingPane, {
			email: makeEmail({ cryptoType: 'smime-encrypted', decryptState: 'wrong_key', bodyText: undefined }),
			mailboxes: [], currentRole: null, actions: acts(),
		});
		expect(container.textContent).toContain('certificate you no longer have');
	});

	it('error: renders the calm try-again copy', () => {
		const { container } = render(ReadingPane, {
			email: makeEmail({ cryptoType: 'smime-encrypted', decryptState: 'error', bodyText: undefined }),
			mailboxes: [], currentRole: null, actions: acts(),
		});
		expect(container.textContent).toContain('could not be opened right now');
	});
});

describe('ReadingPane — Recall (Task 1)', () => {
	it('shows a Recall button when currentRole is sent and onRecall is given', () => {
		const { container } = render(ReadingPane, {
			email: makeEmail(), mailboxes: [],
			currentRole: 'sent', actions: acts({ onRecall: vi.fn() }),
		});
		expect(container.querySelector('[aria-label="Recall"]')).not.toBeNull();
	});

	it('does NOT show Recall in the inbox', () => {
		const { container } = render(ReadingPane, {
			email: makeEmail(), mailboxes: [],
			currentRole: 'inbox', actions: acts({ onRecall: vi.fn() }),
		});
		expect(container.querySelector('[aria-label="Recall"]')).toBeNull();
	});

	it('does NOT show Recall when onRecall is absent (even in Sent)', () => {
		const { container } = render(ReadingPane, {
			email: makeEmail(), mailboxes: [],
			currentRole: 'sent', actions: acts(),
		});
		expect(container.querySelector('[aria-label="Recall"]')).toBeNull();
	});

	it('fires onRecall when clicked', async () => {
		const onRecall = vi.fn();
		const { container } = render(ReadingPane, {
			email: makeEmail(), mailboxes: [],
			currentRole: 'sent', actions: acts({ onRecall }),
		});
		const btn = container.querySelector('[aria-label="Recall"]') as HTMLButtonElement;
		expect(btn).not.toBeNull();
		await fireEvent.click(btn);
		expect(onRecall).toHaveBeenCalledOnce();
	});

	// --- MAM watermark overlay integration ---
	describe('WatermarkOverlay mount', () => {
		beforeEach(() => {
			vi.mocked(isNative).mockReturnValue(false);
			offline.watermarkEnabled = false;
		});

		it('renders the tiled identity stamp when native + watermarkEnabled', () => {
			vi.mocked(isNative).mockReturnValue(true);
			offline.watermarkEnabled = true;
			const { getAllByText } = render(ReadingPane, {
				email: makeEmail(), mailboxes: [], currentRole: null,
				userEmail: 'user@test.example',
				actions: acts(),
			});
			// Tiled overlay: more than one stamp span with the user email.
			expect(getAllByText(/user@test\.example/).length).toBeGreaterThan(1);
		});

		it('renders nothing when watermarkEnabled is false (even in native)', () => {
			vi.mocked(isNative).mockReturnValue(true);
			offline.watermarkEnabled = false;
			const { queryByText } = render(ReadingPane, {
				email: makeEmail(), mailboxes: [], currentRole: null,
				userEmail: 'user@test.example',
				actions: acts(),
			});
			expect(queryByText(/user@test\.example/)).toBeNull();
		});

		it('renders nothing when not native (plain browser)', () => {
			vi.mocked(isNative).mockReturnValue(false);
			offline.watermarkEnabled = true;
			const { queryByText } = render(ReadingPane, {
				email: makeEmail(), mailboxes: [], currentRole: null,
				userEmail: 'user@test.example',
				actions: acts(),
			});
			expect(queryByText(/user@test\.example/)).toBeNull();
		});
	});

	// --- Copilot assist menu (WAVE-5 #7): Summarize + Translate merged into ONE
	// Sparkles menu, plain-text result, "Show original" for translation, error
	// copy mirrored per mode. ---
	describe('Copilot assist menu (WAVE-5 #7)', () => {
		afterEach(() => {
			jmapSession.set(null);
			vi.mocked(assistComplete).mockReset();
		});

		function enableAssist() {
			jmapSession.set({ effectiveCapabilities: { features: { assist: true } } } as never);
		}

		it('is not rendered when feature.assist is off', () => {
			const { queryByRole } = render(ReadingPane, {
				email: makeEmail(), mailboxes: [], currentRole: null, actions: acts(),
			});
			expect(queryByRole('button', { name: 'Assist' })).toBeNull();
		});

		it('offers Summarize and Translate as items of ONE menu (not sibling icons)', async () => {
			enableAssist();
			const { getByRole, findByRole } = render(ReadingPane, {
				email: makeEmail(), mailboxes: [], currentRole: null, actions: acts(),
			});
			await fireEvent.click(getByRole('button', { name: 'Assist' }));
			expect(await findByRole('menuitem', { name: 'Summarize' })).toBeTruthy();
			expect(await findByRole('menuitem', { name: 'Translate' })).toBeTruthy();
		});

		it('Translate renders a plain-text result with a "Show original" affordance', async () => {
			enableAssist();
			vi.mocked(assistComplete).mockResolvedValue('Bonjour');
			const { getByRole, findByRole, findByText } = render(ReadingPane, {
				email: makeEmail(), mailboxes: [], currentRole: null, actions: acts(),
			});
			await fireEvent.click(getByRole('button', { name: 'Assist' }));
			await fireEvent.click(await findByRole('menuitem', { name: 'Translate' }));

			expect(await findByText('Bonjour')).toBeTruthy();
			// Prompt targets the UI locale (no picker) — plain text only, never HTML.
			expect(assistComplete).toHaveBeenCalledWith(
				[{ role: 'user', content: expect.stringContaining('Translate this email') }],
				expect.anything(),
			);
			expect(await findByRole('button', { name: 'Show original' })).toBeTruthy();
		});

		it('Summarize still works standalone through the same menu', async () => {
			enableAssist();
			vi.mocked(assistComplete).mockResolvedValue('Point one. Point two.');
			const { getByRole, findByRole, findByText, queryByRole } = render(ReadingPane, {
				email: makeEmail(), mailboxes: [], currentRole: null, actions: acts(),
			});
			await fireEvent.click(getByRole('button', { name: 'Assist' }));
			await fireEvent.click(await findByRole('menuitem', { name: 'Summarize' }));

			expect(await findByText('Point one. Point two.')).toBeTruthy();
			// Summarize has no "Show original" toggle (only translation does).
			expect(queryByRole('button', { name: 'Show original' })).toBeNull();
		});

		it('mirrors the failure copy per mode (translate vs summarize)', async () => {
			enableAssist();
			vi.mocked(assistComplete).mockRejectedValue(new Error('boom'));
			const { getByRole, findByRole, findByText } = render(ReadingPane, {
				email: makeEmail(), mailboxes: [], currentRole: null, actions: acts(),
			});
			await fireEvent.click(getByRole('button', { name: 'Assist' }));
			await fireEvent.click(await findByRole('menuitem', { name: 'Translate' }));
			expect(await findByText('Could not translate this email. Try again.')).toBeTruthy();
		});
	});

	// --- Smart-reply quick-response chips (#14): 1-tap suggested replies under a
	// received message, generated via the existing assist provider. ---
	describe('smart-reply chips (#14)', () => {
		afterEach(() => {
			jmapSession.set(null);
			vi.mocked(assistComplete).mockReset();
		});

		function enableAssist() {
			jmapSession.set({ effectiveCapabilities: { features: { assist: true } } } as never);
		}

		it('renders 3 chips on reply focus and fills the textarea on click', async () => {
			enableAssist();
			vi.mocked(assistComplete).mockResolvedValue('Sounds good\n- Will do\n3. Thanks!');
			const { container, findAllByRole } = render(ReadingPane, {
				email: makeEmail(), mailboxes: [], currentRole: null, actions: acts(),
			});
			const textarea = container.querySelector('textarea') as HTMLTextAreaElement;
			await fireEvent.focus(textarea);
			const chips = await findAllByRole('button', { name: /Use suggested reply/ });
			expect(chips).toHaveLength(3);
			await fireEvent.click(chips[0]);
			expect(textarea.value).toBe('Sounds good');
		});

		it('renders no chips and does not throw when assist rejects', async () => {
			enableAssist();
			vi.mocked(assistComplete).mockRejectedValue(new Error('boom'));
			const { container, queryAllByRole } = render(ReadingPane, {
				email: makeEmail(), mailboxes: [], currentRole: null, actions: acts(),
			});
			const textarea = container.querySelector('textarea') as HTMLTextAreaElement;
			await fireEvent.focus(textarea);
			await Promise.resolve();
			await Promise.resolve();
			expect(queryAllByRole('button', { name: /Use suggested reply/ })).toHaveLength(0);
		});
	});
});
