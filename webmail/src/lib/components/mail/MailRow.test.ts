import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte/svelte5';
import MailRow from './MailRow.svelte';
import { setOpenSwipeRowId } from './mailRowSwipe.svelte';
import type { Email, Mailbox } from '$lib/types/jmap';

// Minimal Email fixture
function makeEmail(overrides: Partial<Email> = {}): Email {
	return {
		id: 'e1',
		threadId: 't1',
		mailboxIds: { mb1: true },
		from: [{ name: 'Alice Smith', email: 'alice@example.com' }],
		subject: 'Quarterly report',
		preview: 'Please find attached the Q3 results.',
		receivedAt: '2026-06-14T10:00:00Z',
		hasAttachment: false,
		keywords: { $seen: true },
		...overrides,
	};
}

// Minimal Mailbox (tag) fixture
function makeTag(id: string, name: string, color = 'blue'): Mailbox {
	return { id, name, color, role: undefined };
}

describe('MailRow', () => {
	it('renders sender name on line 1', () => {
		const { container } = render(MailRow, {
			email: makeEmail(),
			tags: [],
			selected: false,
			onOpen: vi.fn(),
			onArchive: vi.fn(),
			onStar: vi.fn(),
			onTrash: vi.fn(),
		});
		expect(container.querySelector('.sj-mailrow__sender')?.textContent?.trim()).toBe('Alice Smith');
	});

	it('exposes an aria-label describing the message on the row button', () => {
		const { container } = render(MailRow, {
			email: makeEmail({ subject: 'Quarterly report' }),
			tags: [],
			selected: false,
			onOpen: vi.fn(),
			onArchive: vi.fn(),
			onStar: vi.fn(),
			onTrash: vi.fn(),
		});
		const row = container.querySelector('.sj-mailrow') as HTMLElement;
		expect(row).not.toBeNull();
		const label = row.getAttribute('aria-label');
		expect(label).toBeTruthy();
		expect(label).toContain('Alice Smith');
		expect(label).toContain('Quarterly report');
	});

	it('falls back to email address when no sender name', () => {
		const { container } = render(MailRow, {
			email: makeEmail({ from: [{ email: 'bob@example.com' }] }),
			tags: [],
			selected: false,
			onOpen: vi.fn(),
			onArchive: vi.fn(),
			onStar: vi.fn(),
			onTrash: vi.fn(),
		});
		expect(container.querySelector('.sj-mailrow__sender')?.textContent?.trim()).toBe('bob@example.com');
	});

	it('falls back to Unknown when no from field', () => {
		const { container } = render(MailRow, {
			email: makeEmail({ from: [] }),
			tags: [],
			selected: false,
			onOpen: vi.fn(),
			onArchive: vi.fn(),
			onStar: vi.fn(),
			onTrash: vi.fn(),
		});
		expect(container.querySelector('.sj-mailrow__sender')?.textContent?.trim()).toBe('Unknown');
	});

	it('renders subject on line 2', () => {
		const { container } = render(MailRow, {
			email: makeEmail(),
			tags: [],
			selected: false,
			onOpen: vi.fn(),
			onArchive: vi.fn(),
			onStar: vi.fn(),
			onTrash: vi.fn(),
		});
		expect(container.querySelector('.sj-mailrow__subject')?.textContent?.trim()).toBe('Quarterly report');
	});

	it('renders (no subject) when subject is missing', () => {
		const { container } = render(MailRow, {
			email: makeEmail({ subject: undefined }),
			tags: [],
			selected: false,
			onOpen: vi.fn(),
			onArchive: vi.fn(),
			onStar: vi.fn(),
			onTrash: vi.fn(),
		});
		expect(container.querySelector('.sj-mailrow__subject')?.textContent?.trim()).toBe('(no subject)');
	});

	it('renders preview snippet on line 3', () => {
		const { container } = render(MailRow, {
			email: makeEmail(),
			tags: [],
			selected: false,
			onOpen: vi.fn(),
			onArchive: vi.fn(),
			onStar: vi.fn(),
			onTrash: vi.fn(),
		});
		expect(container.querySelector('.sj-mailrow__snippet')?.textContent?.trim()).toBe(
			'Please find attached the Q3 results.',
		);
	});

	it('shows unread dot when email is unread ($seen falsy)', () => {
		const { container } = render(MailRow, {
			email: makeEmail({ keywords: {} }),
			tags: [],
			selected: false,
			onOpen: vi.fn(),
			onArchive: vi.fn(),
			onStar: vi.fn(),
			onTrash: vi.fn(),
		});
		const dot = container.querySelector('.sj-mailrow__dot');
		expect(dot?.getAttribute('data-unread')).toBe('true');
	});

	it('sets data-unread="false" on dot when email is read ($seen true)', () => {
		const { container } = render(MailRow, {
			email: makeEmail({ keywords: { $seen: true } }),
			tags: [],
			selected: false,
			onOpen: vi.fn(),
			onArchive: vi.fn(),
			onStar: vi.fn(),
			onTrash: vi.fn(),
		});
		const dot = container.querySelector('.sj-mailrow__dot');
		expect(dot?.getAttribute('data-unread')).toBe('false');
	});

	it('sets data-unread on from element when unread', () => {
		const { container } = render(MailRow, {
			email: makeEmail({ keywords: {} }),
			tags: [],
			selected: false,
			onOpen: vi.fn(),
			onArchive: vi.fn(),
			onStar: vi.fn(),
			onTrash: vi.fn(),
		});
		const sender = container.querySelector('.sj-mailrow__sender');
		expect(sender?.getAttribute('data-unread')).toBe('true');
	});

	it('sets data-unread="false" on from element when read', () => {
		const { container } = render(MailRow, {
			email: makeEmail({ keywords: { $seen: true } }),
			tags: [],
			selected: false,
			onOpen: vi.fn(),
			onArchive: vi.fn(),
			onStar: vi.fn(),
			onTrash: vi.fn(),
		});
		const sender = container.querySelector('.sj-mailrow__sender');
		expect(sender?.getAttribute('data-unread')).toBe('false');
	});

	it('renders a Paperclip icon when hasAttachment is true', () => {
		const { container } = render(MailRow, {
			email: makeEmail({ hasAttachment: true }),
			tags: [],
			selected: false,
			onOpen: vi.fn(),
			onArchive: vi.fn(),
			onStar: vi.fn(),
			onTrash: vi.fn(),
		});
		const timeRow = container.querySelector('.sj-mailrow__time-row');
		expect(timeRow?.querySelector('svg')).not.toBeNull();
	});

	it('does not render a Paperclip icon when hasAttachment is false', () => {
		const { container } = render(MailRow, {
			email: makeEmail({ hasAttachment: false }),
			tags: [],
			selected: false,
			onOpen: vi.fn(),
			onArchive: vi.fn(),
			onStar: vi.fn(),
			onTrash: vi.fn(),
		});
		const timeRow = container.querySelector('.sj-mailrow__time-row');
		// There should be no svg in the time-row when no attachment
		expect(timeRow?.querySelector('svg')).toBeNull();
	});

	it('renders at most 2 Tag chips even when 3 tags are passed', () => {
		const { container } = render(MailRow, {
			email: makeEmail(),
			tags: [makeTag('t1', 'Finance'), makeTag('t2', 'Work'), makeTag('t3', 'Personal')],
			selected: false,
			onOpen: vi.fn(),
			onArchive: vi.fn(),
			onStar: vi.fn(),
			onTrash: vi.fn(),
		});
		const chips = container.querySelectorAll('.tag');
		expect(chips.length).toBe(2);
	});

	it('calls onOpen when the row is clicked', async () => {
		const onOpen = vi.fn();
		const { container } = render(MailRow, {
			email: makeEmail(),
			tags: [],
			selected: false,
			onOpen,
			onArchive: vi.fn(),
			onStar: vi.fn(),
			onTrash: vi.fn(),
		});
		await fireEvent.click(container.querySelector('.sj-mailrow')!);
		expect(onOpen).toHaveBeenCalledTimes(1);
	});

	it('calls onArchive when Archive button is clicked and does NOT call onOpen', async () => {
		const onOpen = vi.fn();
		const onArchive = vi.fn();
		const { container } = render(MailRow, {
			email: makeEmail(),
			tags: [],
			selected: false,
			onOpen,
			onArchive,
			onStar: vi.fn(),
			onTrash: vi.fn(),
		});
		const archiveBtn = container.querySelector('[aria-label="Archive"]') as HTMLButtonElement;
		expect(archiveBtn).not.toBeNull();
		await fireEvent.click(archiveBtn);
		expect(onArchive).toHaveBeenCalledTimes(1);
		expect(onOpen).not.toHaveBeenCalled();
	});

	it('calls onStar when Star button is clicked and does NOT call onOpen', async () => {
		const onOpen = vi.fn();
		const onStar = vi.fn();
		const { container } = render(MailRow, {
			email: makeEmail(),
			tags: [],
			selected: false,
			onOpen,
			onArchive: vi.fn(),
			onStar,
			onTrash: vi.fn(),
		});
		const starBtn = container.querySelector('[aria-label="Star"]') as HTMLButtonElement;
		expect(starBtn).not.toBeNull();
		await fireEvent.click(starBtn);
		expect(onStar).toHaveBeenCalledTimes(1);
		expect(onOpen).not.toHaveBeenCalled();
	});

	it('calls onTrash when Trash button is clicked and does NOT call onOpen', async () => {
		const onOpen = vi.fn();
		const onTrash = vi.fn();
		const { container } = render(MailRow, {
			email: makeEmail(),
			tags: [],
			selected: false,
			onOpen,
			onArchive: vi.fn(),
			onStar: vi.fn(),
			onTrash,
		});
		const trashBtn = container.querySelector('[aria-label="Trash"]') as HTMLButtonElement;
		expect(trashBtn).not.toBeNull();
		await fireEvent.click(trashBtn);
		expect(onTrash).toHaveBeenCalledTimes(1);
		expect(onOpen).not.toHaveBeenCalled();
	});

	it('calls onOpen on Enter keydown', async () => {
		const onOpen = vi.fn();
		const { container } = render(MailRow, {
			email: makeEmail(),
			tags: [],
			selected: false,
			onOpen,
			onArchive: vi.fn(),
			onStar: vi.fn(),
			onTrash: vi.fn(),
		});
		await fireEvent.keyDown(container.querySelector('.sj-mailrow')!, { key: 'Enter' });
		expect(onOpen).toHaveBeenCalledTimes(1);
	});
});

describe('MailRow — swipe actions (QoL #2)', () => {
	afterEach(() => {
		setOpenSwipeRowId(null);
	});

	function touchDown(row: Element, clientX: number, pointerId = 1) {
		return fireEvent.pointerDown(row, { pointerId, pointerType: 'touch', clientX, clientY: 0 });
	}
	function touchMove(row: Element, clientX: number, pointerId = 1) {
		return fireEvent.pointerMove(row, { pointerId, pointerType: 'touch', clientX, clientY: 0 });
	}
	function touchUp(row: Element, clientX: number, pointerId = 1) {
		return fireEvent.pointerUp(row, { pointerId, pointerType: 'touch', clientX, clientY: 0 });
	}

	it('reveals the swipe tray past the half-tray-width threshold', async () => {
		const { container } = render(MailRow, {
			email: makeEmail(),
			tags: [],
			selected: false,
			onOpen: vi.fn(),
			onArchive: vi.fn(),
			onStar: vi.fn(),
			onTrash: vi.fn(),
		});
		const row = container.querySelector('.sj-mailrow')!;
		await touchDown(row, 200);
		await touchMove(row, 100); // dx=-100, past half of 168
		await touchUp(row, 100);
		expect(container.querySelector('.sj-mailrow__swipe-tray')).not.toBeNull();
		expect(container.querySelector('[aria-label="Archive"][tabindex="0"]')).not.toBeNull();
	});

	it('snaps back when the drag does not clear the threshold', async () => {
		const { container } = render(MailRow, {
			email: makeEmail(),
			tags: [],
			selected: false,
			onOpen: vi.fn(),
			onArchive: vi.fn(),
			onStar: vi.fn(),
			onTrash: vi.fn(),
		});
		const row = container.querySelector('.sj-mailrow')!;
		await touchDown(row, 200);
		await touchMove(row, 180); // dx=-20, well under half of 168
		await touchUp(row, 180);
		expect(container.querySelector('.sj-mailrow__swipe-tray')).toBeNull();
	});

	it('tap-commits Archive from the revealed tray and closes it', async () => {
		const onArchive = vi.fn();
		const onOpen = vi.fn();
		const { container } = render(MailRow, {
			email: makeEmail(),
			tags: [],
			selected: false,
			onOpen,
			onArchive,
			onStar: vi.fn(),
			onTrash: vi.fn(),
		});
		const row = container.querySelector('.sj-mailrow')!;
		await touchDown(row, 200);
		await touchMove(row, 100);
		await touchUp(row, 100);
		const trayArchive = container.querySelector('.sj-mailrow__swipe-tray [aria-label="Archive"]') as HTMLButtonElement;
		expect(trayArchive).not.toBeNull();
		await fireEvent.click(trayArchive);
		expect(onArchive).toHaveBeenCalledTimes(1);
		expect(onOpen).not.toHaveBeenCalled();
		expect(container.querySelector('.sj-mailrow__swipe-tray')).toBeNull();
	});

	it('tap-commits Trash from the revealed tray', async () => {
		const onTrash = vi.fn();
		const { container } = render(MailRow, {
			email: makeEmail(),
			tags: [],
			selected: false,
			onOpen: vi.fn(),
			onArchive: vi.fn(),
			onStar: vi.fn(),
			onTrash,
		});
		const row = container.querySelector('.sj-mailrow')!;
		await touchDown(row, 200);
		await touchMove(row, 100);
		await touchUp(row, 100);
		const trayTrash = container.querySelector('.sj-mailrow__swipe-tray [aria-label="Trash"]') as HTMLButtonElement;
		await fireEvent.click(trayTrash);
		expect(onTrash).toHaveBeenCalledTimes(1);
	});

	it('mouse pointerdown/move never reveals the tray', async () => {
		const { container } = render(MailRow, {
			email: makeEmail(),
			tags: [],
			selected: false,
			onOpen: vi.fn(),
			onArchive: vi.fn(),
			onStar: vi.fn(),
			onTrash: vi.fn(),
		});
		const row = container.querySelector('.sj-mailrow')!;
		await fireEvent.pointerDown(row, { pointerId: 1, pointerType: 'mouse', clientX: 200, clientY: 0 });
		await fireEvent.pointerMove(row, { pointerId: 1, pointerType: 'mouse', clientX: 50, clientY: 0 });
		await fireEvent.pointerUp(row, { pointerId: 1, pointerType: 'mouse', clientX: 50, clientY: 0 });
		expect(container.querySelector('.sj-mailrow__swipe-tray')).toBeNull();
	});

	it('long-press (600ms hold) opens the tray as a non-gesture equivalent', async () => {
		vi.useFakeTimers();
		try {
			const { container } = render(MailRow, {
				email: makeEmail(),
				tags: [],
				selected: false,
				onOpen: vi.fn(),
				onArchive: vi.fn(),
				onStar: vi.fn(),
				onTrash: vi.fn(),
			});
			const row = container.querySelector('.sj-mailrow')!;
			await fireEvent.pointerDown(row, { pointerId: 1, pointerType: 'touch', clientX: 200, clientY: 0 });
			await vi.advanceTimersByTimeAsync(650);
			expect(container.querySelector('.sj-mailrow__swipe-tray')).not.toBeNull();
		} finally {
			vi.useRealTimers();
		}
	});

	it('does not render an onSnooze tray button when onSnooze is absent', async () => {
		const { container } = render(MailRow, {
			email: makeEmail(),
			tags: [],
			selected: false,
			onOpen: vi.fn(),
			onArchive: vi.fn(),
			onStar: vi.fn(),
			onTrash: vi.fn(),
		});
		const row = container.querySelector('.sj-mailrow')!;
		await touchDown(row, 200);
		await touchMove(row, 100);
		await touchUp(row, 100);
		expect(container.querySelector('.sj-mailrow__swipe-tray [aria-label="Snooze"]')).toBeNull();
	});

	it('calls onSnooze with the picked date and shows an undo-capable toast trash flow via onTrash reuse', async () => {
		const onSnooze = vi.fn();
		const { container } = render(MailRow, {
			email: makeEmail(),
			tags: [],
			selected: false,
			onOpen: vi.fn(),
			onArchive: vi.fn(),
			onStar: vi.fn(),
			onTrash: vi.fn(),
			onSnooze,
		});
		const row = container.querySelector('.sj-mailrow')!;
		await touchDown(row, 200);
		await touchMove(row, 100);
		await touchUp(row, 100);
		const snoozeBtn = container.querySelector('.sj-mailrow__swipe-tray [aria-label="Snooze"]') as HTMLButtonElement;
		expect(snoozeBtn).not.toBeNull();
		await fireEvent.click(snoozeBtn);
		const presetBtn = container.querySelector('.sj-snooze__item') as HTMLButtonElement;
		expect(presetBtn).not.toBeNull();
		await fireEvent.click(presetBtn);
		expect(onSnooze).toHaveBeenCalledTimes(1);
		expect(onSnooze.mock.calls[0][0]).toBeInstanceOf(Date);
		expect(container.querySelector('.sj-mailrow__swipe-tray')).toBeNull();
	});

	it('revealing one row snaps back another previously-open row', async () => {
		const rowA = render(MailRow, {
			email: makeEmail({ id: 'a' }),
			tags: [],
			selected: false,
			onOpen: vi.fn(),
			onArchive: vi.fn(),
			onStar: vi.fn(),
			onTrash: vi.fn(),
		});
		const rowB = render(MailRow, {
			email: makeEmail({ id: 'b' }),
			tags: [],
			selected: false,
			onOpen: vi.fn(),
			onArchive: vi.fn(),
			onStar: vi.fn(),
			onTrash: vi.fn(),
		});
		const elA = rowA.container.querySelector('.sj-mailrow')!;
		const elB = rowB.container.querySelector('.sj-mailrow')!;
		await touchDown(elA, 200);
		await touchMove(elA, 100);
		await touchUp(elA, 100);
		expect(rowA.container.querySelector('.sj-mailrow__swipe-tray')).not.toBeNull();

		await touchDown(elB, 200);
		await touchMove(elB, 100);
		await touchUp(elB, 100);
		expect(rowB.container.querySelector('.sj-mailrow__swipe-tray')).not.toBeNull();
		expect(rowA.container.querySelector('.sj-mailrow__swipe-tray')).toBeNull();
	});
});

describe('MailRow tour anchor', () => {
	it('emits data-tour when tour prop set', () => {
		const { container } = render(MailRow, {
			email: makeEmail(), tags: [], selected: false,
			onOpen: vi.fn(), onArchive: vi.fn(), onStar: vi.fn(), onTrash: vi.fn(),
			tour: 'organize',
		});
		expect(container.querySelector('[data-tour="organize"]')).toBeTruthy();
	});
	it('emits no data-tour when tour prop absent', () => {
		const { container } = render(MailRow, {
			email: makeEmail(), tags: [], selected: false,
			onOpen: vi.fn(), onArchive: vi.fn(), onStar: vi.fn(), onTrash: vi.fn(),
		});
		expect(container.querySelector('[data-tour]')).toBeNull();
	});
});

describe('MailRow S/MIME shield', () => {
	it('renders ShieldCheck when smimeStatus is valid', () => {
		const { container } = render(MailRow, {
			email: makeEmail({ smimeStatus: 'valid' }),
			tags: [],
			selected: false,
			onOpen: vi.fn(),
			onArchive: vi.fn(),
			onStar: vi.fn(),
			onTrash: vi.fn(),
		});
		expect(container.querySelector('.sj-mailrow__verified')).not.toBeNull();
	});

	it('no shield when smimeStatus is untrusted', () => {
		const { container } = render(MailRow, {
			email: makeEmail({ smimeStatus: 'untrusted' }),
			tags: [],
			selected: false,
			onOpen: vi.fn(),
			onArchive: vi.fn(),
			onStar: vi.fn(),
			onTrash: vi.fn(),
		});
		expect(container.querySelector('.sj-mailrow__verified')).toBeNull();
	});

	it('no shield when smimeStatus is invalid', () => {
		const { container } = render(MailRow, {
			email: makeEmail({ smimeStatus: 'invalid' }),
			tags: [],
			selected: false,
			onOpen: vi.fn(),
			onArchive: vi.fn(),
			onStar: vi.fn(),
			onTrash: vi.fn(),
		});
		expect(container.querySelector('.sj-mailrow__verified')).toBeNull();
	});

	it('no shield when smimeStatus is absent', () => {
		const { container } = render(MailRow, {
			email: makeEmail(),
			tags: [],
			selected: false,
			onOpen: vi.fn(),
			onArchive: vi.fn(),
			onStar: vi.fn(),
			onTrash: vi.fn(),
		});
		expect(container.querySelector('.sj-mailrow__verified')).toBeNull();
	});

	it('shield appears before the paperclip in the DOM when both present', () => {
		const { container } = render(MailRow, {
			email: makeEmail({ smimeStatus: 'valid', hasAttachment: true }),
			tags: [],
			selected: false,
			onOpen: vi.fn(),
			onArchive: vi.fn(),
			onStar: vi.fn(),
			onTrash: vi.fn(),
		});
		const timeRow = container.querySelector('.sj-mailrow__time-row')!;
		const children = Array.from(timeRow.children);
		const shieldIdx = children.findIndex((el) => el.classList.contains('sj-mailrow__verified'));
		const paperclipIdx = children.findIndex((el) => el.classList.contains('sj-mailrow__paperclip'));
		expect(shieldIdx).toBeGreaterThanOrEqual(0);
		expect(paperclipIdx).toBeGreaterThan(shieldIdx);
	});
});

describe('MailRow — mark read/unread (A2)', () => {
	it('does not render the toggle when onToggleRead is absent', () => {
		const { container } = render(MailRow, {
			email: makeEmail(), tags: [], selected: false,
			onOpen: vi.fn(), onArchive: vi.fn(), onStar: vi.fn(), onTrash: vi.fn(),
		});
		expect(container.querySelector('[aria-label="Mark read"]')).toBeNull();
		expect(container.querySelector('[aria-label="Mark unread"]')).toBeNull();
	});

	it('shows Mark read for an unread row and forwards read=true', async () => {
		const onToggleRead = vi.fn();
		const { container } = render(MailRow, {
			email: makeEmail({ keywords: {} }), tags: [], selected: false,
			onOpen: vi.fn(), onArchive: vi.fn(), onStar: vi.fn(), onTrash: vi.fn(), onToggleRead,
		});
		const btn = container.querySelector('[aria-label="Mark read"]') as HTMLButtonElement;
		expect(btn).not.toBeNull();
		await fireEvent.click(btn);
		expect(onToggleRead).toHaveBeenCalledWith(true);
	});

	it('shows Mark unread for a read row and forwards read=false', async () => {
		const onToggleRead = vi.fn();
		const { container } = render(MailRow, {
			email: makeEmail({ keywords: { $seen: true } }), tags: [], selected: false,
			onOpen: vi.fn(), onArchive: vi.fn(), onStar: vi.fn(), onTrash: vi.fn(), onToggleRead,
		});
		const btn = container.querySelector('[aria-label="Mark unread"]') as HTMLButtonElement;
		expect(btn).not.toBeNull();
		await fireEvent.click(btn);
		expect(onToggleRead).toHaveBeenCalledWith(false);
	});
});

describe('MailRow encrypted read state (D-F1)', () => {
	const handlers = {
		onOpen: vi.fn(), onArchive: vi.fn(), onStar: vi.fn(), onTrash: vi.fn(),
	};

	it('renders the Lock placeholder (never a blank snippet) for an encrypted message', () => {
		const { container } = render(MailRow, {
			email: makeEmail({ cryptoType: 'smime-encrypted', preview: undefined }),
			tags: [], selected: false, ...handlers,
		});
		const enc = container.querySelector('.sj-mailrow__encrypted');
		expect(enc).not.toBeNull();
		expect(container.querySelector('.sj-mailrow__lock')).not.toBeNull();
		expect(container.textContent).toContain('Encrypted message');
		// The plaintext-preview snippet must NOT leak (none exists, but assert empty).
		const snippet = container.querySelector('.sj-mailrow__snippet')?.textContent ?? '';
		expect(snippet.trim()).toBe('');
	});

	it('does NOT render a ShieldCheck verified shield merely for encryption', () => {
		const { container } = render(MailRow, {
			email: makeEmail({ cryptoType: 'smime-encrypted', smimeStatus: undefined }),
			tags: [], selected: false, ...handlers,
		});
		expect(container.querySelector('.sj-mailrow__verified')).toBeNull();
	});

	it('a normal (non-encrypted) message still renders its preview snippet', () => {
		const { container } = render(MailRow, {
			email: makeEmail({ preview: 'plain preview text' }),
			tags: [], selected: false, ...handlers,
		});
		expect(container.querySelector('.sj-mailrow__encrypted')).toBeNull();
		expect(container.querySelector('.sj-mailrow__snippet')?.textContent).toContain('plain preview text');
	});
});

describe('MailRow — search snippets (SearchSnippet/get)', () => {
	const handlers = {
		onOpen: vi.fn(), onArchive: vi.fn(), onStar: vi.fn(), onTrash: vi.fn(),
	};

	it('renders the highlighted subject snippet (with a real <mark>) over the plain subject', () => {
		const { container } = render(MailRow, {
			email: makeEmail({ subject: 'Quarterly report', searchSubject: 'Quarterly <mark>report</mark>' }),
			tags: [], selected: false, ...handlers,
		});
		const subj = container.querySelector('.sj-mailrow__subject')!;
		expect(subj.querySelector('mark')?.textContent).toBe('report');
		expect(subj.textContent).toContain('Quarterly report');
	});

	it('renders the highlighted preview snippet with a real <mark>', () => {
		const { container } = render(MailRow, {
			email: makeEmail({ searchPreview: 'the <mark>results</mark> are in' }),
			tags: [], selected: false, ...handlers,
		});
		const snippet = container.querySelector('.sj-mailrow__snippet')!;
		expect(snippet.querySelector('mark')?.textContent).toBe('results');
	});

	it('does NOT inject a <script> smuggled in a snippet (XSS)', () => {
		const { container } = render(MailRow, {
			email: makeEmail({ searchPreview: '<mark>hi</mark><script>alert(1)</script>' }),
			tags: [], selected: false, ...handlers,
		});
		const snippet = container.querySelector('.sj-mailrow__snippet')!;
		// the <mark> survives; the <script> is inert escaped text, no element created
		expect(snippet.querySelector('mark')?.textContent).toBe('hi');
		expect(snippet.querySelector('script')).toBeNull();
		expect(snippet.textContent).toContain('<script>alert(1)</script>');
	});

	it('falls back to the plain preview when no search snippet is present', () => {
		const { container } = render(MailRow, {
			email: makeEmail({ preview: 'plain preview text' }),
			tags: [], selected: false, ...handlers,
		});
		expect(container.querySelector('.sj-mailrow__snippet')?.querySelector('mark')).toBeNull();
		expect(container.querySelector('.sj-mailrow__snippet')?.textContent).toContain('plain preview text');
	});

	it('encrypted messages keep the Lock placeholder even if a preview snippet is set', () => {
		const { container } = render(MailRow, {
			email: makeEmail({ cryptoType: 'smime-encrypted', searchPreview: '<mark>leak</mark>' }),
			tags: [], selected: false, ...handlers,
		});
		expect(container.querySelector('.sj-mailrow__encrypted')).not.toBeNull();
		expect(container.querySelector('.sj-mailrow__snippet')).toBeNull();
	});
});

describe('MailRow — shared work status', () => {
	it('renders the reducer-authored work state with text and a status dot', () => {
		const { container } = render(MailRow, {
			email: makeEmail(), tags: [], selected: false, workStatus: 'waiting',
			onOpen: vi.fn(), onArchive: vi.fn(), onStar: vi.fn(), onTrash: vi.fn(),
		});
		const badge = container.querySelector('.sj-mailrow__work');
		expect(badge?.textContent).toContain('Waiting');
		expect(badge?.getAttribute('data-status')).toBe('waiting');
		expect(badge?.getAttribute('aria-label')).toBe('Status: Waiting');
	});
});
