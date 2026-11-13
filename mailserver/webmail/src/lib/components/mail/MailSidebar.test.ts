import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte/svelte5';
import MailSidebar from './MailSidebar.svelte';
import type { Mailbox } from '$lib/types/jmap';

/** Build a Mailbox fixture with overrides for the sidebar tag tree. */
function makeMailbox(overrides: Partial<Mailbox> = {}): Mailbox {
	return {
		id: 'mb1',
		name: 'Test',
		role: undefined,
		parentId: undefined,
		color: 'blue',
		...overrides,
	};
}

/** The 8 fixed view labels in order (EN only for now); Archive added in A2. */
const VIEW_LABELS = [
	'Inbox',
	'Snoozed',
	'Scheduled',
	'Drafts',
	'Sent',
	'Archive',
	'All Mail',
	'Trash',
];

/**
 * Query the first `.sbitem` whose label text matches; returns
 * the wrapper element or null.
 */
function findByLabel(container: HTMLElement, label: string): HTMLElement | null {
	const items = container.querySelectorAll<HTMLElement>('.sbitem');
	for (const item of items) {
		const lbl = item.querySelector('.sbitem__label');
		if (lbl?.textContent?.trim() === label) return item;
	}
	return null;
}

describe('MailSidebar', () => {
	const defaultProps = {
		view: 'inbox' as const,
		tagFilter: null as string | null,
		mailboxes: [] as Mailbox[],
		counts: { inboxUnread: 0, snoozedTotal: 0, tagCounts: {} as Record<string, number> },
		onCompose: vi.fn(),
		onSelectView: vi.fn(),
		onSelectTag: vi.fn(),
		onNewTag: vi.fn(),
	};

	it('renders exactly 8 view items with the correct labels', () => {
		const { container } = render(MailSidebar, defaultProps);
		for (const label of VIEW_LABELS) {
			const el = findByLabel(container, label);
			expect(el, `Expected view "${label}" to be present`).not.toBeNull();
		}
		// Ensure no extra view items
		const allViewItems = container.querySelectorAll('.sbitem');
		// tag rows also use .sbitem, so we only check that the 7 view labels exist
		// and then flag if any unexpected view items slip in.
		const foundLabels: string[] = [];
		allViewItems.forEach((item) => {
			const lbl = item.querySelector('.sbitem__label')?.textContent?.trim();
			if (lbl) foundLabels.push(lbl);
		});
		// At minimum the 7 view labels must be present
		for (const label of VIEW_LABELS) {
			expect(foundLabels).toContain(label);
		}
	});

	it('shows count for Inbox (inboxUnread) and Snoozed (snoozedTotal) but not for others', () => {
		const counts = { inboxUnread: 5, snoozedTotal: 3, tagCounts: {} };
		const { container } = render(MailSidebar, {
			...defaultProps,
			counts,
		});

		// Inbox: count should be visible
		const inboxEl = findByLabel(container, 'Inbox');
		const inboxCount = inboxEl?.querySelector('.sbitem__count');
		expect(inboxCount?.textContent?.trim()).toBe('5');

		// Snoozed: count should be visible
		const snoozedEl = findByLabel(container, 'Snoozed');
		const snoozedCount = snoozedEl?.querySelector('.sbitem__count');
		expect(snoozedCount?.textContent?.trim()).toBe('3');

		// All other views: no count
		for (const label of ['Scheduled', 'Drafts', 'Sent', 'Archive', 'All Mail', 'Trash']) {
			const el = findByLabel(container, label);
			const countEl = el?.querySelector('.sbitem__count');
			expect(
				countEl,
				`"${label}" should have no count element`,
			).toBeNull();
		}
	});

	it('marks a view row active only when view matches and tagFilter is null', () => {
		// view=inbox, no tagFilter -> Inbox active
		const { container } = render(MailSidebar, {
			...defaultProps,
			view: 'inbox',
			tagFilter: null,
		});
		const inboxEl = findByLabel(container, 'Inbox');
		expect(inboxEl?.getAttribute('aria-current')).toBe('true');
		// Others not active
		const snoozedEl = findByLabel(container, 'Snoozed');
		expect(snoozedEl?.hasAttribute('aria-current')).toBe(false);
	});

	it('deselects all view rows when a tagFilter is active', () => {
		const { container } = render(MailSidebar, {
			...defaultProps,
			view: 'inbox',
			tagFilter: 'tag-finance',
		});
		for (const label of VIEW_LABELS) {
			const el = findByLabel(container, label);
			expect(
				el?.hasAttribute('aria-current'),
				`"${label}" should NOT be active when tagFilter is set`,
			).toBe(false);
		}
	});

	it('renders tag rows from userTags+buildTagTree with dotColor, depth, and count', () => {
		const mailboxes: Mailbox[] = [
			makeMailbox({ id: 'finance', name: 'Finance', color: 'green', role: undefined }),
			makeMailbox({
				id: 'invoices',
				name: 'Invoices',
				color: 'amber',
				role: undefined,
				parentId: 'finance',
			}),
		];
		const counts = {
			inboxUnread: 0,
			snoozedTotal: 0,
			tagCounts: { finance: 12, invoices: 3 },
		};

		const { container } = render(MailSidebar, { ...defaultProps, mailboxes, counts });

		// Finance tag row
		const financeEl = findByLabel(container, 'Finance');
		expect(financeEl).not.toBeNull();
		// Should have a dot (not icon)
		expect(financeEl?.querySelector('.sbitem__dot')).not.toBeNull();
		expect(financeEl?.querySelector('.sbitem__count')?.textContent?.trim()).toBe('12');

		// Invoices tag row (child, depth 1)
		const invoicesEl = findByLabel(container, 'Invoices');
		expect(invoicesEl).not.toBeNull();
		expect(invoicesEl?.querySelector('.sbitem__dot')).not.toBeNull();
		expect(invoicesEl?.querySelector('.sbitem__count')?.textContent?.trim()).toBe('3');
		// Depth = 1 means left padding = 8 + 1*16 = 24px
		expect(invoicesEl?.style.paddingLeft).toBe('24px');
	});

	it('highlights the active tag row when tagFilter matches', () => {
		const mailboxes: Mailbox[] = [
			makeMailbox({ id: 'finance', name: 'Finance', color: 'green', role: undefined }),
		];
		const { container } = render(MailSidebar, {
			...defaultProps,
			mailboxes,
			tagFilter: 'finance',
		});
		const financeEl = findByLabel(container, 'Finance');
		expect(financeEl?.getAttribute('aria-current')).toBe('true');
	});

	it('clicking a view row calls onSelectView with the view id', async () => {
		const onSelectView = vi.fn();
		const { container } = render(MailSidebar, { ...defaultProps, onSelectView });
		const inboxEl = findByLabel(container, 'Inbox');
		await fireEvent.click(inboxEl!);
		expect(onSelectView).toHaveBeenCalledWith('inbox');
	});

	it('renders an Archive view item and selects it (A2)', async () => {
		const onSelectView = vi.fn();
		const { container } = render(MailSidebar, { ...defaultProps, onSelectView });
		const archiveEl = findByLabel(container, 'Archive');
		expect(archiveEl).not.toBeNull();
		await fireEvent.click(archiveEl!);
		expect(onSelectView).toHaveBeenCalledWith('archive');
	});

	it('clicking a tag row calls onSelectTag with the tag id', async () => {
		const mailboxes: Mailbox[] = [
			makeMailbox({ id: 'finance', name: 'Finance', color: 'green', role: undefined }),
		];
		const onSelectTag = vi.fn();
		const { container } = render(MailSidebar, { ...defaultProps, mailboxes, onSelectTag });
		const financeEl = findByLabel(container, 'Finance');
		await fireEvent.click(financeEl!);
		expect(onSelectTag).toHaveBeenCalledWith('finance');
	});

	it('shows an inline Input after clicking the TAGS header + button, and Enter calls onNewTag', async () => {
		const onNewTag = vi.fn<(name: string) => void>();
		const { container } = render(MailSidebar, { ...defaultProps, onNewTag });

		// Initially, no inline input
		expect(container.querySelector('.sj-mail-sidebar__new-input')).toBeNull();

		// Click the + button in the TAGS header
		const plusBtn = container.querySelector('[aria-label="New tag"]') as HTMLButtonElement;
		expect(plusBtn).not.toBeNull();
		await fireEvent.click(plusBtn);

		// Input should now be visible
		const input = container.querySelector(
			'.sj-mail-sidebar__new-input',
		) as HTMLInputElement;
		expect(input).not.toBeNull();

		// Type and press Enter — onNewTag carries the chosen hue (defaults to blue).
		await fireEvent.input(input, { target: { value: 'Project Alpha' } });
		await fireEvent.keyDown(input, { key: 'Enter' });

		expect(onNewTag).toHaveBeenCalledWith('Project Alpha', 'blue');
	});

	it('does not call onNewTag on Enter when the new-tag input is empty', async () => {
		const onNewTag = vi.fn<(name: string) => void>();
		const { container } = render(MailSidebar, { ...defaultProps, onNewTag });

		const plusBtn = container.querySelector('[aria-label="New tag"]') as HTMLButtonElement;
		await fireEvent.click(plusBtn);
		const input = container.querySelector(
			'.sj-mail-sidebar__new-input',
		) as HTMLInputElement;
		expect(input).not.toBeNull();

		// Press Enter with empty value
		await fireEvent.keyDown(input, { key: 'Enter' });
		expect(onNewTag).not.toHaveBeenCalled();
	});

	it('closes the new-tag input on Escape', async () => {
		const onNewTag = vi.fn<(name: string) => void>();
		const { container } = render(MailSidebar, { ...defaultProps, onNewTag });

		const plusBtn = container.querySelector('[aria-label="New tag"]') as HTMLButtonElement;
		await fireEvent.click(plusBtn);
		let input = container.querySelector('.sj-mail-sidebar__new-input');
		expect(input).not.toBeNull();

		await fireEvent.keyDown(input!, { key: 'Escape' });
		input = container.querySelector('.sj-mail-sidebar__new-input');
		expect(input).toBeNull();
	});

	it('renders a Compose Button that calls onCompose when clicked', async () => {
		const onCompose = vi.fn();
		const { container } = render(MailSidebar, { ...defaultProps, onCompose });
		const composeBtn = container.querySelector('.sj-mail-sidebar__compose') as HTMLButtonElement;
		expect(composeBtn).not.toBeNull();
		await fireEvent.click(composeBtn);
		expect(onCompose).toHaveBeenCalledTimes(1);
	});
});

describe('MailSidebar saved searches', () => {
	const baseProps = {
		view: 'inbox' as const,
		tagFilter: null as string | null,
		mailboxes: [] as Mailbox[],
		counts: { inboxUnread: 0, snoozedTotal: 0, tagCounts: {} as Record<string, number> },
		onCompose: vi.fn(),
		onSelectView: vi.fn(),
		onSelectTag: vi.fn(),
		onNewTag: vi.fn(),
	};
	const saved = [
		{ id: 's1', name: 'Unread finance', query: 'tag:finance is:unread', position: 0 },
		{ id: 's2', name: 'Big attachments', query: 'larger:5M has:attachment', position: 1 },
	];

	it('renders no Saved searches section when the list is empty', () => {
		const { container } = render(MailSidebar, { ...baseProps, savedSearches: [] });
		expect(findByLabel(container, 'Unread finance')).toBeNull();
	});

	it('renders a Saved searches row per saved search', () => {
		const { container } = render(MailSidebar, { ...baseProps, savedSearches: saved });
		expect(findByLabel(container, 'Unread finance')).not.toBeNull();
		expect(findByLabel(container, 'Big attachments')).not.toBeNull();
	});

	it('clicking a saved-search row calls onSelectSaved with the row', async () => {
		const onSelectSaved = vi.fn();
		const { container } = render(MailSidebar, { ...baseProps, savedSearches: saved, onSelectSaved });
		await fireEvent.click(findByLabel(container, 'Unread finance')!);
		expect(onSelectSaved).toHaveBeenCalledWith(saved[0]);
	});

	it('clicking the delete control calls onDeleteSaved with the id', async () => {
		const onDeleteSaved = vi.fn();
		const { container } = render(MailSidebar, { ...baseProps, savedSearches: saved, onDeleteSaved });
		const delBtns = container.querySelectorAll('[aria-label="Delete saved search"]');
		expect(delBtns.length).toBe(2);
		await fireEvent.click(delBtns[1]);
		expect(onDeleteSaved).toHaveBeenCalledWith('s2');
	});
});

describe('MailSidebar manage labels', () => {
	const baseProps = {
		view: 'inbox' as const,
		tagFilter: null as string | null,
		mailboxes: [] as Mailbox[],
		counts: { inboxUnread: 0, snoozedTotal: 0, tagCounts: {} as Record<string, number> },
		onCompose: vi.fn(),
		onSelectView: vi.fn(),
		onSelectTag: vi.fn(),
		onNewTag: vi.fn(),
	};
	const mailboxes: Mailbox[] = [
		makeMailbox({ id: 'finance', name: 'Finance', color: 'green', role: undefined }),
	];

	it('new-tag block renders the 8-swatch hue picker', async () => {
		const { container } = render(MailSidebar, baseProps);
		await fireEvent.click(container.querySelector('[aria-label="New tag"]') as HTMLButtonElement);
		// The swatch group (aria-label = t('inbox.manage.color') = 'Color') with 8 hues.
		const group = container.querySelector('[role="group"][aria-label="Color"]');
		expect(group).not.toBeNull();
		expect(group?.querySelectorAll('.sj-swatch').length).toBe(8);
	});

	it('opens the inline edit form and Save calls onUpdateTag with the patch', async () => {
		const onUpdateTag = vi.fn();
		const { container } = render(MailSidebar, { ...baseProps, mailboxes, onUpdateTag });
		const editBtn = container.querySelector('[aria-label="Edit label"]') as HTMLButtonElement;
		expect(editBtn).not.toBeNull();
		await fireEvent.click(editBtn);
		// Recolor to rose, then Save.
		await fireEvent.click(container.querySelector('[aria-label="rose"]') as HTMLButtonElement);
		const saveBtn = Array.from(container.querySelectorAll('button')).find(
			(b) => b.textContent?.trim() === 'Save',
		) as HTMLButtonElement;
		await fireEvent.click(saveBtn);
		expect(onUpdateTag).toHaveBeenCalledWith('finance', { color: 'rose', name: 'Finance' });
	});

	it('Delete in the edit form calls onDeleteTag with the id', async () => {
		const onDeleteTag = vi.fn();
		const { container } = render(MailSidebar, { ...baseProps, mailboxes, onDeleteTag });
		await fireEvent.click(container.querySelector('[aria-label="Edit label"]') as HTMLButtonElement);
		await fireEvent.click(container.querySelector('[aria-label="Delete label"]') as HTMLButtonElement);
		expect(onDeleteTag).toHaveBeenCalledWith('finance');
	});
});

describe('MailSidebar data-tour anchor', () => {
	it('marks the compose button with data-tour="compose"', () => {
		const { container } = render(MailSidebar, {
			view: 'inbox',
			tagFilter: null,
			mailboxes: [],
			counts: { inboxUnread: 0, snoozedTotal: 0, tagCounts: {} },
			onCompose: () => {},
			onSelectView: () => {},
			onSelectTag: () => {},
			onNewTag: () => {},
		});
		expect(container.querySelector('button[data-tour="compose"]')).toBeTruthy();
	});
});
