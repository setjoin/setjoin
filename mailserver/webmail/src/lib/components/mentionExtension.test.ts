import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { ContactCard } from '$lib/types/jmap';

const mocks = vi.hoisted(() => ({ galSearch: vi.fn() }));
vi.mock('$lib/jmap/client', () => ({ galSearch: mocks.galSearch }));

import { createMentionExtension, mentionText, toMentionItem, type MentionController } from './mentionExtension';

beforeEach(() => {
	mocks.galSearch.mockReset();
});

describe('mentionText', () => {
	it('renders @Label, falling back to id then empty', () => {
		expect(mentionText({ label: 'Alice' })).toBe('@Alice');
		expect(mentionText({ label: null, id: 'x' })).toBe('@x');
		expect(mentionText({})).toBe('@');
	});
});

describe('toMentionItem', () => {
	it('maps a GAL card to {id,label,email} (email fallback + emails[])', () => {
		expect(toMentionItem({ id: 'g1', displayName: 'GAL Bob', email: 'bob@x.test' } as ContactCard)).toEqual({
			id: 'g1',
			label: 'GAL Bob',
			email: 'bob@x.test',
		});
		expect(
			toMentionItem({ id: 'c2', firstName: 'Ann', lastName: 'Lee', emails: [{ type: 'work', address: 'ann@x.test' }] } as ContactCard)
		).toEqual({ id: 'c2', label: 'Ann Lee', email: 'ann@x.test' });
	});
});

/** Minimal spy controller. */
function controller(): MentionController & { picked: unknown[] } {
	const picked: unknown[] = [];
	return {
		picked,
		onStart: vi.fn(),
		onUpdate: vi.fn(),
		onKeyDown: vi.fn(() => false),
		onExit: vi.fn(),
		onPick: (item) => picked.push(item),
	};
}

describe('createMentionExtension', () => {
	it('configures the @ suggestion whose items() maps galSearch(query, 8)', async () => {
		mocks.galSearch.mockResolvedValue([{ id: 'g1', displayName: 'GAL Bob', email: 'bob@x.test' }]);
		const ext = createMentionExtension(controller());
		const s = ext.options.suggestion;
		expect(s.char).toBe('@');
		const items = await s.items!({ query: 'bob' } as never);
		expect(mocks.galSearch).toHaveBeenCalledWith('bob', 8);
		expect(items).toEqual([{ id: 'g1', label: 'GAL Bob', email: 'bob@x.test' }]);
	});

	it('items() returns [] when galSearch rejects (popup shows the empty row)', async () => {
		mocks.galSearch.mockRejectedValue(new Error('offline'));
		const ext = createMentionExtension(controller());
		expect(await ext.options.suggestion.items!({ query: 'x' } as never)).toEqual([]);
	});

	it('command inserts the mention chip AND fires onPick with the person', () => {
		const ctrl = controller();
		const ext = createMentionExtension(ctrl);
		// Fake editor chain — assert the chip node + trailing space are inserted at the range.
		const insertContentAt = vi.fn(() => chain);
		const run = vi.fn();
		const chain: Record<string, unknown> = {
			focus: () => chain,
			insertContentAt,
			run,
		};
		const editor = { chain: () => chain } as never;
		const item = { id: 'g1', label: 'Alice', email: 'alice@x.test' };

		ext.options.suggestion.command!({ editor, range: { from: 3, to: 4 }, props: item } as never);

		expect(insertContentAt).toHaveBeenCalledWith({ from: 3, to: 4 }, [
			{ type: 'mention', attrs: { id: 'g1', label: 'Alice' } },
			{ type: 'text', text: ' ' },
		]);
		expect(run).toHaveBeenCalled();
		expect(ctrl.picked).toEqual([item]);
	});

	it('renderText / renderHTML both produce @Label', () => {
		const ext = createMentionExtension(controller());
		const node = { attrs: { id: 'g1', label: 'Alice' } };
		expect(ext.options.renderText({ node } as never)).toBe('@Alice');
		const html = ext.options.renderHTML({ node } as never) as [string, Record<string, unknown>, string];
		expect(html[0]).toBe('span');
		expect(html[1].class).toBe('mention');
		expect(html[2]).toBe('@Alice');
	});
});
