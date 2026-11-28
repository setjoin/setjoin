import Mention from '@tiptap/extension-mention';
import type { SuggestionProps } from '@tiptap/suggestion';
import { galSearch } from '$lib/jmap/client';
import type { ContactCard } from '$lib/types/jmap';

/**
 * @-mention support for the compose body. Built on the official
 * `@tiptap/extension-mention` node (an inline atom carrying `{id, label}`) +
 * `@tiptap/suggestion` (the `@`-trigger / caret `clientRect` / range-replace
 * utility) — cheaper and more robust than hand-rolling caret parsing.
 *
 * The chip render is cloned from `templateVariableExtension.ts`: a self-contained
 * `<span class="mention">@Label</span>`, with `renderText` giving the same
 * `@Label` so the plain-text email fallback and the on-screen chip agree.
 *
 * The host (RichTextEditor) supplies a `MentionController` that (a) drives the
 * Svelte popup from the suggestion lifecycle and (b) receives the pick so the
 * picked person is added to the recipients.
 */

/** One @-mention candidate — a GAL/contact person. */
export interface MentionItem {
	id: string;
	label: string;
	email: string;
}

/** Map a GAL `ContactCard` to a mention item (mirrors composeStore.pickContact). */
export function toMentionItem(c: ContactCard): MentionItem {
	const email = c.email || c.emails?.[0]?.address || '';
	const label =
		c.displayName || `${c.firstName ?? ''} ${c.lastName ?? ''}`.trim() || email;
	return { id: c.id ?? email, label, email };
}

/** The chip's visible text: `@Label` (used by both renderHTML and renderText). */
export function mentionText(attrs: { label?: string | null; id?: string | null }): string {
	return `@${attrs.label ?? attrs.id ?? ''}`;
}

/**
 * The seam the host implements to render the popup + receive the pick. The
 * suggestion lifecycle (imperative, TipTap-side) calls onStart/onUpdate/onExit/
 * onKeyDown; onPick fires when a candidate is committed (chip already inserted).
 */
export interface MentionController {
	onStart(props: SuggestionProps<MentionItem>): void;
	onUpdate(props: SuggestionProps<MentionItem>): void;
	onKeyDown(event: KeyboardEvent): boolean;
	onExit(): void;
	onPick(item: MentionItem): void;
}

/** Build the configured Mention extension wired to `controller`. */
export function createMentionExtension(controller: MentionController) {
	return Mention.configure({
		HTMLAttributes: { class: 'mention' },
		renderText: ({ node }) => mentionText(node.attrs),
		renderHTML: ({ node }) => [
			'span',
			{ class: 'mention', 'data-type': 'mention', 'data-id': node.attrs.id, contenteditable: 'false' },
			mentionText(node.attrs),
		],
		suggestion: {
			char: '@',
			items: async ({ query }) => {
				try {
					return (await galSearch(query, 8)).map(toMentionItem);
				} catch {
					return [];
				}
			},
			// Commit: insert the chip (id/label) + trailing space, then fire onPick so
			// the picked person is added to the recipients.
			command: ({ editor, range, props }) => {
				const item = props as MentionItem;
				editor
					.chain()
					.focus()
					.insertContentAt(range, [
						{ type: 'mention', attrs: { id: item.id, label: item.label } },
						{ type: 'text', text: ' ' },
					])
					.run();
				controller.onPick(item);
			},
			render: () => ({
				onStart: (p) => controller.onStart(p),
				onUpdate: (p) => controller.onUpdate(p),
				onKeyDown: (p) => controller.onKeyDown(p.event),
				onExit: () => controller.onExit(),
			}),
		},
	});
}
