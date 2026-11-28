<svelte:options runes={true} />

<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { Editor } from '@tiptap/core';
	import StarterKit from '@tiptap/starter-kit';
	import Placeholder from '@tiptap/extension-placeholder';
	// TableKit (3.26 line) bundles Table + TableRow + TableHeader + TableCell. `resizable`
	// lives under `table:` (not top-level). Table tags/attrs are already sanitizer-allowlisted.
	import { TableKit } from '@tiptap/extension-table';
	// @tiptap/extension-text-style (3.26 line) bundles the TextStyle mark plus the
	// Color / FontFamily / FontSize companion extensions that all write onto it.
	import { TextStyle, Color, FontFamily, FontSize } from '@tiptap/extension-text-style';
	import { TemplateVariable } from './templateVariableExtension';
	import { InlineImage } from './inlineImageExtension';
	import { createMentionExtension, type MentionItem, type MentionController } from './mentionExtension';
	import { INLINE_IMAGE_TYPES } from '$lib/stores/composeStore.svelte';
	import { t } from '$lib/i18n';
	import Spinner from './ui/Spinner.svelte';

	interface Props {
		// INTENTIONALLY read ONCE, at mount (see onMount → new Editor({ content })).
		// This is NOT a live two-way binding, by design (arch A3): TipTap/ProseMirror
		// own the document state after init, so a reactive `$effect` that pushed the
		// prop back into the editor on every change would fight the editor's own
		// `onUpdate` and create an update→prop→setContent→update echo-loop (and, with
		// the caller mirroring content into a `$state`, drop keystrokes). Callers that
		// need to REPLACE the body after mount (load draft / reply-quote / signature /
		// assist) do so IMPERATIVELY via the exported setContent() below — the single,
		// deliberate write path. Do not "upgrade" this to a reactive content binding.
		content?: string;
		placeholder?: string;
		editable?: boolean;
		onUpdate?: (html: string, text: string) => void;
		onFocus?: () => void;
		onBlur?: () => void;
		onEditorReady?: (editor: Editor) => void;
		// When provided, `@` in the body opens a GAL autocomplete; picking a person
		// inserts a mention chip AND calls this with the person (label, email) so the
		// caller can add them to the recipients. Read once at mount (arch A3).
		onMentionPick?: (label: string, email: string) => void;
		// WAVE-5 #2 — inline body images. The editor never imports composeStore (it
		// stays store-agnostic); the caller (ComposeScreen) bridges these to
		// compose.stageInlineImage/pruneOrphanedInlineImages, same shape as the
		// body-read editor-handle seam documented on the store.
		//
		// onInlineImageFile: called for each whitelisted-type image file from a
		// paste/drop — returns the staged {previewUrl, uploadId} synchronously (the
		// caller kicks off the upload in the background) so the placeholder <img>
		// can be inserted immediately, or null if the shared budget is exceeded (the
		// file is then forwarded to onNonInlineFiles instead of being dropped).
		onInlineImageFile?: (file: File) => { previewUrl: string; uploadId: string } | null;
		// Any pasted/dropped file this component does NOT inline (a non-whitelisted
		// type, or one onInlineImageFile rejected) — forwarded here rather than
		// silently dropped, so it rides the ordinary file-attachment path.
		onNonInlineFiles?: (files: File[]) => void;
		// The live status/progress of each staged inline image — drives the
		// upload-progress overlay tracked over the corresponding <img data-upload-id>.
		// Purely presentational input; the editor's own document never changes once
		// a node is inserted (see inlineImageExtension.ts for why).
		inlineUploads?: Array<{ uploadId: string; status?: string; progress?: number }>;
	}

	let {
		content = '',
		placeholder = t('compose.body_placeholder'),
		editable = true,
		onUpdate,
		onFocus,
		onBlur,
		onEditorReady,
		onMentionPick,
		onInlineImageFile,
		onNonInlineFiles,
		inlineUploads = [],
	}: Props = $props();

	let editorEl = $state<HTMLDivElement>();
	let editor = $state<Editor | null>(null);

	// ── @-mention popup (driven by the suggestion lifecycle; see mentionExtension.ts).
	// Rendered as a caret-anchored `position: fixed` dropdown so the editor box's
	// `overflow-y: auto` never clips it. Reuses the `.gal-dropdown` visual language.
	let mentionOpen = $state(false);
	let mentionItems = $state<MentionItem[]>([]);
	let mentionActive = $state(0);
	let mentionRect = $state<DOMRect | null>(null);
	// props.command for the live suggestion session — non-reactive holder.
	let mentionCommand: ((item: MentionItem) => void) | null = null;

	function selectMention(i: number) {
		const item = mentionItems[i];
		if (item && mentionCommand) mentionCommand(item); // inserts the chip + fires onPick
	}

	const mentionController: MentionController = {
		onStart(p) {
			mentionItems = p.items;
			mentionCommand = p.command;
			mentionRect = p.clientRect?.() ?? null;
			mentionActive = 0;
			mentionOpen = true;
		},
		onUpdate(p) {
			mentionItems = p.items;
			mentionCommand = p.command;
			mentionRect = p.clientRect?.() ?? null;
			if (mentionActive >= p.items.length) mentionActive = 0;
			mentionOpen = true;
		},
		onKeyDown(event) {
			if (!mentionOpen) return false;
			if (event.key === 'Escape') {
				mentionOpen = false;
				return true;
			}
			if (mentionItems.length === 0) return false;
			if (event.key === 'ArrowDown') {
				mentionActive = (mentionActive + 1) % mentionItems.length;
				return true;
			}
			if (event.key === 'ArrowUp') {
				mentionActive = (mentionActive - 1 + mentionItems.length) % mentionItems.length;
				return true;
			}
			if (event.key === 'Enter') {
				selectMention(mentionActive);
				return true;
			}
			return false;
		},
		onExit() {
			mentionOpen = false;
			mentionItems = [];
			mentionCommand = null;
		},
		onPick(item) {
			onMentionPick?.(item.label, item.email);
		},
	};

	// ── Inline body images (WAVE-5 #2) ───────────────────────────────────────
	// Stage each whitelisted-type file inline via onInlineImageFile (synchronous —
	// the upload itself runs in the background) and insert its placeholder <img>
	// at `atPos` (the drop point) or the current selection (paste). Anything NOT
	// staged (unwhitelisted type, or over budget) is forwarded to onNonInlineFiles
	// rather than silently dropped. Returns whether anything was inlined, so the
	// caller (handlePaste/handleDrop) knows whether to consume the event.
	// Exported (like insertMarkdown below) so paste/drop routing is unit-testable
	// without fighting jsdom's ClipboardEvent/DragEvent fidelity — handlePaste and
	// handleDrop below are thin adapters over this same function.
	export function handleImageFiles(files: File[], atPos?: number): boolean {
		const nodes: { type: string; attrs: Record<string, unknown> }[] = [];
		const leftover: File[] = [];
		for (const file of files) {
			const staged = INLINE_IMAGE_TYPES.includes(file.type) ? (onInlineImageFile?.(file) ?? null) : null;
			if (staged) {
				nodes.push({ type: 'image', attrs: { src: staged.previewUrl, alt: '', uploadId: staged.uploadId } });
			} else {
				leftover.push(file);
			}
		}
		if (nodes.length > 0 && editor) {
			const chain = editor.chain().focus();
			if (atPos != null) chain.insertContentAt(atPos, nodes).run();
			else chain.insertContent(nodes).run();
		}
		if (leftover.length > 0) onNonInlineFiles?.(leftover);
		return nodes.length > 0;
	}

	// Upload-overlay position tracking — `position: fixed` rects (same technique
	// as the mention dropdown above) keyed by uploadId, recomputed whenever the
	// document changes (a transaction) or the editor box scrolls internally.
	// ponytail: doesn't track an OUTER ancestor's scroll (the mention dropdown
	// above has the same gap) — the overlay only exists for the few seconds an
	// upload is in flight, so a stale rect during a rare outer scroll is low-
	// stakes; revisit if compose grows a taller, separately-scrolling shell.
	let imgRects = $state<Record<string, DOMRect>>({});

	function updateImageRects() {
		if (!editorEl) return;
		const next: Record<string, DOMRect> = {};
		for (const u of inlineUploads) {
			const el = editorEl.querySelector<HTMLImageElement>(`img[data-upload-id="${u.uploadId}"]`);
			if (el) next[u.uploadId] = el.getBoundingClientRect();
		}
		imgRects = next;
	}

	onMount(() => {
		if (!editorEl) return;

		editor = new Editor({
			element: editorEl,
			extensions: [
				StarterKit.configure({
					heading: false,
					codeBlock: false,
					link: {
						openOnClick: false,
						HTMLAttributes: {
							rel: 'noopener noreferrer',
							target: '_blank',
						},
					},
				}),
				Placeholder.configure({
					placeholder,
				}),
				TemplateVariable,
				// Inline image: URL insert (dialog) OR an uploaded blob: preview (WAVE-5
				// #2 paste/drag/toolbar-upload — see composeStore.stageInlineImage).
				// allowBase64 stays false regardless — outbound sanitizeOutboundHTML()
				// in buildMsg() governs what is persisted/sent, and base64 data: images
				// would bloat the stored/sent HTML instead of riding as attachments.
				InlineImage.configure({
					inline: false,
					allowBase64: false,
					HTMLAttributes: { class: 'sj-inline-img' },
				}),
				// Insert-table support (mirrors the inline-image flow in the toolbar).
				TableKit.configure({ table: { resizable: true } }),
				// Font family / size / color marks (all write onto the TextStyle mark).
				TextStyle,
				Color,
				FontFamily,
				FontSize,
				// @-mention (GAL autocomplete) — only when the caller opts in.
				...(onMentionPick ? [createMentionExtension(mentionController)] : []),
			],
			content,
			editable,
			editorProps: {
				attributes: {
					class: 'tiptap-editor',
				},
				handlePaste: (_view, event) => {
					const clipboardData = event.clipboardData;
					if (!clipboardData) return false;

					// Inline image paste (screenshot etc.) — WAVE-5 #2. Only takes over
					// when the clipboard carries at least one image file: a co-pasted
					// non-image file (a PDF) keeps today's behavior (bubbles to the
					// compose container's attach-as-file paste handler) unchanged. Once
					// taken over, the event is fully consumed — never bubbles — and any
					// leftover file in the SAME paste (a non-whitelisted image type, or
					// one over the shared budget) is forwarded via onNonInlineFiles so
					// nothing is silently dropped.
					const files = Array.from(clipboardData.files || []);
					if (files.some((f) => f.type.startsWith('image/'))) {
						event.preventDefault();
						event.stopPropagation();
						handleImageFiles(files);
						return true;
					}

					// Only intercept plain text paste (no rich HTML or files)
					if (clipboardData.types.includes('text/html') || clipboardData.types.includes('Files')) {
						return false;
					}

					const text = clipboardData.getData('text/plain');
					if (!text) return false;

					// Check for markdown syntax
					const hasMarkdown = /(\*\*|__|`|\[.*?\]\(.*?\))/.test(text);
					if (!hasMarkdown) return false;

					// Prevent default paste, insert HTML
					event.preventDefault();
					const html = markdownToHTML(text);
					editor?.commands.insertContent(html);
					return true;
				},
				// Inline image DROP (WAVE-5 #2) — mirrors handlePaste above. `moved`
				// is true for an internal drag-reorder (an existing node dragged
				// within the doc); that is not a file drop, so it is left alone.
				handleDrop: (view, event, _slice, moved) => {
					if (moved) return false;
					const files = Array.from(event.dataTransfer?.files || []);
					if (!files.some((f) => f.type.startsWith('image/'))) return false;
					// At least one image file — take full ownership (mirrors handlePaste):
					// never bubble to the compose container's own drop-to-attach handler,
					// which would otherwise double-attach whatever handleImageFiles
					// forwards via onNonInlineFiles.
					event.preventDefault();
					event.stopPropagation();
					const pos = view.posAtCoords({ left: event.clientX, top: event.clientY })?.pos;
					handleImageFiles(files, pos);
					return true;
				},
			},
			onUpdate: ({ editor: ed }) => {
				onUpdate?.(ed.getHTML(), ed.getText());
			},
			onFocus: () => onFocus?.(),
			onBlur: () => onBlur?.(),
			onTransaction: () => updateImageRects(),
		});

		editorEl.addEventListener('scroll', updateImageRects);

		// Notify parent that editor is ready
		onEditorReady?.(editor as Editor);
	});

	onDestroy(() => {
		editor?.destroy();
		editorEl?.removeEventListener('scroll', updateImageRects);
	});

	/**
	 * Convert basic markdown syntax to HTML for paste handling.
	 * Supports: **bold**, *italic*, `code`, [text](url)
	 */
	function markdownToHTML(text: string): string {
		let html = text
			.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
			.replace(/__(.+?)__/g, '<strong>$1</strong>')
			.replace(/(?<!\*)\*([^*\n]+?)\*(?!\*)/g, '<em>$1</em>')
			.replace(/(?<!_)_([^_\n]+?)_(?!_)/g, '<em>$1</em>')
			.replace(/`([^`\n]+?)`/g, '<code>$1</code>')
			.replace(
				/\[([^\]]+?)\]\(([^)]+?)\)/g,
				'<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>'
			)
			.replace(/\n\n/g, '</p><p>')
			.replace(/\n/g, '<br>');

		if (!html.startsWith('<')) html = '<p>' + html + '</p>';
		return html;
	}

	// Imperative methods exposed to parent
	export function getEditor(): Editor | null {
		return editor;
	}

	export function getHTML(): string {
		return editor?.getHTML() ?? '';
	}

	export function getText(): string {
		return editor?.getText() ?? '';
	}

	// The SINGLE deliberate post-mount body-write path (arch A3 — see the `content`
	// prop note). Callers replace the body imperatively through this; the editor
	// stays the source of truth and no reactive prop-sync fights its onUpdate.
	export function setContent(html: string): void {
		editor?.commands.setContent(html);
	}

	export function clearContent(): void {
		editor?.commands.clearContent();
	}

	export function focus(): void {
		editor?.commands.focus();
	}

	export function insertMarkdown(text: string): void {
		const html = markdownToHTML(text);
		editor?.commands.insertContent(html);
	}

	export function insertImage(src: string, alt = ''): void {
		editor?.chain().focus().setImage({ src, alt }).run();
	}

	// WAVE-5 #2: remove a still-in-body inline image node by its uploadId — used
	// when its upload FAILS (the placeholder is stripped from the body and the
	// row becomes an ordinary failed file-attachment chip instead, per the design:
	// "failed upload → placeholder becomes an error chip w/ retry/remove"). A
	// no-op if the node was already removed (e.g. the user deleted it themselves).
	export function removeInlineImage(uploadId: string): void {
		if (!editor) return;
		let target: { from: number; to: number } | null = null;
		editor.state.doc.descendants((node, pos) => {
			if (target) return false;
			if (node.type.name === 'image' && node.attrs.uploadId === uploadId) {
				target = { from: pos, to: pos + node.nodeSize };
				return false;
			}
			return true;
		});
		if (target) editor.chain().deleteRange(target).run();
	}

	export function setFontFamily(family: string): void {
		editor?.chain().focus().setFontFamily(family).run();
	}

	export function setTextColor(color: string): void {
		editor?.chain().focus().setColor(color).run();
	}
</script>

<div bind:this={editorEl} class="rich-text-editor"></div>

<!-- WAVE-5 #2: inline body image upload overlay — `position: fixed`, tracked over
     the actual <img data-upload-id> (same technique as the mention dropdown
     above). Only preparing/uploading images get one; a failed upload's node is
     removed from the body entirely (removeInlineImage), and a done image needs
     no overlay at all. -->
{#each inlineUploads.filter((u) => u.status === 'preparing' || u.status === 'uploading') as up (up.uploadId)}
	{@const rect = imgRects[up.uploadId]}
	{#if rect}
		<div
			class="inline-img-overlay"
			data-testid="inline-img-overlay"
			style="top: {rect.top}px; left: {rect.left}px; width: {rect.width}px; height: {rect.height}px;"
		>
			<Spinner size={20} label={t('compose.image.uploading')} />
			{#if up.progress}<span class="inline-img-overlay__pct">{up.progress}%</span>{/if}
		</div>
	{/if}
{/each}

{#if mentionOpen && mentionRect}
	<div
		class="gal-dropdown mention-dropdown"
		role="listbox"
		aria-label={t('compose.mention_listbox_label')}
		style="top: {mentionRect.bottom + 4}px; left: {mentionRect.left}px;"
	>
		{#if mentionItems.length === 0}
			<div class="gal-item gal-item-empty">{t('compose.mention_no_results')}</div>
		{:else}
			{#each mentionItems as item, i (item.id)}
				<button
					type="button"
					class="gal-item"
					role="option"
					aria-selected={mentionActive === i}
					class:gal-item--active={mentionActive === i}
					onmousedown={(e) => {
						e.preventDefault();
						selectMention(i);
					}}
				>
					<strong>{item.label}</strong>
					<span>{item.email}</span>
				</button>
			{/each}
		{/if}
	</div>
{/if}

<style>
	.rich-text-editor {
		min-height: 200px;
		max-height: 400px;
		overflow-y: auto;
		padding: 12px 16px;
		font-family: var(--font-sans);
		font-size: var(--text-md);
		line-height: 1.7;
		color: var(--text-primary);
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		outline: none;
		transition: border-color 0.15s;
	}

	.rich-text-editor:focus-within {
		border-color: var(--accent);
		box-shadow: var(--focus-ring);
	}

	/* @-mention popup — mirrors the compose GAL dropdown, but caret-anchored via
	   `position: fixed` so the editor's `overflow-y: auto` can't clip it. */
	.gal-dropdown {
		position: fixed;
		min-width: 220px;
		max-width: 340px;
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		box-shadow: var(--shadow-md);
		z-index: 200;
		max-height: 240px;
		overflow-y: auto;
	}
	.gal-item {
		display: flex;
		flex-direction: column;
		padding: 8px 12px;
		background: none;
		border: none;
		border-bottom: 1px solid var(--border-subtle);
		cursor: pointer;
		width: 100%;
		text-align: left;
	}
	.gal-item:hover,
	.gal-item--active {
		background: var(--surface-hover);
	}
	.gal-item:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.gal-item strong {
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	.gal-item span {
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}
	.gal-item-empty {
		padding: 8px 12px;
		color: var(--text-secondary);
		font-style: italic;
		font-size: var(--text-sm);
		cursor: default;
	}

	/* Mention chip in the body (parallels .template-var-chip). */
	:global(.tiptap-editor .mention) {
		display: inline-block;
		padding: 1px 8px;
		border-radius: var(--radius-sm);
		background: var(--accent-subtle);
		color: var(--text-accent);
		font-weight: 600;
		font-size: 0.9em;
		cursor: default;
		user-select: none;
	}

	/* TipTap editor inner element */
	:global(.tiptap-editor) {
		outline: none;
		min-height: 180px;
	}

	:global(.tiptap-editor p) {
		margin: 0 0 8px;
	}

	:global(.tiptap-editor p:last-child) {
		margin-bottom: 0;
	}

	/* Placeholder */
	:global(.tiptap-editor p.is-editor-empty:first-child::before) {
		content: attr(data-placeholder);
		float: left;
		color: var(--text-disabled);
		pointer-events: none;
		height: 0;
	}

	/* Link styling */
	:global(.tiptap-editor a) {
		color: var(--accent);
		text-decoration: underline;
	}

	/* Lists */
	:global(.tiptap-editor ul),
	:global(.tiptap-editor ol) {
		padding-left: 24px;
		margin: 8px 0;
	}

	:global(.tiptap-editor li) {
		margin-bottom: 4px;
	}

	/* Blockquote */
	:global(.tiptap-editor blockquote) {
		border-left: 3px solid var(--accent);
		padding-left: 16px;
		margin: 8px 0;
		color: var(--text-secondary);
	}

	/* Template variable chip */
	:global(.template-var-chip) {
		display: inline-block;
		padding: 1px 8px;
		border-radius: var(--radius-sm);
		background: var(--accent-subtle);
		color: var(--text-accent);
		font-weight: 600;
		font-size: 0.9em;
		cursor: default;
		user-select: none;
	}

	:global(.tiptap-editor code) {
		background: var(--surface-sunken);
		padding: 2px 6px;
		border-radius: var(--radius-xs, 4px);
		font-family: var(--font-mono);
		font-size: 0.9em;
	}

	/* Inline images */
	:global(.tiptap-editor img.sj-inline-img) {
		max-width: 100%;
		height: auto;
		border-radius: var(--radius-sm);
	}

	/* WAVE-5 #2: upload-in-progress overlay, tracked over the <img> via
	   position: fixed (see mention-dropdown comment above). */
	.inline-img-overlay {
		position: fixed;
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 6px;
		background: color-mix(in srgb, var(--surface-card) 70%, transparent);
		border-radius: var(--radius-sm);
		pointer-events: none;
	}
	.inline-img-overlay__pct {
		font-size: var(--text-xs);
		font-weight: 600;
		color: var(--text-primary);
	}

	/* Tables — visible gridlines while composing (received-mail inline borders skipped;
	   ponytail: editor-only, cell-border inline styles per-cell would be noise). */
	:global(.tiptap-editor table) {
		border-collapse: collapse;
		margin: 8px 0;
		width: 100%;
		table-layout: fixed;
		overflow: hidden;
	}
	:global(.tiptap-editor th),
	:global(.tiptap-editor td) {
		border: 1px solid var(--border-default);
		padding: 6px 8px;
		vertical-align: top;
		text-align: left;
		min-width: 40px;
		position: relative;
	}
	:global(.tiptap-editor th) {
		background: var(--surface-sunken);
		font-weight: 600;
	}
	/* Column-resize handle + active-cell highlight (TipTap table selection). */
	:global(.tiptap-editor .selectedCell::after) {
		content: '';
		position: absolute;
		inset: 0;
		background: var(--accent-subtle);
		pointer-events: none;
	}
	:global(.tiptap-editor .column-resize-handle) {
		position: absolute;
		right: -2px;
		top: 0;
		bottom: 0;
		width: 4px;
		background: var(--accent);
		pointer-events: none;
	}
</style>
