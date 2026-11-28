<svelte:options runes={true} />

<script lang="ts">
	import type { Editor } from '@tiptap/core';
	import Icon from './Icon.svelte';
	import { IconButton, Dialog, Input, Button } from '$lib/components/ui';
	import { INLINE_IMAGE_TYPES } from '$lib/stores/composeStore.svelte';
	import { t } from '$lib/i18n';

	interface Props {
		editor: Editor | null;
		// WAVE-5 #2: the Insert-image dialog's "upload from computer" path — same
		// seam RichTextEditor's paste/drop use (see its onInlineImageFile prop doc).
		// Absent → the dialog offers URL-insert only (unchanged for callers that
		// haven't wired the upload seam, e.g. any future non-compose usage).
		onInlineImageFile?: (file: File) => { previewUrl: string; uploadId: string } | null;
	}

	let { editor, onInlineImageFile }: Props = $props();

	// Reactive snapshot of active marks, updated on every editor transaction.
	// Using $state so Svelte tracks changes and re-renders the toolbar.
	let activeMarks = $state<Record<string, boolean>>({});

	const TRACKED = ['bold', 'italic', 'underline', 'strike', 'orderedList', 'bulletList', 'blockquote', 'link', 'table'];

	function refreshMarks(ed: Editor) {
		const next: Record<string, boolean> = {};
		for (const m of TRACKED) next[m] = ed.isActive(m);
		activeMarks = next;
	}

	// Subscribe to the editor's transaction stream so toolbar stays in sync as
	// the cursor moves in/out of bold, italic, link, etc.
	$effect(() => {
		const ed: Editor | null = editor;
		if (ed === null) {
			activeMarks = {};
			return;
		}
		// Snapshot immediately when editor prop changes (ed is now narrowed to Editor)
		const narrowed: Editor = ed;
		refreshMarks(narrowed);

		const onTransaction = () => refreshMarks(narrowed);
		const onSelectionUpdate = () => refreshMarks(narrowed);
		narrowed.on('transaction', onTransaction);
		narrowed.on('selectionUpdate', onSelectionUpdate);
		return () => {
			narrowed.off('transaction', onTransaction);
			narrowed.off('selectionUpdate', onSelectionUpdate);
		};
	});

	function isActive(action: string): boolean {
		return activeMarks[action] ?? false;
	}

	// Toolbar button definitions
	const groups = [
		[
			{ icon: 'Bold' as const, action: 'bold', title: 'Bold' },
			{ icon: 'Italic' as const, action: 'italic', title: 'Italic' },
			{ icon: 'Underline' as const, action: 'underline', title: 'Underline' },
			{ icon: 'Strikethrough' as const, action: 'strike', title: 'Strikethrough' },
		],
		[
			{ icon: 'ListOrdered' as const, action: 'orderedList', title: 'Numbered list' },
			{ icon: 'List' as const, action: 'bulletList', title: 'Bullet list' },
			{ icon: 'Quote' as const, action: 'blockquote', title: 'Blockquote' },
		],
		[
			{ icon: 'Link' as const, action: 'link', title: 'Insert link' },
		],
	];

	// ── Link dialog state ──
	let linkDialogOpen = $state(false);
	let linkUrl = $state('');
	let linkUrlError = $state('');

	function openLinkDialog() {
		const attrs = editor?.getAttributes('link');
		linkUrl = (attrs?.href as string | undefined) ?? '';
		linkUrlError = '';
		linkDialogOpen = true;
	}

	function closeLinkDialog() {
		linkDialogOpen = false;
		linkUrl = '';
		linkUrlError = '';
	}

	function validateUrl(url: string): boolean {
		const trimmed = url.trim();
		return (
			trimmed.startsWith('https://') ||
			trimmed.startsWith('http://') ||
			trimmed.startsWith('mailto:')
		);
	}

	function insertLink() {
		const trimmed = linkUrl.trim();
		if (!validateUrl(trimmed)) {
			linkUrlError = t('compose.link.url_error');
			return;
		}
		editor?.chain().focus().setLink({ href: trimmed }).run();
		closeLinkDialog();
	}

	function removeLink() {
		editor?.chain().focus().unsetLink().run();
		closeLinkDialog();
	}

	// ── Image dialog state (Task 6) ──
	let imageDialogOpen = $state(false);
	let imageUrl = $state('');
	let imageAlt = $state('');
	let imageUrlError = $state('');

	function openImageDialog() {
		imageUrl = '';
		imageAlt = '';
		imageUrlError = '';
		imageDialogOpen = true;
	}

	function closeImageDialog() {
		imageDialogOpen = false;
		imageUrl = '';
		imageAlt = '';
		imageUrlError = '';
	}

	function validateImageUrl(url: string): boolean {
		const trimmed = url.trim();
		return trimmed.startsWith('https://') || trimmed.startsWith('http://');
	}

	function insertImage() {
		const trimmed = imageUrl.trim();
		if (!validateImageUrl(trimmed)) {
			imageUrlError = t('compose.image.url_error');
			return;
		}
		editor?.chain().focus().setImage({ src: trimmed, alt: imageAlt.trim() }).run();
		closeImageDialog();
	}

	// WAVE-5 #2: "Upload from computer" — the file-input alternative to the URL
	// field above. Stages via onInlineImageFile (the same seam paste/drag use in
	// RichTextEditor) and inserts the placeholder <img> immediately; the upload
	// itself runs in the background (progress/failure surface via the shared
	// composeStore attachment row, same as a pasted image). A rejected file (bad
	// type, or over the shared budget) surfaces inline in the dialog rather than
	// closing it, mirroring the URL field's own validation-error pattern.
	function onImageFileInput(e: Event) {
		const file = (e.target as HTMLInputElement).files?.[0];
		(e.target as HTMLInputElement).value = ''; // allow re-picking the same file
		if (!file) return;
		if (!INLINE_IMAGE_TYPES.includes(file.type)) {
			imageUrlError = t('compose.image.type_error');
			return;
		}
		const staged = onInlineImageFile?.(file);
		if (!staged) {
			imageUrlError = t('compose.attachmentTooLarge', { name: file.name });
			return;
		}
		editor?.chain().focus().insertContent({ type: 'image', attrs: { src: staged.previewUrl, alt: '', uploadId: staged.uploadId } }).run();
		closeImageDialog();
	}

	// ── Table dialog state (mirrors the image dialog) ──
	let tableDialogOpen = $state(false);
	let tableRows = $state('3');
	let tableCols = $state('3');

	function openTableDialog() {
		tableRows = '3';
		tableCols = '3';
		tableDialogOpen = true;
	}

	function closeTableDialog() {
		tableDialogOpen = false;
	}

	function insertTable() {
		const rows = Math.min(20, Math.max(1, parseInt(tableRows, 10) || 3));
		const cols = Math.min(20, Math.max(1, parseInt(tableCols, 10) || 3));
		editor?.chain().focus().insertTable({ rows, cols, withHeaderRow: true }).run();
		closeTableDialog();
	}

	// Contextual table-edit commands (buttons shown only when the cursor is in a table).
	function tableCmd(cmd: 'addRowAfter' | 'deleteRow' | 'addColumnAfter' | 'deleteColumn' | 'deleteTable') {
		if (!editor) return;
		const chain = editor.chain().focus();
		switch (cmd) {
			case 'addRowAfter': chain.addRowAfter().run(); break;
			case 'deleteRow': chain.deleteRow().run(); break;
			case 'addColumnAfter': chain.addColumnAfter().run(); break;
			case 'deleteColumn': chain.deleteColumn().run(); break;
			case 'deleteTable': chain.deleteTable().run(); break;
		}
	}

	// ── Font / size / color controls (Task 7) ──
	function onFontFamily(value: string) {
		editor?.chain().focus().setFontFamily(value).run();
	}

	function onFontSize(value: string) {
		editor?.chain().focus().setFontSize(value).run();
	}

	function onTextColor(value: string) {
		editor?.chain().focus().setColor(value).run();
	}

	function toggle(action: string) {
		if (!editor) return;
		if (action === 'link') {
			if (editor.isActive('link')) {
				editor.chain().focus().unsetLink().run();
			} else {
				openLinkDialog();
			}
			return;
		}
		const chain = editor.chain().focus();
		switch (action) {
			case 'bold': chain.toggleBold().run(); break;
			case 'italic': chain.toggleItalic().run(); break;
			case 'underline': chain.toggleUnderline().run(); break;
			case 'strike': chain.toggleStrike().run(); break;
			case 'orderedList': chain.toggleOrderedList().run(); break;
			case 'bulletList': chain.toggleBulletList().run(); break;
			case 'blockquote': chain.toggleBlockquote().run(); break;
		}
	}

	const isLinkActive = $derived(isActive('link'));
</script>

<div class="toolbar" role="toolbar" aria-label={t('compose.toolbar.formatting')}>
	{#each groups as group}
		<div class="toolbar-group">
			{#each group as btn}
				<IconButton
					label={btn.title}
					size="md"
					variant="ghost"
					active={isActive(btn.action)}
					disabled={!editor}
					aria-pressed={isActive(btn.action)}
					onclick={() => toggle(btn.action)}
				>
					<Icon name={btn.icon} size={16} />
				</IconButton>
			{/each}
		</div>
	{/each}

	<!-- Inline image (Task 6) -->
	<div class="toolbar-group">
		<IconButton
			label={t('compose.toolbar.insertImage')}
			size="md"
			variant="ghost"
			disabled={!editor}
			onclick={openImageDialog}
		>
			<Icon name="Image" size={16} />
		</IconButton>
	</div>

	<!-- Insert table + contextual table-edit controls -->
	<div class="toolbar-group">
		<IconButton
			label={t('compose.toolbar.insert_table')}
			size="md"
			variant="ghost"
			active={isActive('table')}
			disabled={!editor}
			onclick={openTableDialog}
		>
			<Icon name="Table" size={16} />
		</IconButton>
		{#if isActive('table')}
			<IconButton label={t('compose.toolbar.add_row')} size="md" variant="ghost" disabled={!editor} onclick={() => tableCmd('addRowAfter')}>
				<Icon name="BetweenHorizontalEnd" size={16} />
			</IconButton>
			<IconButton label={t('compose.toolbar.delete_row')} size="md" variant="ghost" disabled={!editor} onclick={() => tableCmd('deleteRow')}>
				<Icon name="Rows3" size={16} />
			</IconButton>
			<IconButton label={t('compose.toolbar.add_column')} size="md" variant="ghost" disabled={!editor} onclick={() => tableCmd('addColumnAfter')}>
				<Icon name="BetweenVerticalEnd" size={16} />
			</IconButton>
			<IconButton label={t('compose.toolbar.delete_column')} size="md" variant="ghost" disabled={!editor} onclick={() => tableCmd('deleteColumn')}>
				<Icon name="Columns3" size={16} />
			</IconButton>
			<IconButton label={t('compose.toolbar.delete_table')} size="md" variant="ghost" disabled={!editor} onclick={() => tableCmd('deleteTable')}>
				<Icon name="Trash2" size={16} />
			</IconButton>
		{/if}
	</div>

	<!-- Font family / size / color (Task 7) -->
	<div class="toolbar-group">
		<select
			class="rte-select"
			aria-label="Font"
			disabled={!editor}
			onchange={(e) => onFontFamily((e.target as HTMLSelectElement).value)}
		>
			<option value="">{t('compose.toolbar.fontDefault')}</option>
			<option value="Arial, sans-serif">Sans</option>
			<option value="Georgia, serif">Serif</option>
			<option value="'Courier New', monospace">Mono</option>
		</select>
		<select
			class="rte-select"
			aria-label="Size"
			disabled={!editor}
			onchange={(e) => onFontSize((e.target as HTMLSelectElement).value)}
		>
			<option value="">{t('compose.toolbar.sizeDefault')}</option>
			<option value="0.85em">S</option>
			<option value="1em">M</option>
			<option value="1.25em">L</option>
		</select>
		<label class="rte-color">
			<Icon name="Baseline" size={16} />
			<input
				type="color"
				class="rte-color-input"
				aria-label="Text color"
				disabled={!editor}
				oninput={(e) => onTextColor((e.target as HTMLInputElement).value)}
			/>
		</label>
	</div>
</div>

<!-- Link insert/edit dialog -->
<Dialog
	open={linkDialogOpen}
	title={isLinkActive ? t('compose.link.remove') : t('compose.link.dialog_title')}
	onClose={closeLinkDialog}
>
	{#snippet children()}
		{#if isLinkActive}
			<p style="color: var(--text-secondary); font-size: var(--text-sm); margin: 0 0 4px;">
				{t('compose.link.url_label')}: {editor?.getAttributes('link')?.href ?? ''}
			</p>
		{:else}
			<Input
				label={t('compose.link.url_label')}
				placeholder={t('compose.link.url_placeholder')}
				bind:value={linkUrl}
				error={linkUrlError}
				type="url"
				onkeydown={(e: KeyboardEvent) => { if (e.key === 'Enter') insertLink(); }}
			/>
		{/if}
	{/snippet}
	{#snippet footer()}
		<Button variant="ghost" onclick={closeLinkDialog}>{t('common.cancel')}</Button>
		{#if isLinkActive}
			<Button variant="danger" onclick={removeLink}>{t('compose.link.remove')}</Button>
		{:else}
			<Button variant="primary" onclick={insertLink}>{t('compose.link.insert')}</Button>
		{/if}
	{/snippet}
</Dialog>

<!-- Inline image insert dialog -->
<Dialog open={imageDialogOpen} title={t('compose.image.dialog_title')} onClose={closeImageDialog}>
	{#snippet children()}
		<Input
			label={t('compose.image.url_label')}
			placeholder={t('compose.image.url_placeholder')}
			bind:value={imageUrl}
			error={imageUrlError}
			type="url"
			onkeydown={(e: KeyboardEvent) => { if (e.key === 'Enter') insertImage(); }}
		/>
		<Input
			label={t('compose.image.alt_label')}
			bind:value={imageAlt}
		/>
		{#if onInlineImageFile}
			<label class="rte-file-upload">
				<span>{t('compose.image.or_upload')}</span>
				<input
					type="file"
					accept={INLINE_IMAGE_TYPES.join(',')}
					aria-label={t('compose.image.upload_label')}
					onchange={onImageFileInput}
				/>
			</label>
		{/if}
	{/snippet}
	{#snippet footer()}
		<Button variant="ghost" onclick={closeImageDialog}>{t('common.cancel')}</Button>
		<Button variant="primary" onclick={insertImage}>{t('compose.image.insert')}</Button>
	{/snippet}
</Dialog>

<!-- Insert table dialog (rows × cols) -->
<Dialog open={tableDialogOpen} title={t('compose.toolbar.insert_table')} onClose={closeTableDialog}>
	{#snippet children()}
		<Input
			label={t('compose.toolbar.table_rows')}
			bind:value={tableRows}
			type="number"
			onkeydown={(e: KeyboardEvent) => { if (e.key === 'Enter') insertTable(); }}
		/>
		<Input
			label={t('compose.toolbar.table_cols')}
			bind:value={tableCols}
			type="number"
			onkeydown={(e: KeyboardEvent) => { if (e.key === 'Enter') insertTable(); }}
		/>
	{/snippet}
	{#snippet footer()}
		<Button variant="ghost" onclick={closeTableDialog}>{t('common.cancel')}</Button>
		<Button variant="primary" onclick={insertTable}>{t('compose.image.insert')}</Button>
	{/snippet}
</Dialog>

<style>
	.toolbar {
		display: flex;
		align-items: center;
		gap: 0;
		padding: 4px 8px;
		border: 1px solid var(--border-default);
		border-bottom: none;
		border-radius: var(--radius-sm) var(--radius-sm) 0 0;
		background: var(--surface-sunken);
	}

	.toolbar-group {
		display: flex;
		align-items: center;
		gap: 2px;
		padding: 0 4px;
	}

	.toolbar-group + .toolbar-group {
		border-left: 1px solid var(--border-default);
		margin-left: 4px;
		padding-left: 8px;
	}

	.rte-select {
		height: 26px;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		background: var(--surface-card);
		color: var(--text-primary);
		font-family: var(--font-sans);
		font-size: var(--text-xs);
		padding: 0 6px;
		cursor: pointer;
	}

	.rte-select:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	.rte-select:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.rte-color {
		display: inline-flex;
		align-items: center;
		gap: 2px;
		position: relative;
		color: var(--text-secondary);
		cursor: pointer;
	}

	.rte-color-input {
		width: 22px;
		height: 22px;
		padding: 0;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		background: var(--surface-card);
		cursor: pointer;
	}

	.rte-color-input:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	.rte-color-input:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.rte-file-upload {
		display: flex;
		flex-direction: column;
		gap: 4px;
		margin-top: 8px;
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
</style>
