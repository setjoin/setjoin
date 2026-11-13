import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import RichTextEditorToolbar from './RichTextEditorToolbar.svelte';

function fakeEditor(active: string[] = [], attributes: Record<string, unknown> = {}) {
	const run = vi.fn();
	const listeners = new Map<string, () => void>();
	const chain: Record<string, unknown> = {
		focus: () => chain,
		setImage: vi.fn(() => chain),
		setColor: vi.fn(() => chain),
		setFontFamily: vi.fn(() => chain),
		setFontSize: vi.fn(() => chain),
		setMark: vi.fn(() => chain),
		setLink: vi.fn(() => chain),
		unsetLink: vi.fn(() => chain),
		toggleBold: vi.fn(() => chain),
		toggleItalic: vi.fn(() => chain),
		toggleUnderline: vi.fn(() => chain),
		toggleStrike: vi.fn(() => chain),
		toggleOrderedList: vi.fn(() => chain),
		toggleBulletList: vi.fn(() => chain),
		toggleBlockquote: vi.fn(() => chain),
		insertTable: vi.fn(() => chain),
		addRowAfter: vi.fn(() => chain),
		deleteRow: vi.fn(() => chain),
		addColumnAfter: vi.fn(() => chain),
		deleteColumn: vi.fn(() => chain),
		deleteTable: vi.fn(() => chain),
		insertContent: vi.fn(() => chain),
		run,
	};
	return {
		isActive: (mark: string) => active.includes(mark),
		getAttributes: () => attributes,
		on: vi.fn((event: string, callback: () => void) => listeners.set(event, callback)),
		off: vi.fn((event: string) => listeners.delete(event)),
		chain: () => chain,
		_chain: chain,
		_listeners: listeners,
	} as never;
}

describe('RichTextEditorToolbar — font/color/image (Task 6 + 7)', () => {
	it('renders an Insert image button', () => {
		render(RichTextEditorToolbar, { editor: fakeEditor() });
		expect(screen.getByLabelText('Insert image')).toBeInTheDocument();
	});

	it('renders a text-color control', () => {
		render(RichTextEditorToolbar, { editor: fakeEditor() });
		expect(screen.getByLabelText('Text color')).toBeInTheDocument();
	});

	it('renders a font-family selector', () => {
		render(RichTextEditorToolbar, { editor: fakeEditor() });
		expect(screen.getByLabelText('Font')).toBeInTheDocument();
	});

	it('renders a font-size selector', () => {
		render(RichTextEditorToolbar, { editor: fakeEditor() });
		expect(screen.getByLabelText('Size')).toBeInTheDocument();
	});

	it('calls setFontFamily when a font is chosen', async () => {
		const ed = fakeEditor();
		render(RichTextEditorToolbar, { editor: ed });
		await fireEvent.change(screen.getByLabelText('Font'), { target: { value: 'Georgia, serif' } });
		expect(
			(ed as never as { _chain: { setFontFamily: ReturnType<typeof vi.fn> } })._chain.setFontFamily
		).toHaveBeenCalledWith('Georgia, serif');
	});

	it('calls setColor when a color is picked', async () => {
		const ed = fakeEditor();
		render(RichTextEditorToolbar, { editor: ed });
		await fireEvent.input(screen.getByLabelText('Text color'), { target: { value: '#123456' } });
		expect(
			(ed as never as { _chain: { setColor: ReturnType<typeof vi.fn> } })._chain.setColor
		).toHaveBeenCalledWith('#123456');
	});

	it('disables every command when no editor is attached', () => {
		render(RichTextEditorToolbar, { editor: null });
		expect(screen.getAllByRole('button').every((button) => (button as HTMLButtonElement).disabled)).toBe(true);
		expect((screen.getByLabelText('Font') as HTMLSelectElement).disabled).toBe(true);
		expect((screen.getByLabelText('Text color') as HTMLInputElement).disabled).toBe(true);
	});

	it('runs each inline formatting command and the font-size command', async () => {
		const ed = fakeEditor();
		render(RichTextEditorToolbar, { editor: ed });
		for (const label of ['Bold', 'Italic', 'Underline', 'Strikethrough', 'Numbered list', 'Bullet list', 'Blockquote']) {
			await fireEvent.click(screen.getByLabelText(label));
		}
		await fireEvent.change(screen.getByLabelText('Size'), { target: { value: '1.25em' } });
		const chain = (ed as never as { _chain: Record<string, ReturnType<typeof vi.fn>> })._chain;
		for (const command of ['toggleBold', 'toggleItalic', 'toggleUnderline', 'toggleStrike', 'toggleOrderedList', 'toggleBulletList', 'toggleBlockquote']) {
			expect(chain[command]).toHaveBeenCalledOnce();
		}
		expect(chain.setFontSize).toHaveBeenCalledWith('1.25em');
	});

	it('refreshes active marks on editor events and unsubscribes on teardown', async () => {
		const active: string[] = [];
		const ed = fakeEditor(active);
		const view = render(RichTextEditorToolbar, { editor: ed });
		await waitFor(() => expect((ed as never as { on: ReturnType<typeof vi.fn> }).on).toHaveBeenCalledTimes(2));
		active.push('bold');
		(ed as never as { _listeners: Map<string, () => void> })._listeners.get('transaction')?.();
		await waitFor(() => expect(screen.getByLabelText('Bold')).toHaveAttribute('aria-pressed', 'true'));
		active.push('table');
		(ed as never as { _listeners: Map<string, () => void> })._listeners.get('selectionUpdate')?.();
		await waitFor(() => expect(screen.getByLabelText('Add row')).toBeInTheDocument());
		view.unmount();
		expect((ed as never as { off: ReturnType<typeof vi.fn> }).off).toHaveBeenCalledTimes(2);
	});

	it('validates, inserts, edits, and removes links', async () => {
		const ed = fakeEditor();
		render(RichTextEditorToolbar, { editor: ed });
		await fireEvent.click(screen.getByLabelText('Insert link'));
		const input = screen.getByLabelText('URL');
		await fireEvent.input(input, { target: { value: 'ftp://unsafe.test' } });
		await fireEvent.click(screen.getByText('Insert'));
		expect(screen.getByText(/valid URL/i)).toBeInTheDocument();
		await fireEvent.input(input, { target: { value: ' mailto:user@example.test ' } });
		await fireEvent.keyDown(input, { key: 'Enter' });
		expect((ed as never as { _chain: { setLink: ReturnType<typeof vi.fn> } })._chain.setLink)
			.toHaveBeenCalledWith({ href: 'mailto:user@example.test' });

		const linked = fakeEditor(['link'], { href: 'https://setjoin.test' });
		render(RichTextEditorToolbar, { editor: linked });
		await fireEvent.click(screen.getAllByLabelText('Insert link')[1]);
		expect((linked as never as { _chain: { unsetLink: ReturnType<typeof vi.fn> } })._chain.unsetLink).toHaveBeenCalledOnce();
	});

	it('opens the image dialog and inserts an image URL', async () => {
		const ed = fakeEditor();
		render(RichTextEditorToolbar, { editor: ed });
		await fireEvent.click(screen.getByLabelText('Insert image'));
		const urlInput = screen.getByLabelText('Image URL') as HTMLInputElement;
		await fireEvent.input(urlInput, { target: { value: 'https://corp.test/pic.png' } });
		await fireEvent.click(screen.getByText('Insert'));
		expect(
			(ed as never as { _chain: { setImage: ReturnType<typeof vi.fn> } })._chain.setImage
		).toHaveBeenCalledWith(expect.objectContaining({ src: 'https://corp.test/pic.png' }));
	});

	it('keeps the image dialog open for invalid URLs and inserts trimmed alt text on Enter', async () => {
		const ed = fakeEditor();
		render(RichTextEditorToolbar, { editor: ed });
		await fireEvent.click(screen.getByLabelText('Insert image'));
		const url = screen.getByLabelText('Image URL');
		await fireEvent.input(url, { target: { value: 'data:image/png;base64,bad' } });
		await fireEvent.click(screen.getByText('Insert'));
		expect(screen.getByText(/valid image URL/i)).toBeInTheDocument();
		await fireEvent.input(url, { target: { value: ' https://corp.test/diagram.png ' } });
		await fireEvent.input(screen.getByLabelText('Alt text'), { target: { value: ' Diagram ' } });
		await fireEvent.keyDown(url, { key: 'Enter' });
		expect((ed as never as { _chain: { setImage: ReturnType<typeof vi.fn> } })._chain.setImage)
			.toHaveBeenCalledWith({ src: 'https://corp.test/diagram.png', alt: 'Diagram' });
	});

	// -- WAVE-5 #2: toolbar "upload from computer" --

	function png(name = 'shot.png') {
		return new File(['x'], name, { type: 'image/png' });
	}

	it('the upload control is absent when onInlineImageFile is not wired', async () => {
		render(RichTextEditorToolbar, { editor: fakeEditor() });
		await fireEvent.click(screen.getByLabelText('Insert image'));
		expect(screen.queryByLabelText('Upload image from your computer')).toBeNull();
	});

	it('uploading a whitelisted file inserts a placeholder image node with its uploadId', async () => {
		const ed = fakeEditor();
		const staged = { previewUrl: 'blob:mock-1', uploadId: 'up-1' };
		const onInlineImageFile = vi.fn(() => staged);
		render(RichTextEditorToolbar, { editor: ed, onInlineImageFile });
		await fireEvent.click(screen.getByLabelText('Insert image'));

		const file = png();
		const input = screen.getByLabelText('Upload image from your computer') as HTMLInputElement;
		await fireEvent.change(input, { target: { files: [file] } });

		expect(onInlineImageFile).toHaveBeenCalledWith(file);
		expect(
			(ed as never as { _chain: { insertContent: ReturnType<typeof vi.fn> } })._chain.insertContent
		).toHaveBeenCalledWith({ type: 'image', attrs: { src: 'blob:mock-1', alt: '', uploadId: 'up-1' } });
		// Dialog closes on success.
		expect(screen.queryByLabelText('Upload image from your computer')).toBeNull();
	});

	it('a rejected upload (over budget) surfaces an inline error and keeps the dialog open', async () => {
		const ed = fakeEditor();
		const onInlineImageFile = vi.fn(() => null); // budget rejection
		render(RichTextEditorToolbar, { editor: ed, onInlineImageFile });
		await fireEvent.click(screen.getByLabelText('Insert image'));

		await fireEvent.change(screen.getByLabelText('Upload image from your computer'), {
			target: { files: [png('huge.png')] },
		});

		expect(
			(ed as never as { _chain: { insertContent: ReturnType<typeof vi.fn> } })._chain.insertContent
		).not.toHaveBeenCalled();
		expect(screen.getByText(/huge\.png/)).toBeInTheDocument();
		// Dialog stayed open (the URL field is still there).
		expect(screen.getByLabelText('Image URL')).toBeInTheDocument();
	});

	it('a non-whitelisted type (SVG) is rejected before ever calling onInlineImageFile', async () => {
		const ed = fakeEditor();
		const onInlineImageFile = vi.fn();
		render(RichTextEditorToolbar, { editor: ed, onInlineImageFile });
		await fireEvent.click(screen.getByLabelText('Insert image'));

		const svg = new File(['x'], 'evil.svg', { type: 'image/svg+xml' });
		await fireEvent.change(screen.getByLabelText('Upload image from your computer'), { target: { files: [svg] } });

		expect(onInlineImageFile).not.toHaveBeenCalled();
		expect(
			(ed as never as { _chain: { insertContent: ReturnType<typeof vi.fn> } })._chain.insertContent
		).not.toHaveBeenCalled();
	});

	it('ignores an empty file selection and permits picking the same file again', async () => {
		const ed = fakeEditor();
		const onInlineImageFile = vi.fn(() => ({ previewUrl: 'blob:x', uploadId: 'x' }));
		render(RichTextEditorToolbar, { editor: ed, onInlineImageFile });
		await fireEvent.click(screen.getByLabelText('Insert image'));
		const input = screen.getByLabelText('Upload image from your computer') as HTMLInputElement;
		await fireEvent.change(input, { target: { files: [] } });
		expect(onInlineImageFile).not.toHaveBeenCalled();
		expect(input.value).toBe('');
	});

	it('clamps table dimensions and exposes every contextual table command', async () => {
		const ed = fakeEditor(['table']);
		render(RichTextEditorToolbar, { editor: ed });
		await fireEvent.click(screen.getByLabelText('Insert table'));
		await fireEvent.input(screen.getByLabelText('Rows'), { target: { value: '99' } });
		await fireEvent.input(screen.getByLabelText('Columns'), { target: { value: '-5' } });
		await fireEvent.keyDown(screen.getByLabelText('Columns'), { key: 'Enter' });
		const chain = (ed as never as { _chain: Record<string, ReturnType<typeof vi.fn>> })._chain;
		expect(chain.insertTable).toHaveBeenCalledWith({ rows: 20, cols: 1, withHeaderRow: true });
		for (const [label, command] of [
			['Add row', 'addRowAfter'], ['Delete row', 'deleteRow'], ['Add column', 'addColumnAfter'],
			['Delete column', 'deleteColumn'], ['Delete table', 'deleteTable'],
		] as const) {
			await fireEvent.click(screen.getByLabelText(label));
			expect(chain[command]).toHaveBeenCalledOnce();
		}
	});

	it('falls back to a 3 by 3 table for non-numeric dimensions and closes on cancel', async () => {
		const ed = fakeEditor();
		render(RichTextEditorToolbar, { editor: ed });
		await fireEvent.click(screen.getByLabelText('Insert table'));
		await fireEvent.input(screen.getByLabelText('Rows'), { target: { value: '' } });
		await fireEvent.input(screen.getByLabelText('Columns'), { target: { value: '' } });
		await fireEvent.click(screen.getByText('Insert'));
		expect((ed as never as { _chain: { insertTable: ReturnType<typeof vi.fn> } })._chain.insertTable)
			.toHaveBeenCalledWith({ rows: 3, cols: 3, withHeaderRow: true });
	});
});
