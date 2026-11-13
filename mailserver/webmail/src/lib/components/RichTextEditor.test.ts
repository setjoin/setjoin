import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import RichTextEditor from './RichTextEditor.svelte';

// TipTap/ProseMirror uses browser APIs not available in jsdom.
// Provide minimal stubs so the Editor constructor doesn't crash.
beforeEach(() => {
	// jsdom doesn't have getSelection on document
	if (typeof document.getSelection !== 'function') {
		Object.defineProperty(document, 'getSelection', {
			value: () => null,
			writable: true,
			configurable: true,
		});
	}
	// Some ProseMirror plugins need Range
	if (typeof globalThis.Range !== 'function') {
		(globalThis as any).Range = class Range {
			startContainer: any = null;
			startOffset = 0;
			endContainer: any = null;
			endOffset = 0;
			collapsed = true;
			setStart() {}
			setEnd() {}
			setStartBefore() {}
			setEndAfter() {}
		};
	}
	// ProseMirror viewport tracking uses elementFromPoint (not in jsdom)
	if (typeof (document as any).elementFromPoint !== 'function') {
		(document as any).elementFromPoint = () => document.body;
	}
	// Some ProseMirror view operations use caretPositionFromPoint
	if (typeof (document as any).caretPositionFromPoint !== 'function') {
		(document as any).caretPositionFromPoint = () => null;
	}
});

describe('RichTextEditor', () => {
	it('renders the editor with initial HTML content', async () => {
		const { container } = render(RichTextEditor, {
			content: '<p>Hello <strong>World</strong></p>',
			placeholder: 'Write your message...',
		});

		// TipTap renders a div with contenteditable
		await waitFor(() => {
			const editor = container.querySelector('[contenteditable]');
			expect(editor).toBeTruthy();
		});

		const editor = container.querySelector('[contenteditable]')!;
		expect(editor.innerHTML).toContain('<strong>World</strong>');
	});

	it('emits content changes via onUpdate callback', async () => {
		let lastHtml = '';
		let lastText = '';
		const { container } = render(RichTextEditor, {
			content: '<p>Initial</p>',
			onUpdate: (html: string, text: string) => {
				lastHtml = html;
				lastText = text;
			},
		});

		await waitFor(() => {
			const editor = container.querySelector('[contenteditable]');
			expect(editor).toBeTruthy();
		});

		const editor = container.querySelector('[contenteditable]')!;
		editor.innerHTML = '<p>Updated content</p>';
		await fireEvent.input(editor);

		// onUpdate should have been called with the new content
		expect(lastText).toContain('Updated content');
	});

	it('shows placeholder text when empty', async () => {
		const { container } = render(RichTextEditor, {
			content: '',
			placeholder: 'Compose email...',
		});

		await waitFor(() => {
			const editor = container.querySelector('[contenteditable]');
			expect(editor).toBeTruthy();
		});

		// The TipTap Placeholder extension sets data-placeholder on empty nodes
		// and adds the is-editor-empty class. Check anywhere in the editor tree.
		const hasPlaceholder =
			container.querySelector('[data-placeholder="Compose email..."]') !== null ||
			container.querySelector('.is-editor-empty') !== null;
		expect(hasPlaceholder).toBe(true);
	});

	it('accepts getHTML() and getText() imperative methods', async () => {
		const { component, container } = render(RichTextEditor, {
			content: '<p>Test <em>italic</em></p>',
		});

		await waitFor(() => {
			const editor = container.querySelector('[contenteditable]');
			expect(editor).toBeTruthy();
		});

		const editor = container.querySelector('[contenteditable]')!;
		editor.innerHTML = '<p>New <strong>bold</strong></p>';
		await fireEvent.input(editor);

		// Read back via the component's imperative API
		const html = (component as any).getHTML?.();
		const text = (component as any).getText?.();
		expect(html).toContain('<strong>bold</strong>');
		expect(text).toContain('New bold');
	});

	it('setContent() replaces editor content', async () => {
		const { component, container } = render(RichTextEditor, {
			content: '<p>Original</p>',
		});

		await waitFor(() => {
			const editor = container.querySelector('[contenteditable]');
			expect(editor).toBeTruthy();
		});

		(component as any).setContent?.('<p>Replaced <em>content</em></p>');

		await waitFor(() => {
			const editor = container.querySelector('[contenteditable]')!;
			expect(editor.innerHTML).toContain('<em>content</em>');
		});
	});

	it('clearContent() empties the editor', async () => {
		const { component, container } = render(RichTextEditor, {
			content: '<p>Stuff to clear</p>',
		});

		await waitFor(() => {
			const editor = container.querySelector('[contenteditable]');
			expect(editor).toBeTruthy();
		});

		(component as any).clearContent?.();

		await waitFor(() => {
			const editor = container.querySelector('[contenteditable]')!;
			// After clearContent, editor should have empty paragraph or be empty
			const text = editor.textContent?.trim() ?? '';
			expect(text).toBe('');
		});
	});

	// -- Task 3: Template variable chips --

	it('renders template variables as styled chips', async () => {
		const { container } = render(RichTextEditor, {
			content: '<p>Hello <span data-template-var="first_name">{first_name}</span></p>',
		});
		await waitFor(() => {
			const editor = container.querySelector('[contenteditable]');
			expect(editor).toBeTruthy();
		});
		const editor = container.querySelector('[contenteditable]')!;
		// Template variables should be rendered as non-editable chips
		const vars = editor.querySelectorAll('[data-template-var]');
		expect(vars.length).toBe(1);
		expect(vars[0].getAttribute('data-template-var')).toBe('first_name');
	});

	it('resolves template variable to underlying text in getText()', async () => {
		const { component, container } = render(RichTextEditor, {
			content: '<p>Hello <span data-template-var="first_name">{first_name}</span></p>',
		});
		await waitFor(() => {
			const editor = container.querySelector('[contenteditable]');
			expect(editor).toBeTruthy();
		});
		const text = (component as any).getText?.();
		expect(text).toContain('{first_name}');
	});

	// -- Task 4: Markdown paste handling --

	it('converts markdown bold to rich text via insertMarkdown', async () => {
		const { component, container } = render(RichTextEditor, {
			content: '<p>Start</p>',
		});
		await waitFor(() => {
			const editor = container.querySelector('[contenteditable]');
			expect(editor).toBeTruthy();
		});

		// Call the imperative insertMarkdown method to simulate pasting markdown
		(component as any).insertMarkdown?.('Hello **bold** world');

		await waitFor(() => {
			const editor = container.querySelector('[contenteditable]')!;
			expect(editor.innerHTML).toContain('<strong>bold</strong>');
		});
	});

	it('converts markdown links to rich text via insertMarkdown', async () => {
		const { component, container } = render(RichTextEditor, {
			content: '<p>Start</p>',
		});
		await waitFor(() => {
			const editor = container.querySelector('[contenteditable]');
			expect(editor).toBeTruthy();
		});

		(component as any).insertMarkdown?.('Check [SetJoin](https://setjoin.com) out');

		await waitFor(() => {
			const editor = container.querySelector('[contenteditable]')!;
			expect(editor.innerHTML).toContain('href="https://setjoin.com"');
		});
	});

	// -- Task 6: inline image insert --

	it('exposes an insertImage method that adds an <img>', async () => {
		const { component, container } = render(RichTextEditor, { content: '<p>hi</p>' });
		await waitFor(() => {
			const editor = container.querySelector('[contenteditable]');
			expect(editor).toBeTruthy();
		});
		const ref = component as unknown as {
			insertImage: (src: string, alt?: string) => void;
			getHTML: () => string;
		};
		ref.insertImage('https://corp.test/logo.png', 'Logo');
		await waitFor(() => {
			expect(ref.getHTML()).toContain('<img');
			expect(ref.getHTML()).toContain('https://corp.test/logo.png');
		});
	});

	// -- Task 7: font family / text color marks --

	it('exposes setFontFamily and setTextColor imperative methods', async () => {
		const { component, container } = render(RichTextEditor, { content: '<p>style me</p>' });
		await waitFor(() => {
			const editor = container.querySelector('[contenteditable]');
			expect(editor).toBeTruthy();
		});
		const ref = component as unknown as {
			setFontFamily: (f: string) => void;
			setTextColor: (c: string) => void;
		};
		expect(typeof ref.setFontFamily).toBe('function');
		expect(typeof ref.setTextColor).toBe('function');
		// Should not throw when invoked.
		ref.setFontFamily('Georgia, serif');
		ref.setTextColor('#112233');
	});

	// -- WAVE-5 #2: inline body images --
	// handleImageFiles is the shared core handlePaste/handleDrop route through
	// (exported like insertMarkdown above) — exercised directly rather than via
	// synthetic ClipboardEvent/DragEvent (jsdom's fidelity there is the e2e
	// spec's job, in a real browser).

	function png(name = 'shot.png') {
		return new File(['x'], name, { type: 'image/png' });
	}

	it('handleImageFiles inserts a placeholder <img data-upload-id> for a staged file', async () => {
		const staged = { previewUrl: 'blob:mock-1', uploadId: 'up-1' };
		const onInlineImageFile = vi.fn(() => staged);
		const { component, container } = render(RichTextEditor, {
			content: '<p>hi</p>',
			onInlineImageFile,
		});
		await waitFor(() => expect(container.querySelector('[contenteditable]')).toBeTruthy());

		const ref = component as unknown as { handleImageFiles: (files: File[]) => boolean; getHTML: () => string };
		const file = png();
		const handled = ref.handleImageFiles([file]);

		expect(handled).toBe(true);
		expect(onInlineImageFile).toHaveBeenCalledWith(file);
		await waitFor(() => {
			expect(ref.getHTML()).toContain('data-upload-id="up-1"');
			expect(ref.getHTML()).toContain('blob:mock-1');
		});
	});

	it('forwards a file onInlineImageFile rejects (over budget / non-whitelisted) to onNonInlineFiles instead of dropping it', async () => {
		const onInlineImageFile = vi.fn(() => null); // simulates budget rejection
		const onNonInlineFiles = vi.fn();
		const { component, container } = render(RichTextEditor, {
			content: '<p>hi</p>',
			onInlineImageFile,
			onNonInlineFiles,
		});
		await waitFor(() => expect(container.querySelector('[contenteditable]')).toBeTruthy());

		const file = png('big.png');
		const ref = component as unknown as { handleImageFiles: (files: File[]) => boolean };
		const handled = ref.handleImageFiles([file]);

		expect(handled).toBe(false); // nothing inlined
		expect(onNonInlineFiles).toHaveBeenCalledWith([file]);
	});

	it('a non-image file is never routed through onInlineImageFile and is forwarded whole', async () => {
		const onInlineImageFile = vi.fn();
		const onNonInlineFiles = vi.fn();
		const { component, container } = render(RichTextEditor, {
			content: '<p>hi</p>',
			onInlineImageFile,
			onNonInlineFiles,
		});
		await waitFor(() => expect(container.querySelector('[contenteditable]')).toBeTruthy());

		const pdf = new File(['x'], 'doc.pdf', { type: 'application/pdf' });
		const ref = component as unknown as { handleImageFiles: (files: File[]) => boolean };
		ref.handleImageFiles([pdf]);

		expect(onInlineImageFile).not.toHaveBeenCalled();
		expect(onNonInlineFiles).toHaveBeenCalledWith([pdf]);
	});

	it('an SVG among whitelisted images: the PNG inlines, the SVG is forwarded — nothing is silently dropped', async () => {
		const staged = { previewUrl: 'blob:mock-2', uploadId: 'up-2' };
		const onInlineImageFile = vi.fn((f: File) => (f.type === 'image/png' ? staged : null));
		const onNonInlineFiles = vi.fn();
		const { component, container } = render(RichTextEditor, {
			content: '<p>hi</p>',
			onInlineImageFile,
			onNonInlineFiles,
		});
		await waitFor(() => expect(container.querySelector('[contenteditable]')).toBeTruthy());

		const svg = new File(['x'], 'evil.svg', { type: 'image/svg+xml' });
		const goodPng = png();
		const ref = component as unknown as { handleImageFiles: (files: File[]) => boolean; getHTML: () => string };
		const handled = ref.handleImageFiles([svg, goodPng]);

		expect(handled).toBe(true);
		expect(onNonInlineFiles).toHaveBeenCalledWith([svg]);
		await waitFor(() => expect(ref.getHTML()).toContain('data-upload-id="up-2"'));
	});

	it('removeInlineImage deletes the matching <img> node from the body (no-op if already gone)', async () => {
		const staged = { previewUrl: 'blob:mock-3', uploadId: 'up-3' };
		const { component, container } = render(RichTextEditor, {
			content: '<p>hi</p>',
			onInlineImageFile: () => staged,
		});
		await waitFor(() => expect(container.querySelector('[contenteditable]')).toBeTruthy());

		const ref = component as unknown as {
			handleImageFiles: (files: File[]) => boolean;
			removeInlineImage: (id: string) => void;
			getHTML: () => string;
		};
		ref.handleImageFiles([png()]);
		await waitFor(() => expect(ref.getHTML()).toContain('data-upload-id="up-3"'));

		ref.removeInlineImage('up-3');
		await waitFor(() => expect(ref.getHTML()).not.toContain('up-3'));

		// Already gone — must not throw.
		expect(() => ref.removeInlineImage('up-3')).not.toThrow();
	});

	it('shows the upload overlay only while the tracked chip is preparing/uploading, not once done', async () => {
		const staged = { previewUrl: 'blob:mock-4', uploadId: 'up-4' };
		const { component, container, rerender } = render(RichTextEditor, {
			content: '<p>hi</p>',
			onInlineImageFile: () => staged,
			inlineUploads: [{ uploadId: 'up-4', status: 'uploading', progress: 40 }],
		});
		await waitFor(() => expect(container.querySelector('[contenteditable]')).toBeTruthy());

		const ref = component as unknown as { handleImageFiles: (files: File[]) => boolean };
		ref.handleImageFiles([png()]);

		await waitFor(() => {
			const overlay = container.querySelector('[data-testid="inline-img-overlay"]');
			expect(overlay).toBeTruthy();
			expect(overlay?.textContent).toContain('40%');
		});

		await rerender({ inlineUploads: [{ uploadId: 'up-4', status: 'done', progress: 100 }] });
		expect(container.querySelector('[data-testid="inline-img-overlay"]')).toBeNull();
	});

	it('fires ready, focus, and blur callbacks and exposes focus/getEditor safely', async () => {
		const onEditorReady = vi.fn();
		const onFocus = vi.fn();
		const onBlur = vi.fn();
		const { component, container } = render(RichTextEditor, { onEditorReady, onFocus, onBlur });
		await waitFor(() => expect(onEditorReady).toHaveBeenCalledOnce());
		const ref = component as unknown as { getEditor: () => any; focus: () => void };
		expect(ref.getEditor()).toBe(onEditorReady.mock.calls[0][0]);
		ref.focus();
		await waitFor(() => expect(onFocus).toHaveBeenCalled());
		ref.getEditor().commands.blur();
		await waitFor(() => expect(onBlur).toHaveBeenCalled());
		expect(container.querySelector('[contenteditable]')).toBeInTheDocument();
	});

	it('converts every supported markdown form and preserves paragraph/line boundaries', async () => {
		const { component, container } = render(RichTextEditor, { content: '' });
		await waitFor(() => expect(container.querySelector('[contenteditable]')).toBeTruthy());
		const ref = component as unknown as { insertMarkdown: (text: string) => void; getHTML: () => string };
		ref.insertMarkdown('__bold__ *star* _under_ `code`\nline\n\nnext');
		await waitFor(() => {
			const html = ref.getHTML();
			expect(html).toContain('<strong>bold</strong>');
			expect(html).toContain('<em>star</em>');
			expect(html).toContain('<em>under</em>');
			expect(html).toContain('<code>code</code>');
			expect(html).toContain('line');
			expect(html).toContain('next');
		});
	});

	it('inserts staged image nodes at an explicit document position', async () => {
		const { component, container } = render(RichTextEditor, {
			content: '<p>before after</p>',
			onInlineImageFile: () => ({ previewUrl: 'blob:at-pos', uploadId: 'pos-1' }),
		});
		await waitFor(() => expect(container.querySelector('[contenteditable]')).toBeTruthy());
		const ref = component as unknown as { handleImageFiles: (files: File[], atPos?: number) => boolean; getHTML: () => string };
		expect(ref.handleImageFiles([png()], 2)).toBe(true);
		await waitFor(() => expect(ref.getHTML()).toContain('data-upload-id="pos-1"'));
	});

	it('routes paste variants without swallowing normal text, HTML, or file-only payloads', async () => {
		const onNonInlineFiles = vi.fn();
		const { component, container } = render(RichTextEditor, { content: '', onNonInlineFiles });
		await waitFor(() => expect(container.querySelector('[contenteditable]')).toBeTruthy());
		const editor = (component as unknown as { getEditor: () => any }).getEditor();
		const handlePaste = editor.options.editorProps.handlePaste as (...args: any[]) => boolean;
		const event = (clipboardData: any) => ({ clipboardData, preventDefault: vi.fn(), stopPropagation: vi.fn() });

		expect(handlePaste(editor.view, event(null))).toBe(false);
		expect(handlePaste(editor.view, event({ files: [], types: ['text/html'], getData: () => '<b>x</b>' }))).toBe(false);
		expect(handlePaste(editor.view, event({ files: [], types: ['Files'], getData: () => '' }))).toBe(false);
		expect(handlePaste(editor.view, event({ files: [], types: ['text/plain'], getData: () => '' }))).toBe(false);
		expect(handlePaste(editor.view, event({ files: [], types: ['text/plain'], getData: () => 'ordinary text' }))).toBe(false);

		const markdownEvent = event({ files: [], types: ['text/plain'], getData: () => '**paste bold**' });
		expect(handlePaste(editor.view, markdownEvent)).toBe(true);
		expect(markdownEvent.preventDefault).toHaveBeenCalledOnce();
		await waitFor(() => expect(editor.getHTML()).toContain('<strong>paste bold</strong>'));
	});

	it('owns image pastes, forwards leftovers, and never double-attaches them', async () => {
		const pdf = new File(['x'], 'doc.pdf', { type: 'application/pdf' });
		const image = png('paste.png');
		const onNonInlineFiles = vi.fn();
		const { component, container } = render(RichTextEditor, {
			content: '',
			onInlineImageFile: () => ({ previewUrl: 'blob:paste', uploadId: 'paste-1' }),
			onNonInlineFiles,
		});
		await waitFor(() => expect(container.querySelector('[contenteditable]')).toBeTruthy());
		const editor = (component as unknown as { getEditor: () => any }).getEditor();
		const handlePaste = editor.options.editorProps.handlePaste as (...args: any[]) => boolean;
		const event = { clipboardData: { files: [image, pdf], types: ['Files'], getData: () => '' }, preventDefault: vi.fn(), stopPropagation: vi.fn() };
		expect(handlePaste(editor.view, event)).toBe(true);
		expect(event.preventDefault).toHaveBeenCalledOnce();
		expect(event.stopPropagation).toHaveBeenCalledOnce();
		expect(onNonInlineFiles).toHaveBeenCalledWith([pdf]);
		await waitFor(() => expect(editor.getHTML()).toContain('paste-1'));
	});

	it('routes external image drops at the resolved position and ignores moved or non-image drops', async () => {
		const { component, container } = render(RichTextEditor, {
			content: '<p>drop here</p>',
			onInlineImageFile: () => ({ previewUrl: 'blob:drop', uploadId: 'drop-1' }),
		});
		await waitFor(() => expect(container.querySelector('[contenteditable]')).toBeTruthy());
		const editor = (component as unknown as { getEditor: () => any }).getEditor();
		const handleDrop = editor.options.editorProps.handleDrop as (...args: any[]) => boolean;
		const makeEvent = (files: File[]) => ({ dataTransfer: { files }, clientX: 1, clientY: 2, preventDefault: vi.fn(), stopPropagation: vi.fn() });
		const view = { posAtCoords: vi.fn(() => ({ pos: 2 })) };
		expect(handleDrop(view, makeEvent([png()]), null, true)).toBe(false);
		expect(handleDrop(view, makeEvent([new File(['x'], 'doc.txt', { type: 'text/plain' })]), null, false)).toBe(false);
		const dropped = makeEvent([png()]);
		expect(handleDrop(view, dropped, null, false)).toBe(true);
		expect(view.posAtCoords).toHaveBeenCalledWith({ left: 1, top: 2 });
		expect(dropped.preventDefault).toHaveBeenCalledOnce();
		expect(dropped.stopPropagation).toHaveBeenCalledOnce();
		await waitFor(() => expect(editor.getHTML()).toContain('drop-1'));
	});

	it('drives the mention popup lifecycle, keyboard wraparound, selection, and exit', async () => {
		const onMentionPick = vi.fn();
		const { component, container } = render(RichTextEditor, { content: '', onMentionPick });
		await waitFor(() => expect(container.querySelector('[contenteditable]')).toBeTruthy());
		const editor = (component as unknown as { getEditor: () => any }).getEditor();
		const mention = editor.extensionManager.extensions.find((extension: any) => extension.name === 'mention');
		expect(mention).toBeTruthy();
		const lifecycle = mention.options.suggestion.render();
		const command = vi.fn();
		const rect = new DOMRect(10, 20, 30, 40);
		const items = [
			{ id: '1', label: 'Alice', email: 'alice@example.test' },
			{ id: '2', label: 'Bob', email: 'bob@example.test' },
		];
		lifecycle.onStart({ items: [], command, clientRect: undefined });
		expect(screen.queryByRole('listbox')).toBeNull();
		lifecycle.onUpdate({ items, command, clientRect: () => rect });
		await waitFor(() => expect(screen.getByRole('listbox')).toBeInTheDocument());
		expect(screen.getByText('Alice')).toBeInTheDocument();
		expect(lifecycle.onKeyDown({ event: new KeyboardEvent('keydown', { key: 'x' }) })).toBe(false);
		expect(lifecycle.onKeyDown({ event: new KeyboardEvent('keydown', { key: 'ArrowDown' }) })).toBe(true);
		await waitFor(() => expect(screen.getByRole('option', { name: /Bob/ })).toHaveAttribute('aria-selected', 'true'));
		expect(lifecycle.onKeyDown({ event: new KeyboardEvent('keydown', { key: 'ArrowDown' }) })).toBe(true);
		await waitFor(() => expect(screen.getByRole('option', { name: /Alice/ })).toHaveAttribute('aria-selected', 'true'));
		expect(lifecycle.onKeyDown({ event: new KeyboardEvent('keydown', { key: 'ArrowUp' }) })).toBe(true);
		expect(lifecycle.onKeyDown({ event: new KeyboardEvent('keydown', { key: 'Enter' }) })).toBe(true);
		expect(command).toHaveBeenCalledWith(items[1]);
		await fireEvent.mouseDown(screen.getByRole('option', { name: /Alice/ }));
		expect(command).toHaveBeenCalledWith(items[0]);
		expect(lifecycle.onKeyDown({ event: new KeyboardEvent('keydown', { key: 'Escape' }) })).toBe(true);
		await waitFor(() => expect(screen.queryByRole('listbox')).toBeNull());
		expect(lifecycle.onKeyDown({ event: new KeyboardEvent('keydown', { key: 'Enter' }) })).toBe(false);

		lifecycle.onStart({ items: [], command, clientRect: () => rect });
		await waitFor(() => expect(screen.getByRole('listbox')).toBeInTheDocument());
		expect(lifecycle.onKeyDown({ event: new KeyboardEvent('keydown', { key: 'Enter' }) })).toBe(false);
		lifecycle.onExit();
		await waitFor(() => expect(screen.queryByRole('listbox')).toBeNull());
	});
});
