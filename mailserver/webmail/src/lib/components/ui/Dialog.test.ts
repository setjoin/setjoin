import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import { createRawSnippet } from 'svelte';
import Dialog from './Dialog.svelte';

const body = createRawSnippet(() => ({ render: () => '<p>Body text</p>' }));
const footerButtons = createRawSnippet(() => ({
	render: () => '<div><button>Cancel</button><button>Save</button></div>'
}));

describe('Dialog', () => {
	it('renders title, body and footer when open', () => {
		render(Dialog, { open: true, title: 'Delete message', children: body, footer: footerButtons });
		expect(screen.getByRole('dialog')).toBeTruthy();
		expect(screen.getByText('Delete message')).toBeTruthy();
		expect(screen.getByText('Body text')).toBeTruthy();
		expect(screen.getByText('Save')).toBeTruthy();
	});

	it('renders nothing when open is false', () => {
		render(Dialog, { open: false, title: 'Hidden', children: body });
		expect(screen.queryByRole('dialog')).toBeNull();
	});

	it('labels the dialog with the title element via aria-labelledby', () => {
		render(Dialog, { open: true, title: 'Rename folder', children: body });
		const dialog = screen.getByRole('dialog');
		expect(dialog.getAttribute('aria-modal')).toBe('true');
		const labelId = dialog.getAttribute('aria-labelledby');
		expect(labelId).toBeTruthy();
		const titleEl = document.getElementById(labelId!);
		expect(titleEl?.textContent).toBe('Rename folder');
	});

	it('calls onClose on Escape', async () => {
		const onClose = vi.fn();
		render(Dialog, { open: true, title: 'T', onClose, children: body });
		await fireEvent.keyDown(document, { key: 'Escape' });
		expect(onClose).toHaveBeenCalledTimes(1);
	});

	it('closes on backdrop mousedown but not on dialog mousedown', async () => {
		const onClose = vi.fn();
		const { container } = render(Dialog, { open: true, title: 'T', onClose, children: body });
		await fireEvent.mouseDown(screen.getByRole('dialog'));
		expect(onClose).not.toHaveBeenCalled();
		const backdrop = container.querySelector('.sj-dialog-backdrop')!;
		await fireEvent.mouseDown(backdrop);
		expect(onClose).toHaveBeenCalledTimes(1);
	});

	it('calls onClose from the close button', async () => {
		const onClose = vi.fn();
		render(Dialog, { open: true, title: 'T', onClose, children: body });
		await fireEvent.click(screen.getByLabelText('Close'));
		expect(onClose).toHaveBeenCalledTimes(1);
	});

	it('moves focus to the dialog on open and returns it on close', async () => {
		const outside = document.createElement('button');
		outside.textContent = 'outside';
		document.body.appendChild(outside);
		outside.focus();
		const { rerender } = render(Dialog, { open: true, title: 'T', children: body });
		expect(document.activeElement).toBe(screen.getByRole('dialog'));
		await rerender({ open: false });
		expect(document.activeElement).toBe(outside);
		outside.remove();
	});

	it('traps Tab focus within the dialog', async () => {
		render(Dialog, {
			open: true,
			title: 'T',
			onClose: vi.fn(),
			children: body,
			footer: footerButtons
		});
		// Document order: [Close (head), Cancel, Save (footer)]
		const buttons = screen.getAllByRole('button');
		const first = buttons[0];
		const last = buttons[buttons.length - 1];
		last.focus();
		await fireEvent.keyDown(document, { key: 'Tab' });
		expect(document.activeElement).toBe(first);
		await fireEvent.keyDown(document, { key: 'Tab', shiftKey: true });
		expect(document.activeElement).toBe(last);
	});

	it('applies the wide variant class', () => {
		const { container } = render(Dialog, { open: true, title: 'T', wide: true, children: body });
		expect(container.querySelector('.sj-dialog--wide')).toBeTruthy();
	});
});
