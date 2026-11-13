import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import Textarea from './Textarea.svelte';

describe('Textarea', () => {
	it('renders the label and associates it with the textarea', () => {
		render(Textarea, { label: 'Vacation message' });
		const el = screen.getByLabelText('Vacation message');
		expect(el.tagName).toBe('TEXTAREA');
	});

	it('renders the initial value and updates on input', async () => {
		render(Textarea, { label: 'Notes', value: 'draft' });
		const el = screen.getByLabelText('Notes') as HTMLTextAreaElement;
		expect(el.value).toBe('draft');
		await fireEvent.input(el, { target: { value: 'updated draft' } });
		expect(el.value).toBe('updated draft');
	});

	it('shows the hint when there is no error', () => {
		render(Textarea, { label: 'Notes', hint: 'Plain text only' });
		expect(screen.getByText('Plain text only')).toBeTruthy();
	});

	it('shows the error instead of the hint', () => {
		render(Textarea, { label: 'Notes', hint: 'Plain text only', error: 'Message is too long.' });
		expect(screen.getByText('Message is too long.')).toBeTruthy();
		expect(screen.queryByText('Plain text only')).toBeNull();
	});

	it('applies the error border class', () => {
		const { container } = render(Textarea, { label: 'Notes', error: 'Required.' });
		expect(container.querySelector('.textarea--error')).not.toBeNull();
	});

	it('passes through disabled, placeholder, rows and maxlength', () => {
		render(Textarea, { label: 'Notes', disabled: true, placeholder: 'Type here', rows: 5, maxlength: 200 });
		const el = screen.getByLabelText('Notes') as HTMLTextAreaElement;
		expect(el.disabled).toBe(true);
		expect(el.placeholder).toBe('Type here');
		expect(el.rows).toBe(5);
		expect(el.maxLength).toBe(200);
	});

	it('forwards oninput callback', async () => {
		const oninput = vi.fn();
		render(Textarea, { label: 'Notes', oninput });
		const el = screen.getByLabelText('Notes') as HTMLTextAreaElement;
		await fireEvent.input(el, { target: { value: 'hello' } });
		expect(oninput).toHaveBeenCalledTimes(1);
	});

	it('sets aria-invalid when error is non-empty', () => {
		render(Textarea, { label: 'Notes', error: 'Required.' });
		const el = screen.getByLabelText('Notes');
		expect(el).toHaveAttribute('aria-invalid', 'true');
	});

	it('links hint via aria-describedby', () => {
		render(Textarea, { label: 'Notes', hint: 'Plain text only' });
		const el = screen.getByLabelText('Notes');
		const hint = screen.getByText('Plain text only');
		expect(hint.id).toBe(`${el.id}-hint`);
		expect(el).toHaveAttribute('aria-describedby', hint.id);
	});

	it('links error via aria-describedby and aria-invalid', () => {
		render(Textarea, { label: 'Notes', hint: 'Plain text only', error: 'Message is too long.' });
		const el = screen.getByLabelText('Notes');
		const errorEl = screen.getByText('Message is too long.');
		expect(errorEl.id).toBe(`${el.id}-error`);
		expect(el).toHaveAttribute('aria-describedby', errorEl.id);
		expect(el).toHaveAttribute('aria-invalid', 'true');
	});
});
