import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent, screen } from '@testing-library/svelte/svelte5';
import Input from './Input.svelte';

describe('Input', () => {
	it('associates the label with the input via for/id', () => {
		render(Input, { props: { label: 'Display name' } });
		const input = screen.getByLabelText('Display name');
		expect(input.tagName).toBe('INPUT');
		expect(input.id).not.toBe('');
	});

	it('updates value and forwards oninput', async () => {
		const oninput = vi.fn();
		render(Input, { props: { label: 'Display name', oninput } });
		const input = screen.getByLabelText('Display name') as HTMLInputElement;
		await fireEvent.input(input, { target: { value: 'Lena' } });
		expect(input.value).toBe('Lena');
		expect(oninput).toHaveBeenCalledTimes(1);
	});

	it('shows the hint and links it via aria-describedby', () => {
		render(Input, { props: { label: 'IMAP host', hint: 'e.g. imap.gmail.com' } });
		const input = screen.getByLabelText('IMAP host');
		const hint = screen.getByText('e.g. imap.gmail.com');
		expect(hint.id).toBe(`${input.id}-hint`);
		expect(input).toHaveAttribute('aria-describedby', hint.id);
	});

	it('error replaces hint and switches the input to the error state', () => {
		render(Input, {
			props: {
				label: 'Password',
				hint: 'At least 12 characters',
				error: 'Wrong password. 2 attempts left.'
			}
		});
		const input = screen.getByLabelText('Password');
		expect(screen.getByText('Wrong password. 2 attempts left.')).toBeInTheDocument();
		expect(screen.queryByText('At least 12 characters')).toBeNull();
		expect(input.classList.contains('sj-input--error')).toBe(true);
		expect(input).toHaveAttribute('aria-invalid', 'true');
		expect(input).toHaveAttribute('aria-describedby', `${input.id}-error`);
	});

	it('applies lg and mono classes', () => {
		render(Input, { props: { label: 'IMAP host', size: 'lg', mono: true } });
		const input = screen.getByLabelText('IMAP host');
		expect(input.classList.contains('sj-input--lg')).toBe(true);
		expect(input.classList.contains('sj-input--mono')).toBe(true);
	});

	it('forwards native attributes (disabled, placeholder, type)', () => {
		render(Input, {
			props: { label: 'Password', type: 'password', disabled: true, placeholder: 'Required' }
		});
		const input = screen.getByLabelText('Password');
		expect(input).toBeDisabled();
		expect(input).toHaveAttribute('placeholder', 'Required');
		expect(input).toHaveAttribute('type', 'password');
	});
});
