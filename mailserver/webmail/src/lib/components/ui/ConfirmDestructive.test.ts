import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import ConfirmDestructive from './ConfirmDestructive.svelte';

function props(overrides: Partial<Record<string, unknown>> = {}) {
	return {
		open: true,
		title: 'Destroy the thing',
		message: 'This destroys 5 things across 2 places.',
		confirmWord: 'DESTROY',
		confirmLabel: 'Destroy',
		onConfirm: vi.fn(),
		onCancel: vi.fn(),
		...overrides,
	};
}

describe('ConfirmDestructive', () => {
	it('renders nothing when open is false', () => {
		render(ConfirmDestructive, props({ open: false }));
		expect(screen.queryByRole('dialog')).toBeNull();
	});

	it('shows the message and keeps the confirm button disabled until the exact word is typed', async () => {
		render(ConfirmDestructive, props());
		expect(screen.getByText('This destroys 5 things across 2 places.')).toBeTruthy();
		const confirmBtn = screen.getByText('Destroy', { selector: 'button' }) as HTMLButtonElement;
		expect(confirmBtn.disabled).toBe(true);

		const input = screen.getByLabelText(/type DESTROY to confirm/i);
		await fireEvent.input(input, { target: { value: 'DESTR' } });
		expect(confirmBtn.disabled).toBe(true);

		await fireEvent.input(input, { target: { value: 'DESTROY' } });
		expect(confirmBtn.disabled).toBe(false);
	});

	it('calls onConfirm only once the typed word matches, and onCancel from the Cancel button', async () => {
		const onConfirm = vi.fn();
		const onCancel = vi.fn();
		render(ConfirmDestructive, props({ onConfirm, onCancel }));

		const confirmBtn = screen.getByText('Destroy', { selector: 'button' });
		await fireEvent.click(confirmBtn); // disabled — no-op
		expect(onConfirm).not.toHaveBeenCalled();

		await fireEvent.input(screen.getByLabelText(/type DESTROY to confirm/i), { target: { value: 'DESTROY' } });
		await fireEvent.click(confirmBtn);
		expect(onConfirm).toHaveBeenCalledTimes(1);

		await fireEvent.click(screen.getByText('Cancel'));
		expect(onCancel).toHaveBeenCalledTimes(1);
	});

	it('supports a channel-name confirm word (not just the literal DESTROY)', async () => {
		render(ConfirmDestructive, props({ confirmWord: 'general', message: 'Upgrade #general to Records (WORM).' }));
		const confirmBtn = screen.getByText('Destroy', { selector: 'button' }) as HTMLButtonElement;
		await fireEvent.input(screen.getByLabelText(/type general to confirm/i), { target: { value: 'DESTROY' } });
		expect(confirmBtn.disabled).toBe(true); // wrong word for this instance
		await fireEvent.input(screen.getByLabelText(/type general to confirm/i), { target: { value: 'general' } });
		expect(confirmBtn.disabled).toBe(false);
	});

	it('resets the typed value on every re-open', async () => {
		const { rerender } = render(ConfirmDestructive, props());
		await fireEvent.input(screen.getByLabelText(/type DESTROY to confirm/i), { target: { value: 'DESTROY' } });
		expect((screen.getByText('Destroy', { selector: 'button' }) as HTMLButtonElement).disabled).toBe(false);

		await rerender(props({ open: false }));
		await rerender(props({ open: true }));
		expect((screen.getByText('Destroy', { selector: 'button' }) as HTMLButtonElement).disabled).toBe(true);
	});
});
