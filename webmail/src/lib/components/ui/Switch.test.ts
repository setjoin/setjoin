import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent, screen } from '@testing-library/svelte/svelte5';
import Switch from './Switch.svelte';

describe('Switch', () => {
	it('exposes role switch with aria-checked in sync', async () => {
		render(Switch, { props: { label: 'IMAP' } });
		const input = screen.getByRole('switch');
		expect(input).toHaveAttribute('aria-checked', 'false');
		await fireEvent.click(input);
		expect(input).toHaveAttribute('aria-checked', 'true');
	});

	it('toggles checked on click and forwards onchange', async () => {
		const onchange = vi.fn();
		render(Switch, { props: { label: 'IMAP', onchange } });
		const input = screen.getByRole('switch') as HTMLInputElement;
		expect(input.checked).toBe(false);
		await fireEvent.click(input);
		expect(input.checked).toBe(true);
		expect(onchange).toHaveBeenCalledTimes(1);
	});

	it('renders label and description', () => {
		render(Switch, {
			props: { label: 'IMAP', description: 'Disable to free memory if everyone uses JMAP' }
		});
		expect(screen.getByText('IMAP')).toBeInTheDocument();
		expect(
			screen.getByText('Disable to free memory if everyone uses JMAP')
		).toBeInTheDocument();
	});

	it('applies the on class to the root when checked', async () => {
		const { container } = render(Switch, { props: { label: 'IMAP', checked: true } });
		expect(container.querySelector('label.sj-switch--on')).not.toBeNull();
	});

	it('renders track and thumb elements', () => {
		const { container } = render(Switch, { props: { label: 'IMAP' } });
		expect(container.querySelector('.sj-switch__track')).not.toBeNull();
		expect(container.querySelector('.sj-switch__thumb')).not.toBeNull();
	});

	it('does not toggle or fire onchange when disabled', async () => {
		const onchange = vi.fn();
		const { container } = render(Switch, { props: { label: 'IMAP', disabled: true, onchange } });
		const input = screen.getByRole('switch') as HTMLInputElement;
		expect(container.querySelector('label.sj-switch--disabled')).not.toBeNull();
		await fireEvent.click(input);
		expect(input.checked).toBe(false);
		expect(onchange).not.toHaveBeenCalled();
	});
});
