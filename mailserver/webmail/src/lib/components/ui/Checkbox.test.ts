import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent, screen } from '@testing-library/svelte/svelte5';
import { tick } from 'svelte';
import Checkbox from './Checkbox.svelte';

describe('Checkbox', () => {
	it('renders a native checkbox associated with its label text', () => {
		render(Checkbox, { props: { label: 'Remember this device for 30 days' } });
		const input = screen.getByLabelText('Remember this device for 30 days');
		expect(input).toHaveAttribute('type', 'checkbox');
	});

	it('toggles checked on click and forwards onchange', async () => {
		const onchange = vi.fn();
		render(Checkbox, { props: { label: 'Remember', onchange } });
		const input = screen.getByRole('checkbox') as HTMLInputElement;
		expect(input.checked).toBe(false);
		await fireEvent.click(input);
		expect(input.checked).toBe(true);
		expect(onchange).toHaveBeenCalledTimes(1);
	});

	it('sets the native indeterminate property (not just the drawn dash)', async () => {
		render(Checkbox, { props: { indeterminate: true } });
		await tick();
		const input = screen.getByRole('checkbox') as HTMLInputElement;
		expect(input.indeterminate).toBe(true);
	});

	it('clears the native indeterminate property when the prop turns false', async () => {
		const { rerender } = render(Checkbox, { props: { indeterminate: true } });
		await tick();
		const input = screen.getByRole('checkbox') as HTMLInputElement;
		expect(input.indeterminate).toBe(true);
		await rerender({ indeterminate: false });
		await tick();
		expect(input.indeterminate).toBe(false);
	});

	it('draws the dash icon when indeterminate and the check icon when checked', async () => {
		const a = render(Checkbox, { props: { indeterminate: true } });
		expect(a.container.querySelector('.sj-check__box svg path')?.getAttribute('d')).toBe(
			'M5 12h14'
		);
		expect(a.container.querySelector('label.sj-check--on')).not.toBeNull();
		a.unmount();

		const b = render(Checkbox, { props: { checked: true } });
		expect(b.container.querySelector('.sj-check__box svg path')?.getAttribute('d')).toBe(
			'M20 6 9 17l-5-5'
		);
		expect(b.container.querySelector('label.sj-check--on')).not.toBeNull();
	});

	it('does not toggle or fire onchange when disabled', async () => {
		const onchange = vi.fn();
		const { container } = render(Checkbox, {
			props: { label: 'Remember', disabled: true, onchange }
		});
		const input = screen.getByRole('checkbox') as HTMLInputElement;
		expect(container.querySelector('label.sj-check--disabled')).not.toBeNull();
		await fireEvent.click(input);
		expect(input.checked).toBe(false);
		expect(onchange).not.toHaveBeenCalled();
	});
});
