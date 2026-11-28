import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent, screen } from '@testing-library/svelte/svelte5';
import { createRawSnippet } from 'svelte';
import Select from './Select.svelte';

describe('Select', () => {
	it('renders string options with value equal to label', () => {
		render(Select, {
			props: { label: 'Snooze until', options: ['Later today', 'Tomorrow morning'] }
		});
		const select = screen.getByLabelText('Snooze until') as HTMLSelectElement;
		expect(select.tagName).toBe('SELECT');
		expect(select.options.length).toBe(2);
		expect(select.options[0].value).toBe('Later today');
		expect(select.options[0].textContent).toBe('Later today');
	});

	it('renders object options with distinct value and label', () => {
		render(Select, {
			props: {
				label: 'Role',
				value: 'super_admin',
				options: [
					{ value: 'super_admin', label: 'Super admin' },
					{ value: 'auditor', label: 'Auditor' }
				]
			}
		});
		const select = screen.getByLabelText('Role') as HTMLSelectElement;
		expect(select.options[1].value).toBe('auditor');
		expect(select.options[1].textContent).toBe('Auditor');
	});

	it('updates bound value on change and forwards onchange', async () => {
		const onchange = vi.fn();
		render(Select, {
			props: {
				label: 'Role',
				value: 'super_admin',
				onchange,
				options: [
					{ value: 'super_admin', label: 'Super admin' },
					{ value: 'auditor', label: 'Auditor' }
				]
			}
		});
		const select = screen.getByLabelText('Role') as HTMLSelectElement;
		expect(select.value).toBe('super_admin');
		await fireEvent.change(select, { target: { value: 'auditor' } });
		expect(select.value).toBe('auditor');
		expect(onchange).toHaveBeenCalledTimes(1);
	});

	it('falls back to option children when options is empty', () => {
		const children = createRawSnippet(() => ({
			render: () => `<option value="x">X option</option>`
		}));
		render(Select, { props: { label: 'Custom', children } });
		const select = screen.getByLabelText('Custom') as HTMLSelectElement;
		expect(select.options.length).toBe(1);
		expect(select.options[0].value).toBe('x');
	});

	it('renders the decorative caret and forwards disabled', () => {
		const { container } = render(Select, {
			props: { label: 'Role', disabled: true, options: ['Auditor'] }
		});
		expect(container.querySelector('.sj-select-caret')).not.toBeNull();
		expect(screen.getByLabelText('Role')).toBeDisabled();
	});
});
