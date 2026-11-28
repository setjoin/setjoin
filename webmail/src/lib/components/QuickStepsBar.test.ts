import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte/svelte5';
import QuickStepsBar from './QuickStepsBar.svelte';
import type { QuickStep } from '$lib/types/jmap';

function step(id: string, name: string): QuickStep {
	return { id, name, icon: 'Zap', position: 0, actions: [{ type: 'mark_read' }] };
}

describe('QuickStepsBar (A2)', () => {
	it('renders a button per quick step', () => {
		const { getByText } = render(QuickStepsBar, {
			props: { quickSteps: [step('1', 'File receipt'), step('2', 'To team')], onApply: vi.fn() },
		});
		expect(getByText('File receipt')).toBeTruthy();
		expect(getByText('To team')).toBeTruthy();
	});

	it('forwards the quick-step id to onApply when clicked', async () => {
		const onApply = vi.fn();
		const { getByText } = render(QuickStepsBar, {
			props: { quickSteps: [step('42', 'Archive it')], onApply },
		});
		await fireEvent.click(getByText('Archive it'));
		expect(onApply).toHaveBeenCalledWith('42');
	});

	it('renders nothing when there are no quick steps', () => {
		const { container } = render(QuickStepsBar, { props: { quickSteps: [], onApply: vi.fn() } });
		expect(container.querySelector('.sj-quicksteps')).toBeNull();
	});

	it('disables the running quick step button', () => {
		const { getByText } = render(QuickStepsBar, {
			props: { quickSteps: [step('7', 'Running one')], onApply: vi.fn(), applying: '7' },
		});
		const btn = getByText('Running one').closest('button') as HTMLButtonElement;
		expect(btn.disabled).toBe(true);
	});
});
