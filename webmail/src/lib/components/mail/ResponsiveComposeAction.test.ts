import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render } from '@testing-library/svelte/svelte5';
import ResponsiveComposeAction from './ResponsiveComposeAction.svelte';

describe('ResponsiveComposeAction', () => {
	it('renders tablet and mobile variants with the same localized tour anchor', () => {
		const { container } = render(ResponsiveComposeAction, { onCompose: vi.fn() });
		const anchors = container.querySelectorAll<HTMLButtonElement>('button[data-tour="compose"]');
		expect(anchors).toHaveLength(2);
		expect([...anchors].map((button) => button.getAttribute('aria-label'))).toEqual([
			'Compose',
			'Compose',
		]);
		expect(anchors[0].textContent?.trim()).toBe('Compose');
	});

	it('routes both visible variants through one compose callback', async () => {
		const onCompose = vi.fn();
		const { container } = render(ResponsiveComposeAction, { onCompose });
		for (const button of container.querySelectorAll<HTMLButtonElement>('button')) {
			await fireEvent.click(button);
		}
		expect(onCompose).toHaveBeenCalledTimes(2);
	});

	it('applies the shared read-only disabled state and explanation to both variants', () => {
		const { container } = render(ResponsiveComposeAction, {
			onCompose: vi.fn(),
			disabled: true,
			disabledReason: 'Read-only mailbox',
		});
		const buttons = container.querySelectorAll<HTMLButtonElement>('button');
		expect(buttons).toHaveLength(2);
		for (const button of buttons) {
			expect(button.disabled).toBe(true);
			expect(button.title).toBe('Read-only mailbox');
		}
	});
});
