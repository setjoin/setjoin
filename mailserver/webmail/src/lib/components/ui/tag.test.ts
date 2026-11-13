import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import { TAG_COLORS, splitTagPath } from './tag';
import Tag from './Tag.svelte';

describe('TAG_COLORS', () => {
	it('lists exactly the 8 system hues in picker order', () => {
		expect(TAG_COLORS).toEqual([
			'blue',
			'teal',
			'green',
			'amber',
			'orange',
			'rose',
			'purple',
			'gray'
		]);
	});
});

describe('splitTagPath', () => {
	it('returns a single segment for a flat label', () => {
		expect(splitTagPath('Finance')).toEqual(['Finance']);
	});

	it('splits nested labels on slashes', () => {
		expect(splitTagPath('Finance/Invoices')).toEqual(['Finance', 'Invoices']);
	});

	it('drops empty segments from stray slashes', () => {
		expect(splitTagPath('/Finance//Invoices/')).toEqual(['Finance', 'Invoices']);
	});

	it('returns an empty array for an empty label', () => {
		expect(splitTagPath('')).toEqual([]);
	});
});

describe('Tag', () => {
	it('renders the label', () => {
		render(Tag, { label: 'Finance' });
		expect(screen.getByText('Finance')).toBeTruthy();
	});

	it('renders no buttons when neither onclick nor onremove is set', () => {
		const { container } = render(Tag, { label: 'Finance' });
		expect(container.querySelectorAll('button').length).toBe(0);
	});

	it('renders the hue dot by default and hides it when dot is false', () => {
		const withDot = render(Tag, { label: 'Finance', color: 'blue' });
		expect(withDot.container.querySelector('.tag__dot')).not.toBeNull();
		withDot.unmount();
		const withoutDot = render(Tag, { label: 'Finance', dot: false });
		expect(withoutDot.container.querySelector('.tag__dot')).toBeNull();
	});

	it('calls onclick when the chip body is clicked', async () => {
		const onclick = vi.fn();
		render(Tag, { label: 'Personal', onclick });
		await fireEvent.click(screen.getByRole('button', { name: 'Personal' }));
		expect(onclick).toHaveBeenCalledTimes(1);
	});

	it('calls onremove when the remove button is clicked', async () => {
		const onremove = vi.fn();
		render(Tag, { label: 'Infra', onremove });
		await fireEvent.click(screen.getByRole('button', { name: 'Remove tag Infra' }));
		expect(onremove).toHaveBeenCalledTimes(1);
	});

	it('renders sibling buttons, never nested, when both onclick and onremove are set', async () => {
		const onclick = vi.fn();
		const onremove = vi.fn();
		const { container } = render(Tag, { label: 'Infra', onclick, onremove });
		expect(container.querySelector('button button')).toBeNull();
		expect(container.querySelectorAll('button').length).toBe(2);
		await fireEvent.click(screen.getByRole('button', { name: 'Remove tag Infra' }));
		expect(onremove).toHaveBeenCalledTimes(1);
		expect(onclick).not.toHaveBeenCalled();
	});

	it('renders nested tag paths as breadcrumb segments', () => {
		const { container } = render(Tag, { label: 'Finance/Invoices' });
		const text = container.querySelector('.tag__text');
		expect(text?.textContent).toBe('Finance/Invoices');
		expect(container.querySelectorAll('.tag__sep').length).toBe(1);
	});

	it('applies the hue tokens as inline styles', () => {
		const { container } = render(Tag, { label: 'Finance', color: 'teal' });
		const chip = container.querySelector('.tag') as HTMLElement;
		expect(chip.getAttribute('style')).toContain('var(--tag-teal-bg)');
		expect(chip.getAttribute('style')).toContain('var(--tag-teal-fg)');
	});

	it('degrades an off-whitelist color to the neutral gray hue (never reaches the style attr)', () => {
		// The prop is typed TagColor, but an untyped caller can pass anything —
		// the runtime whitelist must own the boundary.
		const rogue = render(Tag, {
			label: 'Finance',
			color: 'blue; background: url(https://x)' as never
		});
		const style = (rogue.container.querySelector('.tag') as HTMLElement).getAttribute('style') ?? '';
		expect(style).toContain('var(--tag-gray-bg)');
		expect(style).not.toContain('url(');
		rogue.unmount();
		const unknownHue = render(Tag, { label: 'Finance', color: 'magenta' as never });
		const style2 = (unknownHue.container.querySelector('.tag') as HTMLElement).getAttribute('style') ?? '';
		expect(style2).toContain('var(--tag-gray-fg)');
	});
});
