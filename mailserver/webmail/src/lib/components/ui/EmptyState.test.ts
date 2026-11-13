import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte/svelte5';
import { createRawSnippet } from 'svelte';
import EmptyState from './EmptyState.svelte';

describe('EmptyState', () => {
	it('renders the title', () => {
		render(EmptyState, { title: 'No messages' });
		expect(screen.getByText('No messages')).toBeTruthy();
	});

	it('hides the watermark by default', () => {
		const { container } = render(EmptyState, { title: 'x' });
		expect(container.querySelector('img')).toBeNull();
	});

	it('shows the decorative logomark watermark when enabled', () => {
		const { container } = render(EmptyState, { title: 'x', watermark: true });
		const img = container.querySelector('img')!;
		expect(img.getAttribute('src')).toBe('/brand/logo-mark.svg');
		expect(img.classList.contains('sj-ink')).toBe(true);
		expect(img.getAttribute('alt')).toBe('');
	});

	it('renders the action snippet', () => {
		const action = createRawSnippet(() => ({ render: () => '<button>Compose</button>' }));
		render(EmptyState, { title: 'x', action });
		expect(screen.getByText('Compose')).toBeTruthy();
	});
});
