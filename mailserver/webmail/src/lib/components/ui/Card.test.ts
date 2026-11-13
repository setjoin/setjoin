import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte/svelte5';
import { createRawSnippet } from 'svelte';
import Card from './Card.svelte';

const snippet = (html: string) => createRawSnippet(() => ({ render: () => `<div>${html}</div>` }));

describe('Card', () => {
	it('renders the body content', () => {
		render(Card, { children: snippet('428 GB of 2 TB used') });
		expect(screen.getByText('428 GB of 2 TB used')).toBeTruthy();
	});

	it('renders a header when title is set', () => {
		const { container } = render(Card, { title: 'Storage', children: snippet('body') });
		expect(screen.getByText('Storage')).toBeTruthy();
		expect(container.querySelector('.card__header')).not.toBeNull();
	});

	it('renders no header when title and actions are absent', () => {
		const { container } = render(Card, { children: snippet('body') });
		expect(container.querySelector('.card__header')).toBeNull();
	});

	it('renders actions in the header', () => {
		render(Card, { title: 'Storage', actions: snippet('Manage'), children: snippet('body') });
		expect(screen.getByText('Manage')).toBeTruthy();
	});

	it('removes body padding in flush mode', () => {
		const { container } = render(Card, { flush: true, children: snippet('rows') });
		expect(container.querySelector('.card__body--flush')).not.toBeNull();
	});
});
