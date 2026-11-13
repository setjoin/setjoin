import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte/svelte5';
import Avatar from './Avatar.svelte';

describe('Avatar', () => {
	it('renders initials when no image is given', () => {
		render(Avatar, { name: 'Lena Fischer' });
		expect(screen.getByText('LF')).toBeTruthy();
	});

	it('renders the image when src is given', () => {
		render(Avatar, { name: 'Priya Raman', src: '/photos/priya.jpg' });
		const img = screen.getByAltText('Priya Raman') as HTMLImageElement;
		expect(img.getAttribute('src')).toBe('/photos/priya.jpg');
	});

	it('sizes follow the sm/md/lg/xl scale with 0.38 font ratio', () => {
		const { container } = render(Avatar, { name: 'Ada', size: 'xl' });
		const el = container.querySelector('.avatar') as HTMLElement;
		expect(el.getAttribute('style')).toContain('width: 64px');
		expect(el.getAttribute('style')).toContain('height: 64px');
		expect(el.getAttribute('style')).toContain('font-size: 24px');
	});

	it('defaults to md (32px)', () => {
		const { container } = render(Avatar, { name: 'Ada' });
		const el = container.querySelector('.avatar') as HTMLElement;
		expect(el.getAttribute('style')).toContain('width: 32px');
		expect(el.getAttribute('style')).toContain('font-size: 12px');
	});

	it('uses the deterministic hue as background', () => {
		// avatarHash('Lena Fischer') = 1497240750; 1497240750 % 8 = 6 → purple
		const { container } = render(Avatar, { name: 'Lena Fischer' });
		const el = container.querySelector('.avatar') as HTMLElement;
		expect(el.getAttribute('style')).toContain('var(--tag-purple-dot)');
	});

	it('uses a neutral background behind images', () => {
		const { container } = render(Avatar, { name: 'Priya Raman', src: '/photos/priya.jpg' });
		const el = container.querySelector('.avatar') as HTMLElement;
		expect(el.getAttribute('style')).toContain('var(--gray-200)');
	});

	it('shows ? for an empty name', () => {
		render(Avatar, {});
		expect(screen.getByText('?')).toBeTruthy();
	});
});
