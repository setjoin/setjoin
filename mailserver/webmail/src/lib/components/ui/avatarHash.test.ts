import { describe, it, expect } from 'vitest';
import { AVATAR_HUES, avatarHash, avatarHue, avatarInitials } from './avatarHash';

describe('AVATAR_HUES', () => {
	it('is the 8 tag dot hues with indigo-500 replacing gray', () => {
		expect(AVATAR_HUES).toEqual([
			'var(--tag-blue-dot)',
			'var(--tag-teal-dot)',
			'var(--tag-green-dot)',
			'var(--tag-amber-dot)',
			'var(--tag-orange-dot)',
			'var(--tag-rose-dot)',
			'var(--tag-purple-dot)',
			'var(--indigo-500)'
		]);
	});
});

describe('avatarHash', () => {
	// Vectors hand-traced in the plan (Task 2.5) against the reference algorithm.
	it('matches the reference for "Ada" (no overflow)', () => {
		expect(avatarHash('Ada')).toBe(65662);
	});

	it('matches the reference for "Lena Fischer" (32-bit overflow path)', () => {
		expect(avatarHash('Lena Fischer')).toBe(1497240750);
	});

	it('matches the reference for "bob@example.com" (negative intermediates)', () => {
		expect(avatarHash('bob@example.com')).toBe(467379442);
	});

	it('hashes the empty string to 0', () => {
		expect(avatarHash('')).toBe(0);
	});
});

describe('avatarHue', () => {
	it('maps "Ada" to index 6 (purple)', () => {
		expect(avatarHue('Ada')).toBe('var(--tag-purple-dot)');
	});

	it('maps "Lena Fischer" to index 6 (purple)', () => {
		expect(avatarHue('Lena Fischer')).toBe('var(--tag-purple-dot)');
	});

	it('maps "bob@example.com" to index 2 (green)', () => {
		expect(avatarHue('bob@example.com')).toBe('var(--tag-green-dot)');
	});

	it('maps the empty string to index 0 (blue)', () => {
		expect(avatarHue('')).toBe('var(--tag-blue-dot)');
	});
});

describe('avatarInitials', () => {
	it('takes the first letters of the first and last words', () => {
		expect(avatarInitials('Lena Fischer')).toBe('LF');
	});

	it('uses first + last word when there are more than two', () => {
		expect(avatarInitials('Jean-Luc Picard III')).toBe('JI');
	});

	it('takes the first two characters of a single word', () => {
		expect(avatarInitials('Ada')).toBe('AD');
	});

	it('returns ? for empty or whitespace-only names', () => {
		expect(avatarInitials('')).toBe('?');
		expect(avatarInitials('   ')).toBe('?');
	});
});
