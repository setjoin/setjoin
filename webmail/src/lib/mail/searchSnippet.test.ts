import { describe, it, expect } from 'vitest';
import { sanitizeSnippet } from './searchSnippet';

describe('sanitizeSnippet', () => {
	it('preserves <mark> highlight tags', () => {
		expect(sanitizeSnippet('the <mark>quick</mark> fox')).toBe('the <mark>quick</mark> fox');
	});

	it('escapes a <script> injection while keeping <mark>', () => {
		const dirty = '<mark>hi</mark><script>alert(1)</script>';
		const clean = sanitizeSnippet(dirty);
		expect(clean).toBe('<mark>hi</mark>&lt;script&gt;alert(1)&lt;/script&gt;');
		expect(clean).not.toContain('<script>');
	});

	it('escapes all other angle-bracket markup', () => {
		expect(sanitizeSnippet('<img src=x onerror=alert(1)>')).toBe(
			'&lt;img src=x onerror=alert(1)&gt;',
		);
	});

	it('does not re-allow a <mark> carrying attributes (only the bare literal)', () => {
		const clean = sanitizeSnippet('<mark onmouseover="steal()">x</mark>');
		expect(clean).toContain('&lt;mark onmouseover=');
		expect(clean).not.toContain('onmouseover="steal()"');
		// the matching bare closing tag IS re-allowed — harmless without an open tag
		expect(clean).toContain('</mark>');
	});

	it('escapes ampersands and double quotes', () => {
		expect(sanitizeSnippet('a & b "c"')).toBe('a &amp; b &quot;c&quot;');
	});

	it('escapes & before it can form a false entity (order matters)', () => {
		// A literal "&lt;mark&gt;" in the source must NOT become a real tag.
		expect(sanitizeSnippet('&lt;mark&gt;')).toBe('&amp;lt;mark&amp;gt;');
	});
});
