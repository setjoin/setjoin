import { describe, it, expect } from 'vitest';
import { splitQuotedHTML, splitQuotedText } from './quoteSplit';

describe('splitQuotedHTML', () => {
	it('splits at a top-level <blockquote>', () => {
		const html = '<p>Fresh reply.</p><blockquote><p>Old text</p></blockquote>';
		const r = splitQuotedHTML(html);
		expect(r.main).toBe('<p>Fresh reply.</p>');
		expect(r.quoted).toBe('<blockquote><p>Old text</p></blockquote>');
	});

	it('splits at a .gmail_quote div and at div[type=cite]', () => {
		const gmail = splitQuotedHTML('<p>Hi</p><div class="gmail_quote"><p>old</p></div>');
		expect(gmail.quoted).toContain('gmail_quote');
		const tb = splitQuotedHTML('<p>Hi</p><div type="cite"><p>old</p></div>');
		expect(tb.quoted).toContain('type="cite"');
	});

	it('treats a bare English "On … wrote:" line as the boundary (attribution included in the tail)', () => {
		const html =
			'<p>Thanks!</p><div>On Tue, Jul 1, 2025 at 9:00 AM Ada &lt;a@x.test&gt; wrote:</div><blockquote>old</blockquote>';
		const r = splitQuotedHTML(html);
		expect(r.main).toBe('<p>Thanks!</p>');
		expect(r.quoted).toContain('wrote:');
		expect(r.quoted).toContain('<blockquote>old</blockquote>');
	});

	it('whole-body quote → no split (nothing fresh to keep)', () => {
		const html = '<blockquote><p>Only a quote</p></blockquote>';
		expect(splitQuotedHTML(html).quoted).toBeNull();
	});

	it('no boundary → no split', () => {
		expect(splitQuotedHTML('<p>Just text</p>').quoted).toBeNull();
	});

	it('a nested (non-top-level) blockquote is NOT a boundary', () => {
		const html = '<div><p>text</p><blockquote>inner</blockquote></div>';
		expect(splitQuotedHTML(html).quoted).toBeNull();
	});

	it('a long paragraph starting with "On" does not false-positive as attribution', () => {
		const html = `<p>On reflection I think we should ship it. ${'x'.repeat(400)}</p><p>More.</p>`;
		expect(splitQuotedHTML(html).quoted).toBeNull();
	});
});

describe('splitQuotedText', () => {
	it('splits at the trailing > run, folding in the attribution line', () => {
		const text = 'Sounds good.\n\nOn Tue, Jul 1, 2025 Ada wrote:\n> old line 1\n> old line 2';
		const r = splitQuotedText(text);
		expect(r.main).toBe('Sounds good.');
		expect(r.quoted).toBe('On Tue, Jul 1, 2025 Ada wrote:\n> old line 1\n> old line 2');
	});

	it('interleaved reply (fresh text below the quote) stays unsplit', () => {
		const text = 'Top.\n> quoted\nMy answer below the quote.';
		expect(splitQuotedText(text).quoted).toBeNull();
	});

	it('whole-body quote → no split', () => {
		expect(splitQuotedText('> only\n> quote').quoted).toBeNull();
	});

	it('no quote → no split', () => {
		expect(splitQuotedText('plain text').quoted).toBeNull();
	});
});
