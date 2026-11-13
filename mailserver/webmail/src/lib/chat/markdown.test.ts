import { describe, it, expect } from 'vitest';
import { renderChatMarkdown } from './markdown';

describe('renderChatMarkdown — XSS probes (Design F7)', () => {
    it('neutralizes an <img onerror> payload', () => {
        // Escaped to inert text — "onerror=alert" surviving as plain
        // characters inside &lt;img ...&gt; is safe; a live <img> tag with a
        // live onerror handler is not, and that's what `not.toContain` guards.
        const out = renderChatMarkdown('<img src=x onerror=alert(1)>');
        expect(out).not.toContain('<img');
        expect(out).toBe('&lt;img src=x onerror=alert(1)&gt;');
    });

    it('never turns a javascript: markdown link into an anchor', () => {
        const out = renderChatMarkdown('[click me](javascript:alert(1))');
        expect(out).not.toContain('<a ');
        expect(out).toBe('[click me](javascript:alert(1))');
    });

    it('never autolinks a bare javascript: URI (no http/https scheme)', () => {
        const out = renderChatMarkdown('go to javascript:alert(1) now');
        expect(out).not.toContain('<a ');
    });

    it('escapes a raw <script> tag', () => {
        const out = renderChatMarkdown('<script>alert(document.cookie)</script>');
        expect(out).not.toContain('<script');
        expect(out).toContain('&lt;script&gt;');
    });

    it('escapes HTML injected via nested markdown (bold containing a tag)', () => {
        const out = renderChatMarkdown('**<img src=x onerror=alert(1)>**');
        expect(out).not.toContain('<img');
        expect(out).toBe('<strong>&lt;img src=x onerror=alert(1)&gt;</strong>');
    });

    it('escapes HTML injected inside a markdown link label', () => {
        const out = renderChatMarkdown('[<img src=x onerror=alert(1)>](https://example.com)');
        expect(out).toContain('&lt;img src=x onerror=alert(1)&gt;');
        expect(out).not.toContain('<img');
        expect(out).toBe(
            '<a href="https://example.com" target="_blank" rel="noopener noreferrer">&lt;img src=x onerror=alert(1)&gt;</a>',
        );
    });

    it('escapes HTML injected inside inline code and fenced code', () => {
        expect(renderChatMarkdown('`<img onerror=alert(1) src=x>`')).toBe(
            '<code>&lt;img onerror=alert(1) src=x&gt;</code>',
        );
        expect(renderChatMarkdown('```\n<script>alert(1)</script>\n```')).toBe(
            '<pre><code>\n&lt;script&gt;alert(1)&lt;/script&gt;\n</code></pre>',
        );
    });

    it('does not double-decode an entity smuggled in as literal text', () => {
        // If a naive implementation escaped the input twice interleaved with
        // decoding, this would come back as a live "<" instead of the entity.
        const out = renderChatMarkdown('&lt;script&gt;alert(1)&lt;/script&gt;');
        expect(out).not.toContain('<script');
        expect(out).toBe('&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;');
    });
});

describe('renderChatMarkdown — allowlisted constructs', () => {
    it('renders bold and italic, including nested', () => {
        expect(renderChatMarkdown('**bold**')).toBe('<strong>bold</strong>');
        expect(renderChatMarkdown('*italic*')).toBe('<em>italic</em>');
        expect(renderChatMarkdown('**bold *and italic* text**')).toBe(
            '<strong>bold <em>and italic</em> text</strong>',
        );
    });

    it('renders inline code without interpreting markdown inside it', () => {
        expect(renderChatMarkdown('`*not bold*`')).toBe('<code>*not bold*</code>');
    });

    it('renders fenced code blocks without interpreting markdown inside them', () => {
        expect(renderChatMarkdown('```\n*not bold*\n- not a list\n```')).toBe(
            '<pre><code>\n*not bold*\n- not a list\n</code></pre>',
        );
    });

    it('autolinks bare http(s) URLs with a safe rel/target', () => {
        const out = renderChatMarkdown('see https://example.com/path for details');
        expect(out).toBe(
            'see <a href="https://example.com/path" target="_blank" rel="noopener noreferrer">https://example.com/path</a> for details',
        );
    });

    it('renders markdown-style links for http(s) URLs', () => {
        const out = renderChatMarkdown('[docs](https://example.com/docs)');
        expect(out).toBe('<a href="https://example.com/docs" target="_blank" rel="noopener noreferrer">docs</a>');
    });

    it('resolves a vault placeholder nested inside a link label (inline code as link text)', () => {
        const out = renderChatMarkdown('[`x`](https://a.com)');
        expect(out).toBe('<a href="https://a.com" target="_blank" rel="noopener noreferrer"><code>x</code></a>');
    });

    it('renders unordered and ordered lists', () => {
        expect(renderChatMarkdown('- one\n- two')).toBe('<ul><li>one</li><li>two</li></ul>');
        expect(renderChatMarkdown('1. one\n2. two')).toBe('<ol><li>one</li><li>two</li></ol>');
    });

    it('is idempotent-safe on plain text with no markdown', () => {
        expect(renderChatMarkdown('hello world')).toBe('hello world');
    });
});
