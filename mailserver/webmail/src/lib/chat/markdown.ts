// Chat message body renderer (Design F7: markdown is a security surface).
//
// Chat bodies render INLINE — unlike mail (rendered inside a sandboxed
// iframe, see $lib/sanitize.ts), there is no iframe boundary here. So this
// pipeline is allowlist-first, not denylist: escape every character of the
// raw input as HTML text FIRST, then re-introduce exactly the constructs the
// spec allows (bold, italic, inline code, fenced code, http(s) links, lists)
// by pattern-matching the already-escaped text. Nothing that wasn't produced
// by one of the steps below can ever reach the DOM as a tag or attribute —
// an `<img onerror=...>` or `javascript:` scheme never becomes live markup
// because the initial escape runs before any markdown rule sees the input.
//
// Callers render the result via `{@html renderChatMarkdown(body)}`. No other
// caller must ever `{@html}` a chat body directly — always go through here.

import { escapeHtml } from '$lib/util/printWindow';


// Opaque, order-preserving placeholders so later passes (links, bold/italic,
// lists) never re-parse markdown syntax that lives inside code or an
// already-built anchor. U+0000 is not a character chat text contains and
// escapeHtml() never produces it, so it's a safe, collision-free delimiter
// (unlike a printable marker, it can't collide with digits already present
// in the message body).
const NUL = '\u0000';
const PLACEHOLDER_RE = new RegExp(`${NUL}(\\d+)${NUL}`, 'g');

function makeVault() {
    const store: string[] = [];
    return {
        hide(html: string): string {
            const idx = store.push(html) - 1;
            return `${NUL}${idx}${NUL}`;
        },
        reveal(text: string): string {
            // Loop to convergence: a vault entry can itself contain another
            // entry's placeholder (e.g. a link label built from hidden inline
            // code, `[`x`](https://a.com)`), so one pass can leave an inner
            // placeholder unresolved in the substituted text.
            let out = text;
            let prev: string;
            do {
                prev = out;
                out = out.replace(PLACEHOLDER_RE, (_, i: string) => store[Number(i)]);
            } while (out !== prev);
            return out;
        },
    };
}

// Markdown link `[text](https://…)` OR a bare `https://…` URL. The regex
// itself IS the scheme allowlist: neither branch matches unless the scheme
// is literally `http://`/`https://`, so a `javascript:`/`data:` href in
// either syntax simply fails to match and falls through as inert escaped
// text (e.g. `[click](javascript:alert(1))` renders as that literal string,
// never as an anchor).
const LINK_RE = new RegExp(`\\[([^[\\]]+)\\]\\((https?://[^\\s)${NUL}]+)\\)|(https?://[^\\s<${NUL}]+)`, 'g');

function linkify(text: string, vault: ReturnType<typeof makeVault>): string {
    return text.replace(
        LINK_RE,
        (_match, mdText: string | undefined, mdUrl: string | undefined, bareUrl: string | undefined) => {
            const url = mdUrl ?? bareUrl!;
            const label = mdText ?? bareUrl!;
            return vault.hide(`<a href="${url}" target="_blank" rel="noopener noreferrer">${label}</a>`);
        },
    );
}

// **bold** before *italic* — an *italic* run can't contain an unescaped
// `**`, so resolving bold first lets `**bold *italic* text**` nest correctly.
function applyEmphasis(text: string): string {
    // Bold's content class allows a lone `*` (not `**`) so `**bold *nested*
    // text**` resolves as one bold span with an italic run inside it — the
    // lazy quantifier still stops at the first literal `**` it finds.
    return text
        .replace(/\*\*([^\n]+?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*([^\n*]+?)\*/g, '<em>$1</em>');
}

// Line-based `- `/`* ` and `1. ` list grouping. ponytail: relies on the
// consuming component rendering the body with `white-space: pre-wrap` for
// plain line breaks — no `<br>` insertion here, one less thing to escape.
function applyLists(text: string): string {
    const lines = text.split('\n');
    const out: string[] = [];
    let buf: string[] = [];
    let kind: 'ul' | 'ol' | null = null;

    const flush = () => {
        if (kind) out.push(`<${kind}>${buf.map((item) => `<li>${item}</li>`).join('')}</${kind}>`);
        buf = [];
        kind = null;
    };

    for (const line of lines) {
        const ul = /^[-*]\s+(.+)$/.exec(line);
        const ol = /^\d+\.\s+(.+)$/.exec(line);
        if (ul) {
            if (kind !== 'ul') flush();
            kind = 'ul';
            buf.push(ul[1]);
        } else if (ol) {
            if (kind !== 'ol') flush();
            kind = 'ol';
            buf.push(ol[1]);
        } else {
            flush();
            out.push(line);
        }
    }
    flush();
    return out.join('\n');
}

export function renderChatMarkdown(body: string): string {
    const escaped = escapeHtml(body);
    const vault = makeVault();

    // Fenced code first (spans lines, must not be touched by anything else),
    // then inline code — both hide their (already-escaped) content behind a
    // placeholder so bold/italic/link/list rules never see inside a code span.
    let text = escaped.replace(/```([\s\S]*?)```/g, (_, code: string) => vault.hide(`<pre><code>${code}</code></pre>`));
    text = text.replace(/`([^`\n]+)`/g, (_, code: string) => vault.hide(`<code>${code}</code>`));

    text = linkify(text, vault);
    text = applyEmphasis(text);
    text = applyLists(text);

    return vault.reveal(text);
}
