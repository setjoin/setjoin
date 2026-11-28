import DOMPurify from 'dompurify';
import type { Email } from '$lib/types/jmap';

const ALLOWED_TAGS = [
    'b', 'i', 'em', 'strong', 'a', 'p', 'br', 'ul', 'ol', 'li',
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'blockquote', 'pre', 'code', 'img', 'div', 'span',
    'table', 'thead', 'tbody', 'tr', 'td', 'th', 'colgroup', 'col',
];

const ALLOWED_ATTR = [
    'href', 'src', 'alt', 'title', 'class', 'style',
    'width', 'height', 'colspan', 'rowspan',
];

// CSS exfil vectors permitted by the `style` attribute. `url(...)` triggers
// background/list-image network fetches (tracking + IP/User-Agent leak even
// inside the sandboxed reading-pane iframe); `expression(...)` is legacy IE
// script execution. Defense-in-depth: neutralize them in the style value while
// keeping the rest of DOMPurify's behavior unchanged.
const CSS_EXFIL = /url\s*\(|expression\s*\(/i;

// CSS canonicalization primitives. The browser decodes backslash escapes and
// skips comments while PARSING a style value, so a raw-string regex sees
// different tokens than the CSS engine does: `\75 rl(https://evil)` IS
// `url(https://evil)` once parsed, and `expr/*x*/ession(` was the classic IE
// comment-split. Testing CSS_EXFIL on the raw value therefore lets escaped
// identifiers carry remote-load declarations past the gate
// (occ_febfa41fc7d0cc4e234a86c1). canonicalizeCSS resolves both first,
// producing the text the CSS engine will actually act on — the canonicalized
// value is also what we hand back in the style attribute, so the exfil test
// and the delivered bytes can never disagree again.
const CSS_COMMENT = /\/\*[\s\S]*?\*\//g;
const CSS_HEX_ESCAPE = /\\([0-9a-fA-F]{1,6})[\t\n\f\r ]?/g;
const CSS_CHAR_ESCAPE = /\\(.)/g;

function canonicalizeCSS(value: string): string {
    let out = value.replace(CSS_COMMENT, '');
    out = out.replace(CSS_HEX_ESCAPE, (_, hex: string) => {
        const cp = parseInt(hex, 16);
        // Out-of-range escapes (0, beyond Unicode) cannot form an exfil
        // identifier; U+FFFD is an inert stand-in that can never match one.
        return cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : '\uFFFD';
    });
    // Remaining backslashes are non-hex escapes (`\(` → `(`); a lone trailing
    // backslash has nothing to escape and stays inert.
    return out.replace(CSS_CHAR_ESCAPE, '$1');
}

// A remote http(s) (or protocol-relative) URL — these fire a network GET when an
// <img> renders, even inside the sandboxed reading-pane iframe, leaking recipient
// IP/User-Agent + read confirmation (tracking pixels). Relative (`/api/blobs/…`),
// `cid:` (rewritten upstream) and inline `data:` images are NOT remote.
const REMOTE_URL = /^\s*(?:https?:)?\/\//i;

// ponytail: curated best-effort list of common ESP (email service provider)
// tracking domains — sender-analytics/marketing platforms whose 1x1 pixels and
// click-wrapper links are the overwhelming majority of tracking seen in real
// mail. Not exhaustive; isZeroArea + wrapper-host heuristics below catch the
// self-hosted/unknown-domain case. Extend as new trackers get reported.
const TRACKER_DOMAINS = [
    'sendgrid.net',
    'mailchimp.com',
    'list-manage.com',
    'mandrillapp.com',
    'customer.io',
    'iterable.com',
    'braze.com',
    'hubspot.com',
    'hs-analytics.net',
    'klaviyo.com',
    'marketo.net',
    'mailgun.org',
    'sparkpostmail.com',
] as const;

function isTrackerDomain(hostname: string): boolean {
    const h = hostname.toLowerCase();
    return TRACKER_DOMAINS.some((d) => h === d || h.endsWith('.' + d));
}

// Wrapper-link host heuristics (Item B): click-tracking redirectors commonly
// front their links with a numbered subdomain (SendGrid-style `url1234.foo.com`)
// or a `click.`/`links.` subdomain. Combined with TRACKER_DOMAINS in
// looksLikeWrapperHost.
const WRAPPER_HOST_RE = /^(?:url\d+\.|click\.|links\.)/i;

function looksLikeWrapperHost(hostname: string): boolean {
    const h = hostname.toLowerCase();
    return WRAPPER_HOST_RE.test(h) || isTrackerDomain(h);
}

// Best-effort hostname extraction — never throws. Handles protocol-relative
// (`//host/…`) URLs; anything else that fails to parse (relative paths,
// mailto:, javascript:, malformed input) yields ''.
function extractHostname(url: string): string {
    try {
        const trimmed = url.trim();
        const abs = trimmed.startsWith('//') ? 'https:' + trimmed : trimmed;
        return new URL(abs).hostname;
    } catch {
        return '';
    }
}

// A `width`/`height` of 0 or 1(px) is the classic tracking-pixel dimension; so
// is `display:none`/`visibility:hidden`, or an inline width/height style of
// 0-1px. Any one of these on a remote <img> is enough to classify it as a
// tracker regardless of its domain (self-hosted trackers included).
const ZERO_OR_ONE_PX = /^\s*(0|1)(px)?\s*$/i;

function isZeroArea(el: Element): boolean {
    const w = el.getAttribute('width');
    const h = el.getAttribute('height');
    if ((w && ZERO_OR_ONE_PX.test(w)) || (h && ZERO_OR_ONE_PX.test(h))) return true;

    const style = el.getAttribute('style') || '';
    if (/display\s*:\s*none/i.test(style) || /visibility\s*:\s*hidden/i.test(style)) return true;

    const widthDecl = style.match(/(?:^|;)\s*width\s*:\s*(\d+)px\s*(?:;|$)/i);
    const heightDecl = style.match(/(?:^|;)\s*height\s*:\s*(\d+)px\s*(?:;|$)/i);
    if ((widthDecl && Number(widthDecl[1]) <= 1) || (heightDecl && Number(heightDecl[1]) <= 1)) return true;

    return false;
}

// Decodes a `/link-protect?token=<payload>.<sig>` redirect (see
// mailserver/internal/linkprotect) to the ORIGINAL destination URL, purely
// client-side. The token is a base64(JSON).base64(HMAC-sig) pair — the JSON
// payload (which carries the real URL as `.u`) is readable without verifying
// the signature; we only use it to resolve the host for tracker/mismatch
// classification, never to auto-navigate, so an unverifiable/tampered token
// is harmless here. Returns null (fall back to the raw href) on anything
// that doesn't parse — malformed token, foreign token shape, etc.
function decodeLinkProtectToken(href: string): string | null {
    const m = href.match(/^\/link-protect\?token=([^&]+)/);
    if (!m) return null;
    try {
        const payloadB64 = m[1].split('.')[0];
        const padded = payloadB64.replace(/-/g, '+').replace(/_/g, '/');
        const pad = padded.length % 4 === 0 ? '' : '='.repeat(4 - (padded.length % 4));
        const json = atob(padded + pad);
        const claims = JSON.parse(json) as { u?: unknown };
        return typeof claims.u === 'string' ? claims.u : null;
    } catch {
        return null;
    }
}

// If the anchor's visible text itself looks like a URL, return its host —
// used to catch the classic phish/tracker signature where the DISPLAYED text
// says one domain but the href resolves somewhere else.
function extractHostFromVisibleText(text: string): string | null {
    const t = text.trim();
    if (/^https?:\/\//i.test(t)) return extractHostname(t) || null;
    if (/^www\.[a-z0-9.-]+\.[a-z]{2,}/i.test(t)) return extractHostname('http://' + t) || null;
    return null;
}

// Classifies + tags a single <a> element in place (Item B). Flags via a
// native `title="via <host>"` tooltip — no href rewrite, no post-render JS
// (works inside the sandbox="" reading-pane iframe). link_protect (server-side,
// click-time verdict engine) is a different concern; this only DECODES its
// token to see through the redirect, it does not duplicate its verdict.
function classifyAndTagLink(el: Element): void {
    const rawHref = el.getAttribute('href');
    if (!rawHref) return;

    const resolved = decodeLinkProtectToken(rawHref) ?? rawHref;
    const resolvedHost = extractHostname(resolved);
    if (!resolvedHost) return;

    const textHost = extractHostFromVisibleText(el.textContent || '');
    const flagged = looksLikeWrapperHost(resolvedHost) || (!!textHost && textHost !== resolvedHost);
    if (flagged) {
        el.setAttribute('title', `via ${resolvedHost}`);
    }
}

// Per-call hook state. DOMPurify.sanitize is synchronous, so set-before /
// reset-after around each call is race-free (no concurrent sanitize calls
// share these).
let allowRemoteImages = false;
let loadEverything = false; // per-message "load everything" escape hatch — also loads tracker-classified images
let trackerCount = 0;
// Per-node classification from the element pass, read by the attribute pass
// for the SAME node — WeakSet so entries from prior sanitize() calls (whose
// nodes are unreachable garbage) are never seen again.
const trackerImageNodes = new WeakSet<Element>();

let hookInstalled = false;
function installStyleHook() {
    if (hookInstalled) return;
    hookInstalled = true;

    DOMPurify.addHook('uponSanitizeElement', (node, data) => {
        const el = node as Element;
        if (data.tagName === 'img') {
            const src = el.getAttribute('src') || '';
            if (REMOTE_URL.test(src)) {
                const host = extractHostname(src);
                if (isTrackerDomain(host) || isZeroArea(el)) {
                    trackerImageNodes.add(el);
                    trackerCount++;
                }
            }
        } else if (data.tagName === 'a') {
            classifyAndTagLink(el);
        }
    });

    DOMPurify.addHook('uponSanitizeAttribute', (node, data) => {
        if (data.attrName === 'style') {
            // Canonicalize BEFORE the exfil test (occ_febfa41fc7d0cc4e234a86c1):
            // the delivered attribute value becomes the canonical text, so the
            // declarations we test are exactly the declarations the CSS engine
            // sees. Then drop any declaration that carries a url()/expression()
            // value rather than the whole attribute, so benign styling survives.
            data.attrValue = canonicalizeCSS(data.attrValue);
            if (CSS_EXFIL.test(data.attrValue)) {
                data.attrValue = data.attrValue
                    .split(';')
                    .filter((decl) => !CSS_EXFIL.test(decl))
                    .join(';');
            }
        }
        if (data.attrName === 'src' || data.attrName === 'srcset') {
            const isTracker = trackerImageNodes.has(node as Element);
            if (isTracker) {
                // Load-but-strip: a tracker-classified image is stripped unless the
                // user hit the per-message "load everything" escape hatch.
                if (!loadEverything) data.keepAttr = false;
                return;
            }
            // Block remote image fetches (tracking pixels) unless the user opted in.
            if (!allowRemoteImages && REMOTE_URL.test(data.attrValue)) {
                data.keepAttr = false;
            }
        }
    });
}

/** Out-param populated with the tracker-image count for a single sanitizeHTML/
 *  renderEmailBodyHTML call (Item A). Optional — callers who don't need the
 *  count (e.g. the print helper) just omit it. */
export interface TrackerCountOut {
    trackersBlocked: number;
}

export function sanitizeHTML(
    html: string,
    opts?: { allowRemoteImages?: boolean; loadEverything?: boolean },
    out?: TrackerCountOut,
): string {
    installStyleHook();
    allowRemoteImages = opts?.allowRemoteImages ?? false;
    loadEverything = opts?.loadEverything ?? false;
    trackerCount = 0;
    try {
        const result = DOMPurify.sanitize(html, {
            ALLOWED_TAGS,
            ALLOWED_ATTR,
            ALLOW_DATA_ATTR: false,
        });
        if (out) out.trackersBlocked = trackerCount;
        return result;
    } finally {
        allowRemoteImages = false;
        loadEverything = false;
    }
}

// Render an email's HTML body for display: rewrite inline cid: images to their
// content-addressed /api/blobs/<sha> URL, then sanitize. Single source of truth shared
// by the reading-pane card and the print helper — do NOT re-inline this logic.
export function renderEmailBodyHTML(
    email: Pick<Email, 'bodyHTML' | 'inlineImages'>,
    opts?: { allowRemoteImages?: boolean; loadEverything?: boolean },
    out?: TrackerCountOut,
): string {
    if (!email.bodyHTML) {
        if (out) out.trackersBlocked = 0;
        return '';
    }
    let html = email.bodyHTML;
    const inlineImages = email.inlineImages || {};
    for (const [cid, sha256] of Object.entries(inlineImages)) {
        html = html.replaceAll(cid, `/api/blobs/${sha256}`);
    }
    return sanitizeHTML(
        html,
        { allowRemoteImages: opts?.allowRemoteImages ?? false, loadEverything: opts?.loadEverything ?? false },
        out,
    );
}

// C2 fix: the OUTBOUND compose profile — pinned here (not left to a per-call
// `{ allowRemoteImages: true }` at the call site) so no future compose caller
// can silently regress to sanitizeHTML's inbound-safe allowRemoteImages=false
// default. The user's own inserted remote <img> must survive send; script/
// handler/style-exfil stripping is unchanged (same ALLOWED_TAGS/ATTR + hooks).
export function sanitizeOutboundHTML(html: string): string {
	return sanitizeHTML(html, { allowRemoteImages: true });
}

// Text→HTML boundary (occ_b60bbe1192d7e36f597f1d56): plain TEXT interpolated
// into the editor (a text-only mail's reply quote, a draft's bodyText) must be
// entity-encoded before the newline→<br> pass — raw interpolation lets
// attacker-authored text (`<img src="https://…">`) become real markup the
// moment the editor parses it, bypassing this module's remote-image gate
// entirely. The two boundaries are therefore: untrusted HTML → sanitizeHTML;
// plain text interpolated as HTML → escapeHTML first. Element-content
// contexts only — attribute contexts need additional quoting discipline.
export function escapeHTML(text: string): string {
	return text
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#39;');
}

// Cheap heuristic for the "load remote images" banner: does the raw body carry an
// <img> with a remote src? ponytail: regex, not a DOM parse — a false positive
// only shows the banner with nothing to load; the sanitizer is the real gate.
export function hasRemoteImages(html: string): boolean {
    return /<img\b[^>]*\bsrc\s*=\s*["']?\s*(?:https?:)?\/\//i.test(html);
}
