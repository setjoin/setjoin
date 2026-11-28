import { describe, it, expect } from 'vitest';
import { sanitizeHTML, hasRemoteImages, renderEmailBodyHTML, sanitizeOutboundHTML, escapeHTML } from './sanitize';

describe('sanitizeHTML', () => {
	it('strips script tags', () => {
		expect(sanitizeHTML('<script>alert(1)</script>')).toBe('');
		expect(sanitizeHTML('<script type="text/javascript">alert(1)</script>')).toBe('');
		expect(sanitizeHTML('text <SCRIPT>alert(1)</SCRIPT> text')).toBe('text  text');
	});

	it('strips script tags best-effort with nested markup', () => {
		// The regex is a pragmatic filter, not a full HTML parser.
		// Nested "</script>"-like strings inside scripts may leave residue.
		const result = sanitizeHTML('<script>var x = "<script>inner</script>"</script>');
		expect(result).not.toContain('<script');
		expect(result).not.toContain('alert');
	});

	it('strips double-quoted event handlers', () => {
		// Leading space before the handler is consumed too, producing clean tags.
		expect(sanitizeHTML('<div onclick="alert(1)">hi</div>')).toBe('<div>hi</div>');
		expect(sanitizeHTML('<img onerror="bad()" src="x">')).toBe('<img src="x">');
	});

	it('strips single-quoted event handlers', () => {
		expect(sanitizeHTML("<div onclick='alert(1)'>hi</div>")).toBe('<div>hi</div>');
		expect(sanitizeHTML("<span onload='bad()'>x</span>")).toBe('<span>x</span>');
	});

	it('strips backtick-quoted event handlers', () => {
		expect(sanitizeHTML('<div onclick=`alert(1)`>hi</div>')).toBe('<div>hi</div>');
	});

	it('strips bare (unquoted) event handlers', () => {
		expect(sanitizeHTML('<div onclick=alert(1)>hi</div>')).toBe('<div>hi</div>');
	});

	it('strips javascript: hrefs (double quoted)', () => {
		expect(sanitizeHTML('<a href="javascript:alert(1)">link</a>')).toBe('<a>link</a>');
	});

	it('strips javascript: hrefs (single quoted)', () => {
		expect(sanitizeHTML("<a href='javascript:alert(1)'>link</a>")).toBe('<a>link</a>');
	});

	it('preserves benign HTML', () => {
		const html = '<b>bold</b> <i>italic</i> <a href="https://example.com">link</a>';
		expect(sanitizeHTML(html)).toBe(html);
	});

	it('preserves non-javascript hrefs', () => {
		const html = '<a href="/inbox">Inbox</a>';
		expect(sanitizeHTML(html)).toBe(html);
	});

	it('handles empty input', () => {
		expect(sanitizeHTML('')).toBe('');
	});

	it('handles plain text with no HTML', () => {
		expect(sanitizeHTML('Hello, world!')).toBe('Hello, world!');
	});

	it('does not strip benign attributes', () => {
		const html = '<img src="photo.jpg" alt="a photo" width="100">';
		expect(sanitizeHTML(html)).toBe(html);
	});

	it('strips CSS url() from the style attribute (exfil/tracking vector)', () => {
		const out = sanitizeHTML('<div style="background: url(https://evil/track.gif)">x</div>');
		expect(out).not.toContain('url(');
		expect(out).not.toContain('evil');
	});

	describe('CSS-escaped identifiers (occ_febfa41fc7d0cc4e234a86c1)', () => {
		it('strips a hex-escaped url() the raw regex cannot see', () => {
			// The CSS engine parses `\75 rl(` exactly as `url(` — the exfil test
			// must run on the canonicalized text, not the raw attribute string.
			const out = sanitizeHTML('<div style="background: \\75 rl(https://evil.example/track.gif)">x</div>');
			expect(out).not.toContain('evil.example');
			expect(out).not.toMatch(/url\s*\(/i);
		});

		it('strips a hex escape with no trailing space (`\\75rl(`)', () => {
			const out = sanitizeHTML('<div style="background:\\75rl(https://evil.example/p.gif)">x</div>');
			expect(out).not.toContain('evil.example');
			expect(out).not.toMatch(/url\s*\(/i);
		});

		it('strips a comment-split url() (`u/**/rl(`)', () => {
			const out = sanitizeHTML('<div style="background:u/**/rl(https://evil.example/p.gif)">x</div>');
			expect(out).not.toContain('evil.example');
			expect(out).not.toMatch(/url\s*\(/i);
		});

		it('strips an escaped expression() payload', () => {
			const out = sanitizeHTML('<div style="width: expr\\65 ssion(alert(1))">x</div>');
			expect(out).not.toContain('alert');
			expect(out).not.toMatch(/expression\s*\(/i);
		});

		it('strips an HTML-entity-encoded url() (parser decodes entities before the hook)', () => {
			const out = sanitizeHTML('<div style="background: &#117;rl(https://evil.example/p.gif)">x</div>');
			expect(out).not.toContain('evil.example');
			expect(out).not.toMatch(/url\s*\(/i);
		});

		it('keeps a benign escaped declaration, delivered in canonical form', () => {
			// `col\6f r` parses as `color`; canonicalization preserves the
			// declaration (decoded) instead of discarding benign styling.
			const out = sanitizeHTML('<div style="col\\6f r: navy">x</div>');
			expect(out).toContain('color: navy');
		});

		it('never hands the browser text the exfil test did not see (delivered value is canonical)', () => {
			// Whatever survives must itself be escape-free: the canonicalized
			// value replaces the raw one in the attribute, so a later consumer
			// (the CSS engine) evaluates the same bytes we tested.
			const out = sanitizeHTML('<div style="color: re\\64 ; background: \\75rl(https://evil.example/x)">x</div>');
			expect(out).not.toContain('\\');
			expect(out).not.toContain('evil.example');
		});
	});

	it('strips CSS expression() from the style attribute', () => {
		const out = sanitizeHTML('<div style="width: expression(alert(1))">x</div>');
		expect(out).not.toContain('expression(');
		expect(out).not.toContain('alert');
	});

	it('keeps benign style declarations while dropping only the url() one', () => {
		const out = sanitizeHTML('<div style="color: red; background: url(https://evil/x.gif)">x</div>');
		expect(out).toContain('color: red');
		expect(out).not.toContain('url(');
	});

	it('preserves a fully benign style attribute', () => {
		const html = '<div style="color: red; font-weight: bold;">x</div>';
		expect(sanitizeHTML(html)).toContain('color: red');
		expect(sanitizeHTML(html)).toContain('font-weight: bold');
	});

	describe('remote images (tracking-pixel gate)', () => {
		it('strips a remote http(s) <img src> by default', () => {
			const out = sanitizeHTML('<img src="https://tracker.example/p.gif?id=abc">');
			expect(out).not.toContain('tracker.example');
			expect(out).not.toContain('src=');
		});

		it('strips a protocol-relative remote <img src> by default', () => {
			const out = sanitizeHTML('<img src="//tracker.example/p.gif">');
			expect(out).not.toContain('tracker.example');
		});

		it('keeps relative /blobs/ inline images', () => {
			const out = sanitizeHTML('<img src="/blobs/deadbeef" alt="inline">');
			expect(out).toContain('/blobs/deadbeef');
		});

		it('keeps data: images (no network fetch)', () => {
			const out = sanitizeHTML('<img src="data:image/png;base64,AAAA">');
			expect(out).toContain('data:image/png');
		});

		it('keeps remote images when explicitly allowed', () => {
			const out = sanitizeHTML('<img src="https://tracker.example/p.gif">', { allowRemoteImages: true });
			expect(out).toContain('tracker.example');
		});

		it('resets the opt-in between calls (no leak across messages)', () => {
			sanitizeHTML('<img src="https://a.example/x.gif">', { allowRemoteImages: true });
			const out = sanitizeHTML('<img src="https://b.example/y.gif">');
			expect(out).not.toContain('b.example');
		});

		it('sanitizeOutboundHTML (C2 compose profile) keeps remote images by default', () => {
			// Unlike the bare sanitizeHTML default (allowRemoteImages=false, tuned for
			// display of INBOUND mail), the outbound compose profile must let the
			// user's own inserted remote <img> survive send.
			const out = sanitizeOutboundHTML('<img src="https://example.com/photo.png">');
			expect(out).toContain('https://example.com/photo.png');
		});

		it('sanitizeOutboundHTML still strips scripts and event handlers', () => {
			const out = sanitizeOutboundHTML('<script>alert(1)</script><div onclick="bad()">hi</div>');
			expect(out).not.toContain('<script');
			expect(out).not.toContain('onclick');
		});

		it('hasRemoteImages detects remote img but not relative/data', () => {
			expect(hasRemoteImages('<img src="https://t.example/p.gif">')).toBe(true);
			expect(hasRemoteImages('<img src="//t.example/p.gif">')).toBe(true);
			expect(hasRemoteImages('<img src="/blobs/x">')).toBe(false);
			expect(hasRemoteImages('<p>no images</p>')).toBe(false);
		});
	});
});

describe('tracker-image detection (U3 Item A)', () => {
	it('classifies a curated tracker domain and strips it even when remote images are allowed', () => {
		const out = { trackersBlocked: 0 };
		const html = sanitizeHTML(
			'<img src="https://sendgrid.net/wf/open?id=abc"><img src="https://example.com/photo.jpg">',
			{ allowRemoteImages: true },
			out,
		);
		expect(html).not.toContain('sendgrid.net');
		expect(html).toContain('example.com/photo.jpg'); // regular remote image survives load-but-strip
		expect(out.trackersBlocked).toBe(1);
	});

	it('classifies a 1x1 pixel (any domain) as a tracker via width/height attrs', () => {
		const out = { trackersBlocked: 0 };
		const html = sanitizeHTML(
			'<img src="https://unknown-esp.example/p.gif" width="1" height="1">',
			{ allowRemoteImages: true },
			out,
		);
		expect(html).not.toContain('unknown-esp.example');
		expect(out.trackersBlocked).toBe(1);
	});

	it('classifies a hidden-style pixel (display:none) as a tracker', () => {
		const out = { trackersBlocked: 0 };
		const html = sanitizeHTML(
			'<img src="https://unknown-esp.example/p.gif" style="display:none">',
			{ allowRemoteImages: true },
			out,
		);
		expect(html).not.toContain('unknown-esp.example');
		expect(out.trackersBlocked).toBe(1);
	});

	it('classifies a 0-1px inline-style dimension as a tracker', () => {
		const out = { trackersBlocked: 0 };
		const html = sanitizeHTML(
			'<img src="https://unknown-esp.example/p.gif" style="width:1px;height:1px">',
			{ allowRemoteImages: true },
			out,
		);
		expect(html).not.toContain('unknown-esp.example');
		expect(out.trackersBlocked).toBe(1);
	});

	it('counts trackers even when remote images are blocked by default (banner still informs)', () => {
		const out = { trackersBlocked: 0 };
		sanitizeHTML('<img src="https://sendgrid.net/open.gif">', undefined, out);
		expect(out.trackersBlocked).toBe(1);
	});

	it('the "load everything" escape hatch loads the tracker image too', () => {
		const out = { trackersBlocked: 0 };
		const html = sanitizeHTML(
			'<img src="https://sendgrid.net/open.gif">',
			{ allowRemoteImages: true, loadEverything: true },
			out,
		);
		expect(html).toContain('sendgrid.net');
		expect(out.trackersBlocked).toBe(1); // still counted, just not stripped
	});

	it('a benign remote image is not miscounted as a tracker', () => {
		const out = { trackersBlocked: 0 };
		sanitizeHTML('<img src="https://example.com/logo.png" width="200" height="60">', { allowRemoteImages: true }, out);
		expect(out.trackersBlocked).toBe(0);
	});
});

describe('link-wrapper flagging (U3 Item B)', () => {
	function tokenFor(url: string): string {
		const payload = JSON.stringify({ u: url, m: 'msg1', b: 1, e: 9999999999 });
		const payloadB64 = Buffer.from(payload, 'utf-8').toString('base64url');
		return `${payloadB64}.deadbeefsig`; // signature is never verified client-side
	}

	it('flags a link-protect wrapped tracker URL with the REAL host in the title tooltip', () => {
		const href = `/link-protect?token=${tokenFor('https://sendgrid.net/click?id=1')}`;
		const out = sanitizeHTML(`<a href="${href}">Read more</a>`);
		expect(out).toContain('title="via sendgrid.net"');
		expect(out).toContain(`href="${href}"`); // href unchanged — no auto-unwrap
	});

	it('flags a raw (unwrapped) tracker-domain href', () => {
		const out = sanitizeHTML('<a href="https://click.mailer.example/go?x=1">Unsubscribe</a>');
		expect(out).toContain('title="via click.mailer.example"');
	});

	it('flags a link whose visible text names a different host than the href resolves to', () => {
		const out = sanitizeHTML('<a href="https://evil.example/phish">https://mybank.example/login</a>');
		expect(out).toContain('title="via evil.example"');
	});

	it('leaves a benign link untouched (no title added)', () => {
		const html = '<a href="https://example.com/docs">Documentation</a>';
		const out = sanitizeHTML(html);
		expect(out).toBe(html);
	});

	it('leaves a relative link untouched', () => {
		const html = '<a href="/inbox">Inbox</a>';
		const out = sanitizeHTML(html);
		expect(out).toBe(html);
	});
});

describe('escapeHTML (text→HTML boundary, occ_b60bbe1192d7e36f597f1d56)', () => {
	it('entity-encodes every HTML-significant character', () => {
		expect(escapeHTML('<img src="https://evil.example/p.gif">')).toBe(
			'&lt;img src=&quot;https://evil.example/p.gif&quot;&gt;',
		);
		expect(escapeHTML("a & b < c > d ' e")).toBe('a &amp; b &lt; c &gt; d &#39; e');
	});

	it('plain text with a tracking pixel lands as inert text after the newline pass', () => {
		// The exact composition loadReplyContext performs on a text-only mail.
		const html = escapeHTML('hi\n<img src="https://attacker.example/px">').replace(/\n/g, '<br>');
		expect(html).not.toMatch(/<img/);
		expect(html).toContain('&lt;img');
		expect(html).toContain('<br>');
	});

	it('is idempotent-safe on already-escaped text (no double-decode)', () => {
		expect(escapeHTML('&lt;img&gt;')).toBe('&amp;lt;img&amp;gt;');
	});
});

describe('renderEmailBodyHTML (card + print shared render)', () => {
	it('rewrites inline cid: images to /blobs/<sha> and sanitizes away script', () => {
		const out = renderEmailBodyHTML({
			bodyHTML: '<img src="cid:logo@x"><script>alert(1)</script><b>hi</b>',
			inlineImages: { 'cid:logo@x': 'deadbeef' },
		});
		expect(out).toContain('/blobs/deadbeef');
		expect(out).not.toContain('cid:logo@x');
		expect(out).not.toContain('<script');
		expect(out).not.toContain('alert');
		expect(out).toContain('<b>hi</b>');
	});

	it('returns empty string when there is no HTML body', () => {
		expect(renderEmailBodyHTML({ bodyHTML: undefined })).toBe('');
		expect(renderEmailBodyHTML({ bodyHTML: '' })).toBe('');
	});

	it('blocks remote images by default but keeps them when opted in', () => {
		expect(renderEmailBodyHTML({ bodyHTML: '<img src="https://t.example/p.gif">' })).not.toContain('t.example');
		expect(
			renderEmailBodyHTML({ bodyHTML: '<img src="https://t.example/p.gif">' }, { allowRemoteImages: true }),
		).toContain('t.example');
	});
});
