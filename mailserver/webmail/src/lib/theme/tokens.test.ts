import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

// vitest runs in Node, so we read the actual committed files from disk —
// the reliable way to regression-guard real CSS content. (Vite ?raw imports
// return an empty string for .css under the vitest CSS pipeline.) The per-file
// `/// <reference types="node" />` keeps svelte-check happy without touching the
// project tsconfig, which intentionally sets "types": [].
const themeDir = dirname(fileURLToPath(import.meta.url)); // src/lib/theme
const read = (rel: string): string => readFileSync(join(themeDir, rel), 'utf-8');

const colorsCss = read('colors.css');
const fontsCss = read('fonts.css');
const typographyCss = read('typography.css');
const globalCss = read('global.css');
const baseCss = read('base.css');
const spacingCss = read('spacing.css');
const appCss = read('../../app.css');
const appHtml = read('../../app.html');

// Named map of all theme CSS files (mirrors the files in this directory)
const themeCssFiles: Record<string, string> = {
	'colors.css': colorsCss,
	'fonts.css': fontsCss,
	'typography.css': typographyCss,
	'global.css': globalCss,
	'base.css': baseCss,
	'spacing.css': spacingCss,
};

describe('setjoin theme tokens', () => {
	it('the old Liquid Glass tokens.css is gone', () => {
		expect(existsSync(join(themeDir, 'tokens.css'))).toBe(false);
	});

	it('compat.css is deleted (M8 bridge cleanup)', () => {
		expect(existsSync(join(themeDir, 'compat.css'))).toBe(false);
	});

	it('legacy Inter, Inter Tight, JetBrains Mono font files are deleted', () => {
		const fontsDir = join(themeDir, '../../../static/fonts');
		expect(existsSync(join(fontsDir, 'inter-400.woff2'))).toBe(false);
		expect(existsSync(join(fontsDir, 'jetbrains-mono-400.woff2'))).toBe(false);
	});

	it('colors.css defines a [data-theme="dark"] block', () => {
		expect(colorsCss).toMatch(/\[data-theme="dark"\]\s*\{/);
	});

	it('--focus-ring is defined for light and dark', () => {
		const matches = colorsCss.match(/--focus-ring:/g) ?? [];
		expect(matches.length).toBe(2);
	});

	it('--accent resolves to the indigo scale in both themes', () => {
		expect(colorsCss).toMatch(/--accent:\s*var\(--indigo-600\)/); // light
		expect(colorsCss).toMatch(/--accent:\s*var\(--indigo-500\)/); // dark
		expect(colorsCss).toMatch(/--indigo-600:\s*#4A50D0/);
	});

	it('no backdrop-filter or blur() anywhere in theme css', () => {
		const entries = Object.entries(themeCssFiles);
		expect(entries.length).toBeGreaterThanOrEqual(6);
		for (const [f, css] of entries) {
			expect(css, `${f} must not use backdrop-filter`).not.toMatch(/backdrop-filter/);
			expect(css, `${f} must not use blur(`).not.toMatch(/blur\(/);
		}
	});

	it('app.css has no glass remnants and no press-scale transforms', () => {
		expect(appCss).not.toMatch(/backdrop-filter/);
		expect(appCss).not.toMatch(/blur\(/);
		expect(appCss).not.toMatch(/transform:\s*scale/);
	});

	it('fonts.css self-hosts exactly 7 IBM Plex faces, all swap, no CDN', () => {
		const plexFaces = fontsCss.match(/font-family:\s*'IBM Plex (Sans|Mono)'/g) ?? [];
		expect(plexFaces.length).toBe(7);
		const swaps = fontsCss.match(/font-display:\s*swap/g) ?? [];
		expect(swaps.length).toBe(7);
		expect(fontsCss).not.toMatch(/@import/);
		expect(fontsCss).not.toMatch(/googleapis/);
		expect(fontsCss).not.toMatch(/noto-sans-sc-\d+\.woff2/);
	});

	it('--font-sans tries system CJK before the distinct sharded fallback', () => {
		const stack = typographyCss.match(/--font-sans:\s*([^;]+);/)?.[1] ?? '';
		expect(stack).toContain('"IBM Plex Sans"');
		expect(stack).toContain('"PingFang SC"');
		expect(stack).toContain('"Microsoft YaHei UI"');
		expect(stack).toContain('"Noto Sans CJK SC"');
		expect(stack).toContain('"Setjoin Noto SC Fallback"');
		expect(stack.indexOf('"PingFang SC"')).toBeLessThan(stack.indexOf('"Setjoin Noto SC Fallback"'));
		expect(stack.indexOf('"Noto Sans CJK SC"')).toBeLessThan(stack.indexOf('"Setjoin Noto SC Fallback"'));
	});

	it('global.css imports the five theme files and keeps a11y rules', () => {
		for (const f of ['fonts.css', 'fonts-cjk.generated.css', 'colors.css', 'typography.css', 'spacing.css', 'base.css']) {
			expect(globalCss, `global.css must import ${f}`).toContain(`@import './${f}'`);
		}
		expect(globalCss).toContain('.sr-only');
		expect(globalCss).toMatch(/prefers-reduced-motion/);
		expect(globalCss).not.toMatch(/aurora/);
		expect(globalCss).toMatch(/\[data-density="compact"\]\s*\{[^}]*--row-height:\s*30px/);
	});

	it('app.html applies the persisted theme before first paint', () => {
		expect(appHtml).toContain("localStorage.getItem('sj-theme')");
		expect(appHtml).toContain('dataset.theme');
		expect(appHtml).toContain('dataset.density');
		expect(appHtml).toMatch(/matchMedia\('\(prefers-color-scheme: dark\)'\)/);
	});
});

// ── Token resolution + WCAG contrast helpers ────────────────────────────
// The :root block holds the light theme; [data-theme="dark"] overrides a
// subset. We parse each block's `--name: value;` declarations, then resolve
// `var(--x)` chains within a theme (dark falling back to light for tokens it
// doesn't override — mirroring the cascade).

/** Strip /* *\/ CSS comments so they can't be mis-parsed as declarations. */
function stripComments(css: string): string {
	return css.replace(/\/\*[\s\S]*?\*\//g, '');
}

/** Parse `--name: value;` pairs out of a single CSS block body. */
function parseDecls(block: string): Record<string, string> {
	const out: Record<string, string> = {};
	const re = /(--[a-z0-9-]+)\s*:\s*([^;]+);/gi;
	let m: RegExpExecArray | null;
	const clean = stripComments(block);
	while ((m = re.exec(clean)) !== null) out[m[1]] = m[2].trim();
	return out;
}

/** Extract the body of the first `:root { ... }` block (light theme). */
function rootBlock(css: string): string {
	const i = css.indexOf(':root');
	const open = css.indexOf('{', i);
	// Balance braces to find the matching close.
	let depth = 0;
	for (let j = open; j < css.length; j++) {
		if (css[j] === '{') depth++;
		else if (css[j] === '}' && --depth === 0) return css.slice(open + 1, j);
	}
	return '';
}

/** Extract the body of the `[data-theme="dark"] { ... }` block. */
function darkBlock(css: string): string {
	const i = css.indexOf('[data-theme="dark"]');
	const open = css.indexOf('{', i);
	let depth = 0;
	for (let j = open; j < css.length; j++) {
		if (css[j] === '{') depth++;
		else if (css[j] === '}' && --depth === 0) return css.slice(open + 1, j);
	}
	return '';
}

const lightDecls = parseDecls(rootBlock(colorsCss));
const darkOverrides = parseDecls(darkBlock(colorsCss));
// Dark theme = light base with dark overrides layered on (the real cascade).
const darkDecls: Record<string, string> = { ...lightDecls, ...darkOverrides };

/** Resolve a token (following `var(--x)` chains) to a literal value. */
function resolve(name: string, decls: Record<string, string>, seen = new Set<string>()): string {
	const raw = decls[name];
	if (raw === undefined) throw new Error(`token ${name} is undefined in this theme`);
	const varMatch = raw.match(/^var\((--[a-z0-9-]+)\)$/i);
	if (varMatch) {
		if (seen.has(name)) throw new Error(`circular var() for ${name}`);
		seen.add(name);
		return resolve(varMatch[1], decls, seen);
	}
	return raw;
}

function toRgb(hex: string): [number, number, number] {
	const h = hex.trim().replace('#', '');
	const full = h.length === 3 ? h.split('').map((c) => c + c).join('') : h;
	return [
		parseInt(full.slice(0, 2), 16),
		parseInt(full.slice(2, 4), 16),
		parseInt(full.slice(4, 6), 16)
	];
}
function relLum(hex: string): number {
	const lin = (c: number) => {
		const s = c / 255;
		return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
	};
	const [r, g, b] = toRgb(hex);
	return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}
function contrast(a: string, b: string): number {
	const la = relLum(a);
	const lb = relLum(b);
	const hi = Math.max(la, lb);
	const lo = Math.min(la, lb);
	return (hi + 0.05) / (lo + 0.05);
}

const TAG_HUES = ['blue', 'teal', 'green', 'amber', 'orange', 'rose', 'purple', 'gray'] as const;

describe('setjoin token a11y contrast (WCAG AA, light theme)', () => {
	// Page = --surface-page (gray-50 #F6F7F9); Card = --surface-card (gray-0 #FFFFFF).
	const page = resolve('--surface-page', lightDecls);
	const card = resolve('--surface-card', lightDecls);

	it('--surface-page and --surface-card resolve to expected light beds', () => {
		expect(page.toUpperCase()).toBe('#F6F7F9');
		expect(card.toUpperCase()).toBe('#FFFFFF');
	});

	// These tokens carry small text that MUST be read (hints, labels, captions,
	// timestamps, counts). They must clear the 4.5:1 AA floor on both beds.
	for (const token of ['--text-caption', '--text-secondary']) {
		it(`${token} is >= 4.5:1 on the page surface`, () => {
			expect(contrast(resolve(token, lightDecls), page)).toBeGreaterThanOrEqual(4.5);
		});
		it(`${token} is >= 4.5:1 on the card surface`, () => {
			expect(contrast(resolve(token, lightDecls), card)).toBeGreaterThanOrEqual(4.5);
		});
	}

	it('--text-tertiary is intentionally below AA for body text (decorative only)', () => {
		// Documents WHY a separate --text-caption exists: tertiary fails the floor,
		// so it must not be used for small must-read text.
		expect(contrast(resolve('--text-tertiary', lightDecls), page)).toBeLessThan(4.5);
	});

	it('--link-visited stays >= 4.5:1 on page and card', () => {
		expect(contrast(resolve('--link-visited', lightDecls), page)).toBeGreaterThanOrEqual(4.5);
		expect(contrast(resolve('--link-visited', lightDecls), card)).toBeGreaterThanOrEqual(4.5);
	});
});

describe('setjoin token a11y contrast (WCAG AA, dark theme)', () => {
	const page = resolve('--surface-page', darkDecls);
	const card = resolve('--surface-card', darkDecls);
	for (const token of ['--text-caption', '--text-secondary']) {
		it(`${token} is >= 4.5:1 on dark page and card`, () => {
			expect(contrast(resolve(token, darkDecls), page)).toBeGreaterThanOrEqual(4.5);
			expect(contrast(resolve(token, darkDecls), card)).toBeGreaterThanOrEqual(4.5);
		});
	}
});

describe('--success-fg contrast guard (verified icon, WCAG non-text 3:1 floor)', () => {
	// The verified shield uses --success-fg on the card surface (--surface-card).
	// Non-text graphical UI components must clear 3:1 (WCAG 1.4.11).
	it('light: --success-fg vs --surface-card is >= 3.0:1', () => {
		const fg = resolve('--success-fg', lightDecls);
		const card = resolve('--surface-card', lightDecls);
		expect(contrast(fg, card)).toBeGreaterThanOrEqual(3.0);
	});

	it('dark: --success-fg vs --surface-card is >= 3.0:1', () => {
		const fg = resolve('--success-fg', darkDecls);
		const card = resolve('--surface-card', darkDecls);
		expect(contrast(fg, card)).toBeGreaterThanOrEqual(3.0);
	});
});

describe('tag palette is complete in BOTH themes', () => {
	// Tag.svelte renders var(--tag-{color}-{bg|fg|dot}); a missing dot token
	// fails to resolve at runtime (the dark-mode tag-dot bug). Assert every hue
	// defines bg + fg + dot in each theme, and that each resolves to a literal.
	for (const hue of TAG_HUES) {
		for (const part of ['bg', 'fg', 'dot'] as const) {
			const token = `--tag-${hue}-${part}`;
			it(`light: ${token} is defined and resolves`, () => {
				expect(() => resolve(token, lightDecls)).not.toThrow();
				expect(resolve(token, lightDecls)).toMatch(/^#[0-9a-fA-F]{3,8}$/);
			});
			it(`dark: ${token} is defined and resolves`, () => {
				expect(() => resolve(token, darkDecls)).not.toThrow();
				expect(resolve(token, darkDecls)).toMatch(/^#[0-9a-fA-F]{3,8}$/);
			});
		}
	}

	it('the dark block explicitly defines all 8 tag dots (regression: only gray existed)', () => {
		const dark = darkBlock(colorsCss);
		for (const hue of TAG_HUES) {
			expect(dark, `dark --tag-${hue}-dot must be present`).toMatch(
				new RegExp(`--tag-${hue}-dot\\s*:`)
			);
		}
	});
});
