/**
 * CA-3b machine guard: every CA-3b webmail surface that declares a CSS
 * transition or animation MUST also contain a
 * `@media (prefers-reduced-motion: reduce)` block.
 *
 * This is a file-level structural check — it reads each .svelte source and
 * asserts the guard is present whenever motion tokens appear.  A future
 * contributor who adds a `transition:` to one of these files without the
 * guard will fail THIS test, not a manual review.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const FILES = [
	'src/lib/components/TermsAcceptance.svelte',
	'src/lib/components/RiskRemediation.svelte',
	'src/lib/components/CertStatusCard.svelte',
	'src/routes/blocked/+page.svelte',
	'src/routes/admin/(access)/user-risk/+page.svelte',
	'src/routes/admin/(identity)/terms-of-use/+page.svelte',
];

describe('CA-3b surfaces honor prefers-reduced-motion', () => {
	for (const f of FILES) {
		it(`${f} guards motion`, () => {
			const src = readFileSync(resolve(process.cwd(), f), 'utf8');
			const hasMotion = /transition\s*:|animation\s*:/.test(src);
			if (hasMotion) {
				expect(src, `${f} has motion but is missing @media (prefers-reduced-motion: reduce)`)
					.toMatch(/@media[^{]*prefers-reduced-motion\s*:\s*reduce/);
			} else {
				// No motion in this file — nothing to guard (ponytail: YAGNI applies to guards too).
				expect(true).toBe(true);
			}
		});
	}
});
