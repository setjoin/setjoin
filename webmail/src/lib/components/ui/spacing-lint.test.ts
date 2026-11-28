/// <reference types="node" />
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

/**
 * Spacing-token contract lint (DESIGN.md §4/§7).
 *
 * The token-only contract extends from colour to SPACING: component <style>
 * blocks should express gap/padding/margin/height/width via the 4px-grid
 * spacing + layout tokens (`--space-*`, `--row-height`, `--control-height*`,
 * `--sidebar-width`, …), not raw px.
 *
 * Reality: the 28 M1 primitives were authored before this mandate and carry
 * many *intentional* fine-grained values (e.g. a 5px field-stack gap, a 7px
 * badge inset, a 9px caret offset) that are deliberately off the 4px grid.
 * Rewriting all of them at once is out of scope and risky.
 *
 * So this is a **ratchet**: each primitive has a frozen baseline raw-px-spacing
 * count. A file may not EXCEED its baseline (new raw-px spacing fails the
 * build — that is the contract going forward), and a primitive with no baseline
 * entry must be raw-px-free. Baselines may only be LOWERED as primitives are
 * migrated to tokens; lowering one below its recorded number also fails (so the
 * baseline can't silently drift up after a reduction). Allowed without counting:
 * 1px hairlines / -1px overlaps (the documented exception).
 *
 * TODO (recorded in DESIGN.md §7): widen this scan from the 28 primitives to
 * all of src/**\/*.svelte once the primitive baselines reach zero.
 */

const uiDir = dirname(fileURLToPath(import.meta.url)); // src/lib/components/ui

// Spacing / layout-geometry properties governed by the contract.
const PROP =
	/(?:^|[\s;{])(gap|row-gap|column-gap|padding|padding-top|padding-right|padding-bottom|padding-left|margin|margin-top|margin-right|margin-bottom|margin-left|height|min-height|max-height|width|min-width|max-width|top|right|bottom|left|inset)\s*:\s*([^;}]+)[;}]/gi;

function styleBlock(src: string): string {
	const m = src.match(/<style>([\s\S]*?)<\/style>/);
	return m ? m[1] : '';
}

/** Count raw-px spacing values, excluding var() refs and ±1px hairlines. */
function countRawPx(css: string): number {
	let n = 0;
	let m: RegExpExecArray | null;
	PROP.lastIndex = 0;
	while ((m = PROP.exec(css)) !== null) {
		const stripped = m[2].replace(/var\([^)]*\)/g, ''); // drop token refs
		const pxNums = stripped.match(/-?\d*\.?\d+px/g) ?? [];
		for (const p of pxNums) {
			if (Math.abs(parseFloat(p)) === 1) continue; // 1px hairline allowed
			n++;
		}
	}
	return n;
}

// Frozen baseline (2026-06-20). Files absent here must be raw-px-free.
// Numbers may only go DOWN (migrate to tokens), never up (new raw-px fails).
const BASELINE: Record<string, number> = {
	'Badge.svelte': 7,
	'Button.svelte': 4,
	'Card.svelte': 5,
	'Checkbox.svelte': 3,
	'DateTimePicker.svelte': 6,
	'Dialog.svelte': 14,
	'EmptyState.svelte': 5,
	'Input.svelte': 3,
	'Menu.svelte': 9,
	'Pagination.svelte': 4,
	'Progress.svelte': 1,
	'Radio.svelte': 5,
	'Resizer.svelte': 1,
	'Select.svelte': 5,
	'SidebarItem.svelte': 6,
	'Slider.svelte': 1, // 44px coarse-pointer touch target (platform constant, not a design variable)
	'Spinner.svelte': 6,
	'Switch.svelte': 0,
	'Table.svelte': 3,
	'Tabs.svelte': 6,
	'Tag.svelte': 16,
	'Textarea.svelte': 2,
	'Toast.svelte': 13,
	'Tooltip.svelte': 5
};

const primitives = readdirSync(uiDir)
	.filter((f) => f.endsWith('.svelte'))
	.sort();

describe('spacing-token contract — 28 UI primitives (ratchet)', () => {
	it('finds the primitive set on disk', () => {
		// 26 .svelte components (the "28-primitive" library counts 2 plain-module
		// helpers, e.g. toasts service + tag colors, that have no .svelte file).
		expect(primitives.length).toBeGreaterThanOrEqual(26);
	});

	for (const file of primitives) {
		it(`${file}: raw-px spacing does not exceed its frozen baseline`, () => {
			const css = styleBlock(readFileSync(join(uiDir, file), 'utf-8'));
			const count = countRawPx(css);
			const baseline = BASELINE[file] ?? 0;
			// New raw-px spacing (above baseline) is a contract violation.
			expect(
				count,
				count > baseline
					? `${file} introduced new raw-px spacing (${count} > baseline ${baseline}) — use --space-*/layout tokens`
					: `${file} reduced raw-px spacing to ${count}; lower its BASELINE entry to ${count} to lock in the win`
			).toBe(baseline);
		});
	}

	it('every baseline entry maps to a real primitive file (no stale baselines)', () => {
		for (const file of Object.keys(BASELINE)) {
			expect(primitives, `baseline names missing file: ${file}`).toContain(file);
		}
	});
});
