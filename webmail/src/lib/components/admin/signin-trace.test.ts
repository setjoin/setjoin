import { describe, it, expect } from 'vitest';
import { outcomeChip, OUTCOME_LEGEND, decisionVariant } from './signin-trace';

describe('signin-trace helpers', () => {
	it('maps every outcome to a chip matching shared-doc §1 (no local drift)', () => {
		// Variants are the single-sourced design-system-additions.md §1 mapping.
		expect(outcomeChip('applied').variant).toBe('success');     // enforced = green (§1)
		expect(outcomeChip('would_block').variant).toBe('danger');
		expect(outcomeChip('would_step_up').variant).toBe('info');
		expect(outcomeChip('would_notify').variant).toBe('warning');
		expect(outcomeChip('skipped').variant).toBe('neutral');
		expect(outcomeChip('excluded').variant).toBe('neutral');    // neutral, distinct icon (§1)
	});
	it('distinguishes skipped vs excluded by icon (§1 — never collapse)', () => {
		expect(outcomeChip('skipped').icon).toBe('MinusCircle');
		expect(outcomeChip('excluded').icon).toBe('UserMinus');
	});
	it('uses the shared ca.outcome.* i18n namespace (not a bespoke admin.ca.outcome.*)', () => {
		expect(outcomeChip('applied').key).toBe('ca.outcome.applied');
		expect(OUTCOME_LEGEND.every((o) => o.key.startsWith('ca.outcome.'))).toBe(true);
	});
	it('legend covers exactly the six outcomes', () => {
		expect(OUTCOME_LEGEND.map((o) => o.outcome).sort()).toEqual(
			['applied', 'excluded', 'skipped', 'would_block', 'would_notify', 'would_step_up'].sort()
		);
	});
	it('falls back to the §1 unknown chip for a forward-compat outcome (never crashes)', () => {
		const u = outcomeChip('some_future_outcome');
		expect(u.variant).toBe('neutral');
		expect(u.icon).toBe('HelpCircle');
	});
	it('does not let Object.prototype keys bypass the unknown-outcome fallback', () => {
		for (const protoKey of ['constructor', 'toString', '__proto__', 'hasOwnProperty']) {
			const chip = outcomeChip(protoKey);
			expect(chip.outcome).toBe('unknown');
			expect(chip.variant).toBe('neutral');
			expect(chip.icon).toBe('HelpCircle');
		}
	});
	it('badges the effective decision', () => {
		expect(decisionVariant('block')).toBe('danger');
		expect(decisionVariant('allow')).toBe('success');
		expect(decisionVariant('step_up')).toBe('warning');
	});
});
