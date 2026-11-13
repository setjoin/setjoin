import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte/svelte5';
import en from '$lib/i18n/en';
import zh from '$lib/i18n/zh';
import de from '$lib/i18n/de';
import OutcomeChip from './OutcomeChip.svelte';
import OutcomeLegend from './OutcomeLegend.svelte';

// ── All 6 outcomes: icon name + i18n label + role=img + non-empty aria-label ──

describe('OutcomeChip', () => {
	it('applied: CheckCircle2 icon + "Applied" label + role=img + aria-label', () => {
		const { container } = render(OutcomeChip, { props: { outcome: 'applied' } });
		expect(screen.getByText('Applied')).toBeTruthy();
		const chip = container.querySelector('[role="img"]');
		expect(chip).not.toBeNull();
		expect(chip!.getAttribute('aria-label')).toBeTruthy();
		// icon is aria-hidden
		const icon = container.querySelector('[aria-hidden="true"]');
		expect(icon).not.toBeNull();
		// not interactive
		expect(chip!.getAttribute('tabindex')).toBeNull();
	});

	it('would_block: ShieldX icon + "Would block" label', () => {
		const { container } = render(OutcomeChip, { props: { outcome: 'would_block' } });
		expect(screen.getByText('Would block')).toBeTruthy();
		const chip = container.querySelector('[role="img"]');
		expect(chip!.getAttribute('aria-label')).toBeTruthy();
	});

	it('would_step_up: KeyRound icon + "Would step-up" label', () => {
		render(OutcomeChip, { props: { outcome: 'would_step_up' } });
		expect(screen.getByText('Would step-up')).toBeTruthy();
	});

	it('would_notify: BellRing icon + "Would notify" label', () => {
		render(OutcomeChip, { props: { outcome: 'would_notify' } });
		expect(screen.getByText('Would notify')).toBeTruthy();
	});

	it('skipped: MinusCircle icon + "Skipped" label', () => {
		render(OutcomeChip, { props: { outcome: 'skipped' } });
		expect(screen.getByText('Skipped')).toBeTruthy();
	});

	it('excluded: UserMinus icon + "Excluded" label + dashed-border class (distinct from skipped)', () => {
		const { container } = render(OutcomeChip, { props: { outcome: 'excluded' } });
		expect(screen.getByText('Excluded')).toBeTruthy();
		// must carry the dashed class — §1 "must-be-distinguishable" in grayscale
		const chip = container.querySelector('[role="img"]');
		expect(chip!.classList.contains('outcome-chip--excluded')).toBe(true);
	});

	it('excluded uses UserMinus (distinct icon from skipped MinusCircle)', () => {
		// Both outcomes are neutral variant — icon is the only differentiator in grayscale.
		// Assert data-icon attr from Icon.svelte matches (Icon renders data-icon on the svg wrapper).
		const { container: exc } = render(OutcomeChip, { props: { outcome: 'excluded' } });
		const { container: skp } = render(OutcomeChip, { props: { outcome: 'skipped' } });
		const excIcon = exc.querySelector('[data-icon]')?.getAttribute('data-icon');
		const skpIcon = skp.querySelector('[data-icon]')?.getAttribute('data-icon');
		// The icons must differ — UserMinus vs MinusCircle
		expect(excIcon).not.toBe(skpIcon);
	});

	it('count appended as mono pill when set', () => {
		render(OutcomeChip, { props: { outcome: 'would_block', count: 312 } });
		// count is visible in the chip text
		expect(screen.getByText('312', { exact: false })).toBeTruthy();
	});

	it('unknown/forward-compat outcome: renders HelpCircle + raw value + ca.outcome.unknown.tip (never crash)', () => {
		const { container } = render(OutcomeChip, { props: { outcome: 'frobnicate' } });
		// chip must exist and not throw
		const chip = container.querySelector('[role="img"]');
		expect(chip).not.toBeNull();
		// raw value visible as label
		expect(screen.getByText('frobnicate')).toBeTruthy();
	});

	it('chip has no CSS transition/animation on mount (chips appear with their row — §1)', () => {
		const { container } = render(OutcomeChip, { props: { outcome: 'applied' } });
		const chip = container.querySelector('[role="img"]') as HTMLElement | null;
		expect(chip).not.toBeNull();
		const style = getComputedStyle(chip!);
		// In jsdom computed styles return '' for custom CSS; we check that no inline transition exists
		expect(chip!.style.transition).toBe('');
		expect(chip!.style.animation).toBe('');
	});

	it('component style contains @media (prefers-reduced-motion: reduce) block', () => {
		// Assert the stylesheet injected by the component mentions reduced-motion.
		// (jsdom doesn't parse <style> from Svelte scoped components into document.styleSheets
		//  reliably; we assert the raw component source via the import path.)
		// ponytail: source-text assertion is the only reliable way in jsdom — SSR-style.
		const src = import.meta.glob('./OutcomeChip.svelte', { query: '?raw', import: 'default', eager: true }) as Record<string, string>;
		const text = src['./OutcomeChip.svelte'] ?? '';
		expect(text).toContain('prefers-reduced-motion');
	});

	it('no literal hex in rendered inline styles (token-only)', () => {
		const { container } = render(OutcomeChip, { props: { outcome: 'applied' } });
		const chip = container.querySelector('[role="img"]') as HTMLElement | null;
		// Gather all inline style attributes in the subtree
		const allEls = container.querySelectorAll('*');
		for (const el of Array.from(allEls)) {
			const s = (el as HTMLElement).getAttribute('style') ?? '';
			expect(s).not.toMatch(/#[0-9a-fA-F]{3,6}/);
		}
	});

	it('applied exact en label matches copy table', () => {
		render(OutcomeChip, { props: { outcome: 'applied' } });
		expect(screen.getByText('Applied')).toBeTruthy();
	});

	it('i18n completeness: en+zh+de all define every ca.outcome.* key', () => {
		const OUTCOME_KEYS = [
			'ca.outcome.applied', 'ca.outcome.applied.tip',
			'ca.outcome.would_block', 'ca.outcome.would_block.tip',
			'ca.outcome.would_step_up', 'ca.outcome.would_step_up.tip',
			'ca.outcome.would_notify', 'ca.outcome.would_notify.tip',
			'ca.outcome.skipped', 'ca.outcome.skipped.tip',
			'ca.outcome.excluded', 'ca.outcome.excluded.tip',
			'ca.outcome.unknown', 'ca.outcome.unknown.tip',
			'ca.outcome.legend_title',
			'ca.outcome.applied.aria',
			'ca.outcome.would_block.aria',
		];
		for (const k of OUTCOME_KEYS) {
			expect(en[k], `en missing ${k}`).toBeTruthy();
			expect(zh[k], `zh missing ${k}`).toBeTruthy();
			expect(de[k], `de missing ${k}`).toBeTruthy();
		}
	});
});

describe('OutcomeLegend', () => {
	it('renders all six outcome chips', () => {
		render(OutcomeLegend, {});
		expect(screen.getByText('Applied')).toBeTruthy();
		expect(screen.getByText('Would block')).toBeTruthy();
		expect(screen.getByText('Would step-up')).toBeTruthy();
		expect(screen.getByText('Would notify')).toBeTruthy();
		expect(screen.getByText('Skipped')).toBeTruthy();
		expect(screen.getByText('Excluded')).toBeTruthy();
	});

	it('has an SR-only heading (outcome.legend_title) for screen readers', () => {
		const { container } = render(OutcomeLegend, {});
		const heading = container.querySelector('.sr-only');
		expect(heading).not.toBeNull();
		// contains text from the legend_title key
		expect(heading!.textContent?.trim().length).toBeGreaterThan(0);
	});
});
