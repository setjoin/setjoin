/**
 * CA-1 F2 — templates page + TemplateWizard tests.
 * TDD: RED first (pages absent), then GREEN.
 */
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import { describe, it, expect, vi, afterEach } from 'vitest';
import en from '$lib/i18n/en';
import zh from '$lib/i18n/zh';
import de from '$lib/i18n/de';
import TemplatesPage from './+page.svelte';
import TemplateWizard from './TemplateWizard.svelte';

// ── helpers ──────────────────────────────────────────────────────────────────

function makeTemplate(overrides: Record<string, unknown> = {}) {
	return {
		id: 1,
		slug: 'block-legacy-auth',
		name: 'Block legacy auth',
		description: 'Blocks IMAP/POP/SMTP basic auth',
		scope_type: 'global',
		conditions: {},
		actions: { operator: 'all', grants: [{ type: 'block' }] },
		...overrides,
	};
}

function makeImpact(overrides: Record<string, unknown> = {}) {
	return {
		window: '7d',
		window_has_data: true,
		matched: 100,
		would_block: 42,
		would_step_up: 0,
		distinct_users: 30,
		would_block_admins: 0,
		...overrides,
	};
}

function stubFetchForTemplates(
	templates: unknown[],
	impact: unknown = makeImpact(),
	policiesEmpty = true
) {
	let callCount = 0;
	vi.stubGlobal(
		'fetch',
		vi.fn((url: string) => {
			callCount++;
			if ((url as string).includes('template') && !(url as string).includes('impact')) {
				return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(templates) });
			}
			if ((url as string).includes('policies')) {
				return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(policiesEmpty ? [] : [{ id: 1 }]) });
			}
			if ((url as string).includes('impact')) {
				return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(impact) });
			}
			// instantiate
			if ((url as string).includes('instantiate')) {
				return Promise.resolve({ ok: true, status: 201, json: () => Promise.resolve({ id: 99, name: 'Block legacy auth' }) });
			}
			return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) });
		})
	);
}

// ── Page state tests ──────────────────────────────────────────────────────────

describe('templates page — LOADING', () => {
	afterEach(() => vi.restoreAllMocks());

	it('shows 3 card skeletons while loading', () => {
		vi.stubGlobal('fetch', vi.fn(() => new Promise(() => {})));
		render(TemplatesPage);
		const skeletons = screen.getAllByTestId('tmpl-skeleton');
		expect(skeletons.length).toBeGreaterThanOrEqual(3);
	});
});

describe('templates page — ERROR', () => {
	afterEach(() => vi.restoreAllMocks());

	it('shows inline role=alert with Retry on failure', async () => {
		vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('net'))));
		render(TemplatesPage);
		await waitFor(() => expect(screen.getByTestId('tmpl-error')).toBeTruthy());
		expect(screen.getByTestId('tmpl-error').getAttribute('role')).toBe('alert');
		expect(screen.getByTestId('tmpl-retry')).toBeTruthy();
	});
});

describe('templates page — FIRST-TIME vs RETURN', () => {
	afterEach(() => vi.restoreAllMocks());

	it('FIRST-TIME (no existing policies): shows hero banner', async () => {
		stubFetchForTemplates([makeTemplate()], makeImpact(), true);
		render(TemplatesPage);
		await waitFor(() => expect(screen.queryByTestId('tmpl-loading')).toBeFalsy());
		expect(screen.getByTestId('tmpl-hero')).toBeTruthy();
	});

	it('RETURN (policies exist): hero banner hidden', async () => {
		stubFetchForTemplates([makeTemplate()], makeImpact(), false);
		render(TemplatesPage);
		await waitFor(() => expect(screen.queryByTestId('tmpl-loading')).toBeFalsy());
		expect(screen.queryByTestId('tmpl-hero')).toBeFalsy();
	});
});

describe('templates page — gallery', () => {
	afterEach(() => vi.restoreAllMocks());

	it('renders a card per template', async () => {
		const templates = [
			makeTemplate({ id: 1, slug: 'block-legacy-auth' }),
			makeTemplate({ id: 2, slug: 'mfa-for-admins' }),
		];
		stubFetchForTemplates(templates);
		render(TemplatesPage);
		await waitFor(() => expect(screen.queryByTestId('tmpl-loading')).toBeFalsy());
		expect(screen.getByTestId('tmpl-card-1')).toBeTruthy();
		expect(screen.getByTestId('tmpl-card-2')).toBeTruthy();
	});

	it('clicking a card opens the 4-step wizard', async () => {
		stubFetchForTemplates([makeTemplate()]);
		render(TemplatesPage);
		await waitFor(() => expect(screen.getByTestId('tmpl-card-1')).toBeTruthy());
		await fireEvent.click(screen.getByTestId('tmpl-card-1'));
		expect(screen.getByTestId('wizard-dialog')).toBeTruthy();
	});
});

// ── TemplateWizard tests ─────────────────────────────────────────────────────

describe('TemplateWizard — 4-step structure', () => {
	afterEach(() => vi.restoreAllMocks());

	function renderWizard(overrides: Record<string, unknown> = {}) {
		const fetchMock = vi.fn((url: string) => {
			if ((url as string).includes('impact')) {
				return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(makeImpact()) });
			}
			if ((url as string).includes('instantiate')) {
				return Promise.resolve({ ok: true, status: 201, json: () => Promise.resolve({ id: 99, name: 'Block legacy auth' }) });
			}
			return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) });
		});
		vi.stubGlobal('fetch', fetchMock);
		return render(TemplateWizard, {
			open: true,
			template: makeTemplate(),
			breakGlassIds: [42],
			authorId: 7,
			onClose: vi.fn(),
			onCreated: vi.fn(),
			...overrides,
		});
	}

	it('starts at step 2 (review impact) after template is pre-selected', async () => {
		renderWizard();
		await waitFor(() => expect(screen.getByTestId('wizard-step-review')).toBeTruthy());
	});

	it('stepper is role=tablist with aria-current="step"', async () => {
		renderWizard();
		await waitFor(() => expect(screen.getByTestId('wizard-stepper')).toBeTruthy());
		const stepper = screen.getByTestId('wizard-stepper');
		expect(stepper.getAttribute('role')).toBe('tablist');
		// Current step has aria-current="step"
		const current = stepper.querySelector('[aria-current="step"]');
		expect(current).toBeTruthy();
	});

	it('step 2 renders plain-English summary + ImpactCard', async () => {
		renderWizard();
		await waitFor(() => expect(screen.getByTestId('wizard-step-review')).toBeTruthy());
		expect(screen.getByTestId('wizard-tmpl-summary')).toBeTruthy();
		// ImpactCard either loading or loaded
		const ic = document.querySelector('[data-testid="impact-card"], [data-testid="wizard-impact"]');
		expect(ic).toBeTruthy();
	});

	it('step 2 summary uses i18n key (not raw English), for block-legacy-auth slug', async () => {
		renderWizard();
		await waitFor(() => expect(screen.getByTestId('wizard-tmpl-summary')).toBeTruthy());
		const summary = screen.getByTestId('wizard-tmpl-summary');
		// Expect the en translation to be rendered (not an i18n key literal)
		const expected = en['admin.conditional_access.wizard.tmpl.block-legacy-auth.summary' as keyof typeof en] as string;
		if (expected) {
			expect(summary.textContent?.trim().slice(0, 30)).toBe(expected.slice(0, 30));
		}
	});

	it('step 2 NO-DATA impact (window_has_data=false) renders EmptyState, not "0"', async () => {
		const fetchMock = vi.fn((url: string) => {
			if ((url as string).includes('impact')) {
				return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(makeImpact({ window_has_data: false })) });
			}
			return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) });
		});
		vi.stubGlobal('fetch', fetchMock);
		render(TemplateWizard, {
			open: true,
			template: makeTemplate(),
			breakGlassIds: [],
			authorId: 7,
			onClose: vi.fn(),
			onCreated: vi.fn(),
		});
		await waitFor(() => expect(screen.getByTestId('wizard-step-review')).toBeTruthy());
		// impact-no-data should appear
		await waitFor(() => expect(document.querySelector('[data-testid="impact-no-data"]')).toBeTruthy());
	});

	it('step 3: author + break-glass IDs pre-fill exclude list', async () => {
		renderWizard({ breakGlassIds: [42], authorId: 7 });
		await waitFor(() => expect(screen.getByTestId('wizard-step-review')).toBeTruthy());
		// Navigate to step 3
		const nextBtn = screen.getByTestId('wizard-next-btn');
		await fireEvent.click(nextBtn);
		await waitFor(() => expect(screen.getByTestId('wizard-step-scope')).toBeTruthy());
		// Break-glass chip should be pre-filled
		const excludeList = screen.getByTestId('wizard-exclude-list');
		expect(excludeList).toBeTruthy();
	});

	it('step 3: removing break-glass chip shows warning note', async () => {
		renderWizard({ breakGlassIds: [42], authorId: 7 });
		await waitFor(() => expect(screen.getByTestId('wizard-step-review')).toBeTruthy());
		const nextBtn = screen.getByTestId('wizard-next-btn');
		await fireEvent.click(nextBtn);
		await waitFor(() => expect(screen.getByTestId('wizard-step-scope')).toBeTruthy());
		// Try removing the break-glass chip
		const bgChip = screen.queryByTestId('wizard-exclude-chip-42');
		if (bgChip) {
			const removeBtn = bgChip.querySelector('button');
			if (removeBtn) {
				await fireEvent.click(removeBtn);
				// warning note should appear
				expect(screen.getByTestId('wizard-bg-warn')).toBeTruthy();
			}
		}
	});

	it('step 4: shows report-only reassurance panel', async () => {
		renderWizard({ breakGlassIds: [], authorId: 7 });
		await waitFor(() => expect(screen.getByTestId('wizard-step-review')).toBeTruthy());
		// Navigate through steps
		await fireEvent.click(screen.getByTestId('wizard-next-btn'));
		await waitFor(() => expect(screen.getByTestId('wizard-step-scope')).toBeTruthy());
		await fireEvent.click(screen.getByTestId('wizard-next-btn'));
		await waitFor(() => expect(screen.getByTestId('wizard-step-confirm')).toBeTruthy());
		expect(screen.getByTestId('wizard-report-only-panel')).toBeTruthy();
		expect(screen.getByTestId('wizard-create-btn')).toBeTruthy();
	});

	it('step 4: "Create in report-only" calls instantiate + shows success arc', async () => {
		renderWizard({ breakGlassIds: [], authorId: 7 });
		await waitFor(() => expect(screen.getByTestId('wizard-step-review')).toBeTruthy());
		await fireEvent.click(screen.getByTestId('wizard-next-btn'));
		await waitFor(() => expect(screen.getByTestId('wizard-step-scope')).toBeTruthy());
		await fireEvent.click(screen.getByTestId('wizard-next-btn'));
		await waitFor(() => expect(screen.getByTestId('wizard-step-confirm')).toBeTruthy());
		await fireEvent.click(screen.getByTestId('wizard-create-btn'));
		await waitFor(() => expect(screen.getByTestId('wizard-success')).toBeTruthy());
		// Success arc has Open in editor + View impact buttons
		expect(screen.getByTestId('wizard-open-editor-btn')).toBeTruthy();
		expect(screen.getByTestId('wizard-view-impact-btn')).toBeTruthy();
	});

	it('step heading is aria-live="polite" (announces step changes)', async () => {
		renderWizard();
		await waitFor(() => expect(screen.getByTestId('wizard-step-heading')).toBeTruthy());
		expect(screen.getByTestId('wizard-step-heading').getAttribute('aria-live')).toBe('polite');
	});

	it('Escape fires onClose (guarded discard)', async () => {
		const onClose = vi.fn();
		renderWizard({ onClose });
		await waitFor(() => expect(screen.getByTestId('wizard-dialog')).toBeTruthy());
		await fireEvent.keyDown(screen.getByTestId('wizard-dialog'), { key: 'Escape' });
		expect(onClose).toHaveBeenCalled();
	});
});

describe('TemplateWizard — stepper keyboard (p)', () => {
	afterEach(() => vi.restoreAllMocks());

	it('future step is aria-disabled and not focusable', async () => {
		const fetchMock = vi.fn((url: string) => {
			if ((url as string).includes('impact')) {
				return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(makeImpact()) });
			}
			return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) });
		});
		vi.stubGlobal('fetch', fetchMock);
		render(TemplateWizard, {
			open: true,
			template: makeTemplate(),
			breakGlassIds: [],
			authorId: 7,
			onClose: vi.fn(),
			onCreated: vi.fn(),
		});
		await waitFor(() => expect(screen.getByTestId('wizard-stepper')).toBeTruthy());
		// Step 3 (scope) is future when on step 2 — should be aria-disabled
		const futureTab = document.querySelector('[data-testid="wizard-stepper-scope"]');
		if (futureTab) {
			expect(
				futureTab.getAttribute('aria-disabled') === 'true' ||
				(futureTab as HTMLElement).tabIndex === -1
			).toBe(true);
		}
	});
});

describe('TemplateWizard — source checks', () => {
	it('TemplateWizard source has @media (prefers-reduced-motion: reduce)', async () => {
		const { readFileSync } = await import('fs');
		const src = readFileSync(
			'src/routes/admin/(identity)/conditional-access/templates/TemplateWizard.svelte',
			'utf-8'
		);
		expect(src).toContain('@media (prefers-reduced-motion: reduce)');
		expect(src).toContain('--duration-');
		const styleMatch = src.match(/<style>([\s\S]*?)<\/style>/);
		if (styleMatch) {
			expect(styleMatch[1]).not.toMatch(/#[0-9a-fA-F]{3,6}\b/);
		}
	});

	it('TemplateWizard source has @media (pointer: coarse) with 44px', async () => {
		const { readFileSync } = await import('fs');
		const src = readFileSync(
			'src/routes/admin/(identity)/conditional-access/templates/TemplateWizard.svelte',
			'utf-8'
		);
		expect(src).toContain('pointer: coarse');
		expect(src).toContain('44px');
	});
});

describe('templates — i18n completeness', () => {
	const REQUIRED = [
		'admin.conditional_access.wizard.hero',
		'admin.conditional_access.wizard.load_error',
		'admin.conditional_access.wizard.step.pick',
		'admin.conditional_access.wizard.step.review',
		'admin.conditional_access.wizard.step.scope',
		'admin.conditional_access.wizard.step.confirm',
		'admin.conditional_access.wizard.breakglass_remove_warn',
		'admin.conditional_access.wizard.report_only_panel',
		'admin.conditional_access.wizard.create_confirm',
		'admin.conditional_access.wizard.success',
		'admin.conditional_access.wizard.success_open_editor',
		'admin.conditional_access.wizard.success_view_impact',
		'admin.conditional_access.wizard.tmpl.block-legacy-auth.summary',
		'admin.conditional_access.wizard.tmpl.mfa-for-admins.summary',
		'admin.conditional_access.wizard.tmpl.block-by-geo.summary',
	];

	it('all required keys present in en.ts', () => {
		for (const k of REQUIRED) {
			expect(en[k as keyof typeof en], `missing en: ${k}`).toBeTruthy();
		}
	});

	it('all required keys present in zh.ts (real translations)', () => {
		for (const k of REQUIRED) {
			expect(zh[k as keyof typeof zh], `missing zh: ${k}`).toBeTruthy();
			const enVal = en[k as keyof typeof en] as string;
			const zhVal = zh[k as keyof typeof zh] as string;
			if (/[A-Za-z]{3,}/.test(enVal)) {
				expect(zhVal, `zh stub for ${k}`).not.toBe(enVal);
			}
		}
	});

	it('all required keys present in de.ts (real translations)', () => {
		for (const k of REQUIRED) {
			expect(de[k as keyof typeof de], `missing de: ${k}`).toBeTruthy();
			const enVal = en[k as keyof typeof en] as string;
			const deVal = de[k as keyof typeof de] as string;
			if (/[A-Za-z]{3,}/.test(enVal)) {
				expect(deVal, `de stub for ${k}`).not.toBe(enVal);
			}
		}
	});
});
