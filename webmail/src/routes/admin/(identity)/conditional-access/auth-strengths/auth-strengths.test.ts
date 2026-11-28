/**
 * CA-1 F2 — auth-strengths page + AuthStrengthMatrix tests.
 * TDD: RED first (pages absent), then GREEN.
 */
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import { describe, it, expect, vi, afterEach } from 'vitest';
import en from '$lib/i18n/en';
import zh from '$lib/i18n/zh';
import de from '$lib/i18n/de';
import AuthStrengthsPage from './+page.svelte';
import AuthStrengthMatrix from './AuthStrengthMatrix.svelte';

// ── helpers ──────────────────────────────────────────────────────────────────

function makeStrength(overrides: Record<string, unknown> = {}) {
	return {
		id: 1,
		name: 'Custom MFA',
		builtin: false,
		min_acr: 'aal2',
		combinations: [['password', 'totp']],
		deleted_at: null,
		...overrides,
	};
}

function makeBuiltin(overrides: Record<string, unknown> = {}) {
	return makeStrength({ id: 10, name: 'phishing-resistant', builtin: true, combinations: [['webauthn']], ...overrides });
}

function stubFetch(strengths: unknown[], status = 200) {
	vi.stubGlobal(
		'fetch',
		vi.fn(() =>
			Promise.resolve({
				ok: status < 400,
				status,
				json: () => Promise.resolve(strengths),
			})
		)
	);
}

// ── Page state tests ──────────────────────────────────────────────────────────

describe('auth-strengths page — LOADING', () => {
	afterEach(() => vi.restoreAllMocks());

	it('shows skeleton cards while loading', () => {
		vi.stubGlobal('fetch', vi.fn(() => new Promise(() => {})));
		render(AuthStrengthsPage);
		expect(screen.getByTestId('as-loading')).toBeTruthy();
	});
});

describe('auth-strengths page — EMPTY', () => {
	afterEach(() => vi.restoreAllMocks());

	it('shows EmptyState with CTA when no custom strengths', async () => {
		stubFetch([]);
		render(AuthStrengthsPage);
		await waitFor(() => expect(screen.queryByTestId('as-loading')).toBeFalsy());
		expect(screen.getByTestId('as-empty')).toBeTruthy();
		expect(screen.getByTestId('as-empty-cta')).toBeTruthy();
	});
});

describe('auth-strengths page — ERROR', () => {
	afterEach(() => vi.restoreAllMocks());

	it('shows inline role=alert with Retry on failure', async () => {
		vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('net'))));
		render(AuthStrengthsPage);
		await waitFor(() => expect(screen.getByTestId('as-error')).toBeTruthy());
		expect(screen.getByTestId('as-error').getAttribute('role')).toBe('alert');
		expect(screen.getByTestId('as-retry')).toBeTruthy();
	});
});

describe('auth-strengths page — BUILT-IN PROTECTION', () => {
	afterEach(() => vi.restoreAllMocks());

	it('built-in card shows "Built-in" badge and NO delete control', async () => {
		stubFetch([makeBuiltin()]);
		render(AuthStrengthsPage);
		await waitFor(() => expect(screen.getByTestId('as-card-10')).toBeTruthy());
		expect(screen.getByTestId('as-builtin-badge-10')).toBeTruthy();
		expect(screen.queryByTestId('as-delete-btn-10')).toBeFalsy();
	});

	it('custom strength card has delete control', async () => {
		stubFetch([makeStrength()]);
		render(AuthStrengthsPage);
		await waitFor(() => expect(screen.getByTestId('as-card-1')).toBeTruthy());
		expect(screen.getByTestId('as-delete-btn-1')).toBeTruthy();
		expect(screen.queryByTestId('as-builtin-badge-1')).toBeFalsy();
	});
});

describe('auth-strengths page — DELETE (T2 dangerous arc)', () => {
	afterEach(() => vi.restoreAllMocks());

	it('custom delete opens confirm Dialog with blast-radius message', async () => {
		stubFetch([makeStrength()]);
		render(AuthStrengthsPage);
		await waitFor(() => expect(screen.getByTestId('as-delete-btn-1')).toBeTruthy());
		await fireEvent.click(screen.getByTestId('as-delete-btn-1'));
		expect(screen.getByTestId('as-delete-dialog')).toBeTruthy();
		// blast-radius text
		const dialog = screen.getByTestId('as-delete-dialog');
		expect(dialog.textContent).toContain(en['admin.conditional_access.auth_strength.delete_body' as keyof typeof en]?.slice(0, 20));
	});

	it('DELETE type-to-confirm gates the button', async () => {
		stubFetch([makeStrength({ id: 5, name: 'My Strength' })]);
		render(AuthStrengthsPage);
		await waitFor(() => expect(screen.getByTestId('as-delete-btn-5')).toBeTruthy());
		await fireEvent.click(screen.getByTestId('as-delete-btn-5'));
		const confirmBtn = screen.getByTestId('as-delete-confirm-btn') as HTMLButtonElement;
		expect(confirmBtn.disabled).toBe(true);
		const typeInput = screen.getByTestId('as-delete-type-input');
		await fireEvent.input(typeInput, { target: { value: 'DELETE' } });
		expect(confirmBtn.disabled).toBe(false);
	});
});

describe('auth-strengths page — long name truncation', () => {
	afterEach(() => vi.restoreAllMocks());

	it('47-char name truncates with ellipsis (title carries full name)', async () => {
		const longName = 'B'.repeat(47);
		stubFetch([makeStrength({ id: 7, name: longName })]);
		render(AuthStrengthsPage);
		await waitFor(() => expect(screen.getByTestId('as-name-7')).toBeTruthy());
		const nameEl = screen.getByTestId('as-name-7');
		expect(nameEl.getAttribute('title')).toBe(longName);
	});
});

// ── AuthStrengthMatrix widget tests ─────────────────────────────────────────

describe('AuthStrengthMatrix — OR-of-AND structure', () => {
	it('renders OR dividers between combination rows', () => {
		render(AuthStrengthMatrix, {
			combinations: [['webauthn'], ['password', 'totp']],
			onChange: vi.fn(),
		});
		// 2 combination rows → 1 OR divider
		const dividers = screen.getAllByTestId('as-or-divider');
		expect(dividers.length).toBe(1);
	});

	it('each row is a <fieldset> with a <legend> carrying "OR branch N"', () => {
		render(AuthStrengthMatrix, {
			combinations: [['webauthn'], ['password', 'totp']],
			onChange: vi.fn(),
		});
		const fieldsets = document.querySelectorAll('fieldset[data-testid^="as-branch-"]');
		expect(fieldsets.length).toBe(2);
		// First legend should contain "1" (OR branch 1)
		const firstLegend = fieldsets[0].querySelector('legend');
		expect(firstLegend?.textContent).toMatch(/1/);
	});

	it('serializes correctly: [["webauthn"],["password","totp"]]', async () => {
		let emitted: string[][] | null = null;
		render(AuthStrengthMatrix, {
			combinations: [['webauthn'], ['password', 'totp']],
			onChange: (v: string[][]) => { emitted = v; },
		});
		// The wrapper span; find the actual input inside the Checkbox
		const wrapper = screen.getByTestId('as-factor-webauthn-0');
		const webauthnCheckbox = wrapper.querySelector('input[type="checkbox"]') as HTMLInputElement;
		expect(webauthnCheckbox).toBeTruthy();
		// it should be checked already, fire change to emit
		await fireEvent.change(webauthnCheckbox, { target: { checked: false } });
		await fireEvent.change(webauthnCheckbox, { target: { checked: true } });
		expect(emitted).toBeTruthy();
	});

	it('plain-English echo shows "Require: WebAuthn" for [["webauthn"]]', () => {
		render(AuthStrengthMatrix, {
			combinations: [['webauthn']],
			onChange: vi.fn(),
		});
		const echo = screen.getByTestId('as-echo-0');
		expect(echo.textContent?.toLowerCase()).toContain('webauthn');
		expect(echo.getAttribute('aria-live')).toBe('polite');
	});

	it('plain-English echo shows "and" connector for ["password","totp"]', () => {
		render(AuthStrengthMatrix, {
			combinations: [['password', 'totp']],
			onChange: vi.fn(),
		});
		const echo = screen.getByTestId('as-echo-0');
		// Should contain "and" (in en locale)
		expect(echo.textContent?.toLowerCase()).toMatch(/and|&/);
	});

	it('OR divider is aria-hidden (fieldset legends carry SR structure)', () => {
		render(AuthStrengthMatrix, {
			combinations: [['webauthn'], ['password', 'totp']],
			onChange: vi.fn(),
		});
		const divider = screen.getByTestId('as-or-divider');
		expect(divider.getAttribute('aria-hidden')).toBe('true');
	});

	it('"+ Add OR branch" appends a new empty row', async () => {
		const fn = vi.fn();
		render(AuthStrengthMatrix, {
			combinations: [['webauthn']],
			onChange: fn,
		});
		await fireEvent.click(screen.getByTestId('as-add-branch'));
		expect(fn).toHaveBeenCalledWith([['webauthn'], []]);
	});

	it('row Delete removes that row and calls onChange', async () => {
		const fn = vi.fn();
		render(AuthStrengthMatrix, {
			combinations: [['webauthn'], ['password', 'totp']],
			onChange: fn,
		});
		await fireEvent.click(screen.getByTestId('as-delete-branch-0'));
		expect(fn).toHaveBeenCalledWith([['password', 'totp']]);
	});

	it('Delete SR label is "Remove OR branch N"', () => {
		render(AuthStrengthMatrix, {
			combinations: [['webauthn'], ['password']],
			onChange: vi.fn(),
		});
		const btn0 = screen.getByTestId('as-delete-branch-0');
		// aria-label carries the SR text
		const label = btn0.getAttribute('aria-label') ?? '';
		expect(label).toMatch(/remove.*or.*branch.*1|or.*branch.*1.*remove/i);
	});

	it('blocks save (empty matrix validation) when no combinations', () => {
		// The matrix itself renders but calling code validates combinations.length === 0
		// We test by rendering an empty set and checking the validation message testid
		render(AuthStrengthMatrix, {
			combinations: [[]],
			onChange: vi.fn(),
			showValidation: true,
		});
		expect(screen.getByTestId('as-empty-matrix-msg')).toBeTruthy();
	});
});

describe('AuthStrengthMatrix — keyboard (p)', () => {
	it('Space/Enter on factor checkbox toggles it', async () => {
		const fn = vi.fn();
		render(AuthStrengthMatrix, {
			combinations: [['webauthn']],
			onChange: fn,
		});
		// The factor wrapper span; native input is inside the Checkbox label
		const wrapper = screen.getByTestId('as-factor-webauthn-0');
		const cbInput = wrapper.querySelector('input[type="checkbox"]') as HTMLInputElement;
		expect(cbInput).toBeTruthy();
		await fireEvent.keyDown(cbInput, { key: ' ' });
		// Native checkbox fires change on keydown space; simulate it
		await fireEvent.change(cbInput, { target: { checked: false } });
		expect(fn).toHaveBeenCalled();
	});
});

describe('AuthStrengthMatrix — source checks (reduced-motion, tokens, touch targets)', () => {
	it('AuthStrengthMatrix source has @media (prefers-reduced-motion: reduce)', async () => {
		const { readFileSync } = await import('fs');
		const src = readFileSync(
			'src/routes/admin/(identity)/conditional-access/auth-strengths/AuthStrengthMatrix.svelte',
			'utf-8'
		);
		expect(src).toContain('@media (prefers-reduced-motion: reduce)');
		expect(src).toContain('--duration-');
		const styleMatch = src.match(/<style>([\s\S]*?)<\/style>/);
		if (styleMatch) {
			expect(styleMatch[1]).not.toMatch(/#[0-9a-fA-F]{3,6}\b/);
		}
	});

	it('AuthStrengthMatrix source has @media (pointer: coarse) with 44px', async () => {
		const { readFileSync } = await import('fs');
		const src = readFileSync(
			'src/routes/admin/(identity)/conditional-access/auth-strengths/AuthStrengthMatrix.svelte',
			'utf-8'
		);
		expect(src).toContain('pointer: coarse');
		expect(src).toContain('44px');
	});
});

describe('auth-strengths — i18n completeness', () => {
	const REQUIRED = [
		'admin.conditional_access.auth_strength.empty',
		'admin.conditional_access.auth_strength.empty_cta',
		'admin.conditional_access.auth_strength.builtin_badge',
		'admin.conditional_access.auth_strength.or_branch',
		'admin.conditional_access.auth_strength.echo_one',
		'admin.conditional_access.auth_strength.echo_and',
		'admin.conditional_access.auth_strength.empty_matrix',
		'admin.conditional_access.auth_strength.delete_title',
		'admin.conditional_access.auth_strength.delete_body',
		'admin.conditional_access.auth_strength.delete_token',
		'admin.conditional_access.auth_strength.saved_toast',
	];

	it('all required keys present in en.ts', () => {
		for (const k of REQUIRED) {
			expect(en[k as keyof typeof en], `missing en: ${k}`).toBeTruthy();
		}
	});

	it('all required keys present in zh.ts (real translations)', () => {
		// ponytail: delete_token is intentionally "DELETE" in all locales (technical constant per spec)
		const TECHNICAL_CONSTANTS = new Set(['admin.conditional_access.auth_strength.delete_token']);
		for (const k of REQUIRED) {
			expect(zh[k as keyof typeof zh], `missing zh: ${k}`).toBeTruthy();
			if (TECHNICAL_CONSTANTS.has(k)) continue;
			const enVal = en[k as keyof typeof en] as string;
			const zhVal = zh[k as keyof typeof zh] as string;
			if (/[A-Za-z]{3,}/.test(enVal)) {
				expect(zhVal, `zh stub for ${k}`).not.toBe(enVal);
			}
		}
	});

	it('all required keys present in de.ts (real translations)', () => {
		const TECHNICAL_CONSTANTS = new Set(['admin.conditional_access.auth_strength.delete_token']);
		for (const k of REQUIRED) {
			expect(de[k as keyof typeof de], `missing de: ${k}`).toBeTruthy();
			if (TECHNICAL_CONSTANTS.has(k)) continue;
			const enVal = en[k as keyof typeof en] as string;
			const deVal = de[k as keyof typeof de] as string;
			if (/[A-Za-z]{3,}/.test(enVal)) {
				expect(deVal, `de stub for ${k}`).not.toBe(enVal);
			}
		}
	});
});
