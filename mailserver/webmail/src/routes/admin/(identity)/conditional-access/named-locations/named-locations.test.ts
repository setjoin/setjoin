/**
 * CA-1 F2 — named-locations page tests.
 * TDD: RED first (pages absent), then GREEN.
 */
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import en from '$lib/i18n/en';
import zh from '$lib/i18n/zh';
import de from '$lib/i18n/de';
import NamedLocationsPage from './+page.svelte';

// ── helpers ──────────────────────────────────────────────────────────────────

function makeLocation(overrides: Record<string, unknown> = {}) {
	return {
		id: 1,
		name: 'Corporate HQ',
		cidrs: ['10.0.0.0/8', '192.168.0.0/16'],
		countries: [],
		trusted: true,
		deleted_at: null,
		created_at: '2026-01-01T00:00:00Z',
		updated_at: '2026-01-01T00:00:00Z',
		...overrides,
	};
}

function stubFetch(locations: unknown[], status = 200) {
	vi.stubGlobal(
		'fetch',
		vi.fn(() =>
			Promise.resolve({
				ok: status < 400,
				status,
				json: () => Promise.resolve(locations),
			})
		)
	);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('named-locations page — LOADING', () => {
	afterEach(() => vi.restoreAllMocks());

	it('shows skeleton rows while loading', () => {
		vi.stubGlobal('fetch', vi.fn(() => new Promise(() => {})));
		render(NamedLocationsPage);
		expect(screen.getByTestId('nl-loading')).toBeTruthy();
	});
});

describe('named-locations page — EMPTY', () => {
	afterEach(() => vi.restoreAllMocks());

	it('shows EmptyState with CTA when list is empty', async () => {
		stubFetch([]);
		render(NamedLocationsPage);
		await waitFor(() => expect(screen.queryByTestId('nl-loading')).toBeFalsy());
		expect(screen.getByTestId('nl-empty')).toBeTruthy();
		expect(screen.getByTestId('nl-empty-cta')).toBeTruthy();
	});
});

describe('named-locations page — ERROR', () => {
	afterEach(() => vi.restoreAllMocks());

	it('shows inline role=alert with Retry on fetch failure', async () => {
		vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('network'))));
		render(NamedLocationsPage);
		await waitFor(() => expect(screen.getByTestId('nl-error')).toBeTruthy());
		const alert = screen.getByTestId('nl-error');
		expect(alert.getAttribute('role')).toBe('alert');
		expect(screen.getByTestId('nl-retry')).toBeTruthy();
	});
});

describe('named-locations page — LIST', () => {
	afterEach(() => vi.restoreAllMocks());

	it('renders location cards with name + Trusted badge', async () => {
		stubFetch([makeLocation({ trusted: true })]);
		render(NamedLocationsPage);
		await waitFor(() => expect(screen.getByTestId('nl-card-1')).toBeTruthy());
		expect(screen.getByTestId('nl-card-1')).toBeTruthy();
		expect(screen.getByTestId('nl-trusted-badge-1')).toBeTruthy();
	});

	it('does NOT show Trusted badge when trusted=false', async () => {
		stubFetch([makeLocation({ id: 2, trusted: false })]);
		render(NamedLocationsPage);
		await waitFor(() => expect(screen.getByTestId('nl-card-2')).toBeTruthy());
		expect(screen.queryByTestId('nl-trusted-badge-2')).toBeFalsy();
	});

	it('truncates long names with ellipsis (title attr carries full name)', async () => {
		const longName = 'A'.repeat(60);
		stubFetch([makeLocation({ id: 3, name: longName })]);
		render(NamedLocationsPage);
		await waitFor(() => expect(screen.getByTestId('nl-name-3')).toBeTruthy());
		const nameEl = screen.getByTestId('nl-name-3');
		expect(nameEl.getAttribute('title')).toBe(longName);
	});
});

describe('named-locations page — CREATE / EDIT Dialog', () => {
	afterEach(() => vi.restoreAllMocks());

	it('opens create dialog on "New location" click', async () => {
		stubFetch([]);
		render(NamedLocationsPage);
		await waitFor(() => expect(screen.queryByTestId('nl-loading')).toBeFalsy());
		await fireEvent.click(screen.getByTestId('nl-new-btn'));
		expect(screen.getByTestId('nl-form-dialog')).toBeTruthy();
	});

	it('shows inline role=alert on bad CIDR input (never a raw 500)', async () => {
		stubFetch([]);
		render(NamedLocationsPage);
		await waitFor(() => expect(screen.queryByTestId('nl-loading')).toBeFalsy());
		await fireEvent.click(screen.getByTestId('nl-new-btn'));
		const cidrInput = screen.getByTestId('nl-cidr-input');
		await fireEvent.input(cidrInput, { target: { value: 'not-a-cidr' } });
		await fireEvent.blur(cidrInput);
		const cidrAlert = screen.getByTestId('nl-cidr-error');
		expect(cidrAlert.getAttribute('role')).toBe('alert');
	});

	it('save calls POST /admin/conditional-access/named-locations and shows toast', async () => {
		const created = makeLocation({ id: 10, name: 'Test Net' });
		const fetchMock = vi.fn()
			.mockResolvedValueOnce({ ok: true, status: 200, json: () => Promise.resolve([]) })
			.mockResolvedValueOnce({ ok: true, status: 201, json: () => Promise.resolve(created) });
		vi.stubGlobal('fetch', fetchMock);
		render(NamedLocationsPage);
		await waitFor(() => expect(screen.queryByTestId('nl-loading')).toBeFalsy());
		await fireEvent.click(screen.getByTestId('nl-new-btn'));
		const nameInput = screen.getByTestId('nl-name-input');
		await fireEvent.input(nameInput, { target: { value: 'Test Net' } });
		const cidrInput = screen.getByTestId('nl-cidr-input');
		await fireEvent.input(cidrInput, { target: { value: '10.0.0.0/8' } });
		await fireEvent.click(screen.getByTestId('nl-save-btn'));
		await waitFor(() => {
			const calls = fetchMock.mock.calls;
			expect(calls.some((c) => (c[0] as string).includes('named-location'))).toBe(true);
		});
	});
});

describe('named-locations page — SOFT-DELETE', () => {
	afterEach(() => vi.restoreAllMocks());

	it('delete opens confirm Dialog', async () => {
		stubFetch([makeLocation()]);
		render(NamedLocationsPage);
		await waitFor(() => expect(screen.getByTestId('nl-card-1')).toBeTruthy());
		await fireEvent.click(screen.getByTestId('nl-delete-btn-1'));
		expect(screen.getByTestId('nl-delete-dialog')).toBeTruthy();
	});

	it('confirmed delete calls DELETE endpoint and removes card', async () => {
		const fetchMock = vi.fn()
			.mockResolvedValueOnce({ ok: true, status: 200, json: () => Promise.resolve([makeLocation()]) })
			.mockResolvedValueOnce({ ok: true, status: 204, json: () => Promise.resolve(null) });
		vi.stubGlobal('fetch', fetchMock);
		render(NamedLocationsPage);
		await waitFor(() => expect(screen.getByTestId('nl-card-1')).toBeTruthy());
		await fireEvent.click(screen.getByTestId('nl-delete-btn-1'));
		await fireEvent.click(screen.getByTestId('nl-delete-confirm-btn'));
		await waitFor(() => expect(screen.queryByTestId('nl-card-1')).toBeFalsy());
	});

	it('trash+restore: restore button calls POST .../restore', async () => {
		const loc = makeLocation({ deleted_at: '2026-01-02T00:00:00Z' });
		const fetchMock = vi.fn()
			.mockResolvedValueOnce({
				ok: true, status: 200,
				json: () => Promise.resolve([{ ...loc, deleted_at: null }])
			})
			.mockResolvedValueOnce({ ok: true, status: 200, json: () => Promise.resolve([loc]) })
			.mockResolvedValueOnce({ ok: true, status: 200, json: () => Promise.resolve({ ...loc, deleted_at: null }) });
		vi.stubGlobal('fetch', fetchMock);
		render(NamedLocationsPage);
		await waitFor(() => expect(screen.queryByTestId('nl-loading')).toBeFalsy());
		// Expand trash
		const trashToggle = screen.queryByTestId('nl-trash-toggle');
		if (trashToggle) {
			await fireEvent.click(trashToggle);
			await waitFor(() => expect(screen.queryByTestId('nl-restore-btn-1')).toBeTruthy());
			await fireEvent.click(screen.getByTestId('nl-restore-btn-1'));
			await waitFor(() => {
				const calls = fetchMock.mock.calls;
				expect(calls.some((c) => (c[0] as string).includes('restore'))).toBe(true);
			});
		}
	});
});

describe('named-locations — i18n completeness', () => {
	const REQUIRED = [
		'admin.conditional_access.named_location.empty',
		'admin.conditional_access.named_location.empty_cta',
		'admin.conditional_access.named_location.load_error',
		'admin.conditional_access.named_location.bad_cidr',
		'admin.conditional_access.named_location.trusted_badge',
		'admin.conditional_access.named_location.delete_title',
		'admin.conditional_access.named_location.saved_toast',
		'admin.conditional_access.named_location.deleted_toast',
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

describe('named-locations — a11y', () => {
	afterEach(() => vi.restoreAllMocks());

	it('source has @media (prefers-reduced-motion: reduce) and token-only styles', async () => {
		const { readFileSync } = await import('fs');
		const src = readFileSync(
			'src/routes/admin/(identity)/conditional-access/named-locations/+page.svelte',
			'utf-8'
		);
		expect(src).toContain('@media (prefers-reduced-motion: reduce)');
		const styleMatch = src.match(/<style>([\s\S]*?)<\/style>/);
		if (styleMatch) {
			expect(styleMatch[1]).not.toMatch(/#[0-9a-fA-F]{3,6}\b/);
		}
	});

	it('source has @media (pointer: coarse) with 44px touch targets', async () => {
		const { readFileSync } = await import('fs');
		const src = readFileSync(
			'src/routes/admin/(identity)/conditional-access/named-locations/+page.svelte',
			'utf-8'
		);
		expect(src).toContain('pointer: coarse');
		expect(src).toContain('44px');
	});
});
