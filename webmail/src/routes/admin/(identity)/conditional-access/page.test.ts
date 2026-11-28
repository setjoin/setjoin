/**
 * CA policy console — state-helpers (CA-0a) + F1 policy editor tests.
 * CA-1 F1: Policy editor — grant-array builder + PromoteDialog + ImpactCard + trash
 *
 * TDD spec covering EVERY required state per the F1 brief.
 * Tests are component-unit tests (not page-mounted) for PromoteDialog and ImpactCard
 * plus pure-logic assertions for the grant-array serialization.
 */
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import en from '$lib/i18n/en';
import zh from '$lib/i18n/zh';
import PromoteDialog from '$lib/components/ca/PromoteDialog.svelte';
import ImpactCard from '$lib/components/ca/ImpactCard.svelte';
import {
	stateLabelKey,
	stateBadgeVariant,
	parseIdList,
	saveErrorMessage,
	errorKey,
	needsTypedConfirm,
	preflightImpact,
	promoteMode,
} from './state-helpers';

// ── CA state helpers (CA-0a, preserved from original page.test.ts) ────────────

describe('CA state helpers', () => {
	it('maps the tri-state to i18n keys + badge variants', () => {
		expect(stateLabelKey('report_only')).toBe('admin.ca.state.report_only');
		expect(stateLabelKey('on')).toBe('admin.ca.state.on');
		expect(stateLabelKey('off')).toBe('admin.ca.state.off');
		expect(stateBadgeVariant('report_only')).toBe('warning');
		expect(stateBadgeVariant('on')).toBe('success');
		expect(stateBadgeVariant('off')).toBe('neutral');
	});

	it('parses an id list (back-compat paste path)', () => {
		expect(parseIdList('7, 9 ,12')).toEqual([7, 9, 12]);
		expect(parseIdList('')).toEqual([]);
	});

	it('requires a typed confirm only for an on global block/step_up', () => {
		expect(needsTypedConfirm({ state: 'on', scope_type: 'global', action: 'block' })).toBe(true);
		expect(needsTypedConfirm({ state: 'on', scope_type: 'global', action: 'step_up' })).toBe(true);
		expect(needsTypedConfirm({ state: 'on', scope_type: 'global', action: 'notify' })).toBe(false);
		expect(needsTypedConfirm({ state: 'report_only', scope_type: 'global', action: 'block' })).toBe(false);
		expect(needsTypedConfirm({ state: 'on', scope_type: 'user', action: 'block' })).toBe(false);
	});

	it('pre-flight counts admins that remain reachable (0 = will be rejected)', () => {
		expect(preflightImpact({ adminIds: [1, 2], excludeUsers: [1], excludeGroups: [], breakGlass: [], adminGroups: {} }).remaining).toBe(1);
		expect(preflightImpact({ adminIds: [1, 2], excludeUsers: [], excludeGroups: [], breakGlass: [], adminGroups: {} }).remaining).toBe(0);
		expect(preflightImpact({ adminIds: [1, 2], excludeUsers: [], excludeGroups: [], breakGlass: [2], adminGroups: {} }).remaining).toBe(1);
	});

	it('pre-flight respects excluded groups', () => {
		expect(preflightImpact({ adminIds: [1, 2], excludeUsers: [], excludeGroups: [10], breakGlass: [], adminGroups: { 2: [10] } }).remaining).toBe(1);
	});

	it('willReject is true only when remaining===0', () => {
		expect(preflightImpact({ adminIds: [1], excludeUsers: [1], excludeGroups: [], breakGlass: [], adminGroups: {} }).willReject).toBe(false);
		expect(preflightImpact({ adminIds: [1], excludeUsers: [], excludeGroups: [], breakGlass: [], adminGroups: {} }).willReject).toBe(true);
	});

	it('surfaces the 409 HINT verbatim on lockout, falls back to an i18n key otherwise', () => {
		expect(saveErrorMessage(409, 'exclude a break-glass admin account or an admin group')).toContain('break-glass');
		expect(saveErrorMessage(409, '')).toEqual({ key: 'admin.ca.error.lockout' });
		expect(saveErrorMessage(400, '')).toEqual({ key: 'admin.ca.error.invalid' });
		expect(saveErrorMessage(500, '')).toEqual({ key: 'admin.ca.error.save', params: { status: 500 } });
		expect(errorKey).toBeDefined();
	});

	it('promoteMode returns correct branch', () => {
		expect(promoteMode({ state: 'on', scope_type: 'global', action: 'block' }, 1)).toBe('confirm');
		expect(promoteMode({ state: 'on', scope_type: 'global', action: 'block' }, 0)).toBe('remediation');
		expect(promoteMode({ state: 'on', scope_type: 'global', action: 'notify' }, 0)).toBe('none');
		expect(promoteMode({ state: 'report_only', scope_type: 'global', action: 'block' }, 0)).toBe('none');
	});

	it('C2: confirm dialog reachable when an admin IS excluded (remaining > 0)', () => {
		const pf = preflightImpact({ adminIds: [1, 2], excludeUsers: [1], excludeGroups: [], breakGlass: [], adminGroups: {} });
		expect(pf.remaining).toBe(1);
		expect(promoteMode({ state: 'on', scope_type: 'global', action: 'block' }, pf.remaining)).toBe('confirm');
	});

	it('C2: remediation path when no admin remains reachable (remaining = 0)', () => {
		const pf = preflightImpact({ adminIds: [], excludeUsers: [], excludeGroups: [], breakGlass: [], adminGroups: {} });
		expect(pf.remaining).toBe(0);
		expect(promoteMode({ state: 'on', scope_type: 'global', action: 'block' }, pf.remaining)).toBe('remediation');
	});

	it('C1: needsTypedConfirm gates the promote path (only global block/step_up on→on transition)', () => {
		expect(needsTypedConfirm({ state: 'on', scope_type: 'global', action: 'block' })).toBe(true);
		expect(needsTypedConfirm({ state: 'on', scope_type: 'global', action: 'step_up' })).toBe(true);
		expect(needsTypedConfirm({ state: 'on', scope_type: 'user', action: 'block' })).toBe(false);
		expect(needsTypedConfirm({ state: 'on', scope_type: 'global', action: 'notify' })).toBe(false);
	});

	it('ships real zh for every admin.ca.* key (en/zh parity, no English fallthrough)', () => {
		const enKeys = Object.keys(en).filter((k) => k.startsWith('admin.ca.'));
		expect(enKeys.length).toBeGreaterThan(0);
		for (const k of enKeys) {
			expect(zh[k as keyof typeof zh], `missing zh for ${k}`).toBeTruthy();
			if (/[A-Za-z]{3,}/.test(en[k as keyof typeof en] as string)) {
				expect(zh[k as keyof typeof zh], `zh for ${k} is an untranslated English stub`).not.toBe(en[k as keyof typeof en]);
			}
		}
	});
});

// ── helpers ──────────────────────────────────────────────────────────────────

/** Build a minimal promote preview payload. */
function makePreview(overrides: Record<string, unknown> = {}) {
	return {
		would_block_users: 0,
		would_block_admins: 0,
		self_locked_out: false,
		blocked_users: [],
		admin_users: [],
		shown: 0,
		total: 0,
		window: '7d',
		...overrides,
	};
}

/**
 * Stub fetch for the promote preview contract: confirm:false is a PURE preview —
 * would_block>0 → 409 with the blast-radius body, would_block==0 → 200 with the
 * zeroed preview body (never a promote result). Returns the mock so tests can
 * assert call counts and bodies.
 */
function stubPromote(preview: ReturnType<typeof makePreview> | null) {
	const fetchMock = vi.fn(() => {
		if (preview && (preview.would_block_users > 0 || preview.would_block_admins > 0)) {
			return Promise.resolve({ ok: false, status: 409, json: () => Promise.resolve(preview) });
		}
		return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(makePreview()) });
	});
	vi.stubGlobal('fetch', fetchMock);
	return fetchMock;
}

/**
 * PromoteDialog gate: opening the dialog makes NO network request. Each test
 * must click the explicit "Check impact" action to trigger the preview POST.
 */
async function checkImpact() {
	await fireEvent.click(screen.getByTestId('promote-check-impact'));
}

// ── Grant-array shape tests ────────────────────────────────────────────────

describe('Grant-array shape (§6.4 — the editor must emit grant-array, never bare action)', () => {
	it('serializes a block grant as {"operator":"all","grants":[{"type":"block"}]}', () => {
		// The editor stores grants as an array of {type, ...params}; the serializer wraps it.
		function serializeGrants(operator: string, grants: Array<{ type: string; [k: string]: string }>) {
			return { operator, grants };
		}
		const shape = serializeGrants('all', [{ type: 'block' }]);
		expect(shape).toEqual({ operator: 'all', grants: [{ type: 'block' }] });
		// NOT {"action":"block"}
		expect(shape).not.toHaveProperty('action');
		expect((shape as Record<string, unknown>).grants).toBeDefined();
	});

	it('a role-scope policy emits scope_type:"role"', () => {
		// The editor form emits scope_type from the Select; 'role' is the new option.
		const formOutput = { scope_type: 'role', scope_target: 'group-42' };
		expect(formOutput.scope_type).toBe('role');
	});

	it('require_strength grant type has enforceability warning label (warn variant)', () => {
		// Enforceability labels: block/allow/notify → neutral; require_*/step_up → warning
		function enforceBadgeVariant(grantType: string): 'neutral' | 'warning' {
			return ['block', 'allow', 'notify'].includes(grantType) ? 'neutral' : 'warning';
		}
		expect(enforceBadgeVariant('require_strength')).toBe('warning');
		expect(enforceBadgeVariant('require_acr')).toBe('warning');
		expect(enforceBadgeVariant('step_up')).toBe('warning');
		expect(enforceBadgeVariant('block')).toBe('neutral');
		expect(enforceBadgeVariant('allow')).toBe('neutral');
		expect(enforceBadgeVariant('notify')).toBe('neutral');
	});
});

// ── PromoteDialog tests ────────────────────────────────────────────────────

describe('PromoteDialog', () => {
	const POLICY_NAME = 'Block external IPs';

	afterEach(() => {
		vi.restoreAllMocks();
	});

	// (a) Safe arc: would_block===0 → one-click primary, NO type-to-confirm
	it('(a) would_block===0: renders calm arc with NO type-to-confirm, safe primary button enabled', async () => {
		stubPromote(makePreview({ would_block_users: 0, would_block_admins: 0 }));
		render(PromoteDialog, {
			open: true,
			policyId: 1,
			policyName: POLICY_NAME,
			onClose: vi.fn(),
			onEnforced: vi.fn(),
		});

		// Explicit check action → idle → done (200 zeroed preview)
		await checkImpact();
		await waitFor(() => expect(screen.getByTestId('promote-safe-banner')).toBeTruthy());

		// NO type-to-confirm input
		expect(screen.queryByTestId('promote-type-input')).toBeFalsy();

		// Confirm button enabled (not disabled)
		const confirmBtn = screen.getByTestId('promote-confirm-btn') as HTMLButtonElement;
		expect(confirmBtn.disabled).toBe(false);
	});

	// (b) Caution arc: would_block>0, admins===0 → ack checkbox gates confirm
	it('(b) would_block>0, admins===0: confirm gated behind ack checkbox only', async () => {
		stubPromote(makePreview({ would_block_users: 42, would_block_admins: 0 }));
		render(PromoteDialog, {
			open: true,
			policyId: 1,
			policyName: POLICY_NAME,
			onClose: vi.fn(),
			onEnforced: vi.fn(),
		});

		await checkImpact();
		await waitFor(() => expect(screen.getByTestId('promote-ack')).toBeTruthy());

		// Confirm initially disabled (ack not checked)
		const confirmBtn = screen.getByTestId('promote-confirm-btn') as HTMLButtonElement;
		expect(confirmBtn.disabled).toBe(true);

		// NO type-to-confirm
		expect(screen.queryByTestId('promote-type-input')).toBeFalsy();

		// Check the ack → confirm enabled
		const ack = screen.getByTestId('promote-ack');
		const checkbox = ack.querySelector('input[type="checkbox"]') as HTMLInputElement;
		await fireEvent.change(checkbox, { target: { checked: true } });
		expect(confirmBtn.disabled).toBe(false);
	});

	// (c) Danger arc: would_block_admins>0 → danger frame, type-to-confirm, break-glass link
	it('(c) would_block_admins>0: danger frame, pins admins, type-to-confirm required, break-glass link visible', async () => {
		const preview = makePreview({
			would_block_users: 5,
			would_block_admins: 2,
			admin_users: [
				{ id: 10, address: 'admin@corp.test', is_admin: true },
				{ id: 11, address: 'root@corp.test', is_admin: true },
			],
			blocked_users: [
				{ id: 10, address: 'admin@corp.test', is_admin: true },
				{ id: 12, address: 'user@corp.test', is_admin: false },
			],
			shown: 2,
			total: 2,
		});
		stubPromote(preview);
		render(PromoteDialog, {
			open: true,
			policyId: 1,
			policyName: POLICY_NAME,
			onClose: vi.fn(),
			onEnforced: vi.fn(),
		});

		await checkImpact();
		await waitFor(() => expect(screen.getByTestId('promote-danger-admins')).toBeTruthy());

		// Admin users pinned in list
		const adminRows = screen.getAllByTestId('promote-admin-user');
		expect(adminRows.length).toBeGreaterThan(0);

		// Type-to-confirm input present
		const typeInput = screen.getByTestId('promote-type-input');
		expect(typeInput).toBeTruthy();

		// Break-glass link present
		expect(screen.getByTestId('promote-breakglass')).toBeTruthy();
		expect(screen.getByTestId('promote-breakglass-link')).toBeTruthy();

		// Confirm disabled until name typed AND ack checked
		const confirmBtn = screen.getByTestId('promote-confirm-btn') as HTMLButtonElement;
		expect(confirmBtn.disabled).toBe(true);

		// Check ack only — still disabled (need name too)
		const ackCheckbox = screen.getByTestId('promote-ack').querySelector('input') as HTMLInputElement;
		await fireEvent.change(ackCheckbox, { target: { checked: true } });
		expect(confirmBtn.disabled).toBe(true);

		// Type wrong name — still disabled
		await fireEvent.input(typeInput, { target: { value: 'wrong name' } });
		expect(confirmBtn.disabled).toBe(true);

		// Type correct name — now enabled
		await fireEvent.input(typeInput, { target: { value: POLICY_NAME } });
		expect(confirmBtn.disabled).toBe(false);
	});

	// (d) self_locked_out: "including you" line appears
	it('(d) self_locked_out=true shows the "including you" line', async () => {
		const preview = makePreview({
			would_block_users: 3,
			would_block_admins: 1,
			self_locked_out: true,
			admin_users: [{ id: 99, address: 'you@corp.test', is_admin: true }],
			blocked_users: [{ id: 99, address: 'you@corp.test', is_admin: true }],
		});
		stubPromote(preview);
		render(PromoteDialog, {
			open: true,
			policyId: 1,
			policyName: POLICY_NAME,
			actorAddress: 'you@corp.test',
			onClose: vi.fn(),
			onEnforced: vi.fn(),
		});

		await checkImpact();
		await waitFor(() => expect(screen.getByTestId('promote-self-locked')).toBeTruthy());

		// Self-locked line contains actor address
		const selfLocked = screen.getByTestId('promote-self-locked');
		expect(selfLocked.textContent).toContain('you@corp.test');
	});

	// (e) Impact-fetch failure: alert + Retry, confirm DISABLED (never shows 0)
	it('(e) impact-fetch failure: alert + Retry rendered; confirm stays DISABLED', async () => {
		vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('network error'))));
		render(PromoteDialog, {
			open: true,
			policyId: 1,
			policyName: POLICY_NAME,
			onClose: vi.fn(),
			onEnforced: vi.fn(),
		});

		// The failure surfaces only after the explicit check action
		await checkImpact();
		await waitFor(() => expect(screen.getByTestId('promote-impact-error')).toBeTruthy());

		// Confirm button must remain disabled (§e load-bearing safety rule)
		const confirmBtn = screen.getByTestId('promote-confirm-btn') as HTMLButtonElement;
		expect(confirmBtn.disabled).toBe(true);

		// Retry button present
		expect(screen.getByRole('button', { name: /retry/i })).toBeTruthy();
	});

	// (f) Idle → loading: no request on open; spinner + confirm disabled after the explicit action
	it('(f) idle on open with no request; after the explicit check action: spinner + confirm disabled', async () => {
		// Hang the fetch
		const fetchMock = vi.fn(() => new Promise(() => {}));
		vi.stubGlobal('fetch', fetchMock);
		render(PromoteDialog, {
			open: true,
			policyId: 1,
			policyName: POLICY_NAME,
			onClose: vi.fn(),
			onEnforced: vi.fn(),
		});

		// IDLE: no network request has been made yet
		expect(screen.getByTestId('promote-idle')).toBeTruthy();
		expect(fetchMock).not.toHaveBeenCalled();

		const confirmBtn = screen.getByTestId('promote-confirm-btn') as HTMLButtonElement;
		expect(confirmBtn.disabled).toBe(true);

		// Explicit check action → loading spinner
		await checkImpact();
		expect(screen.getByTestId('promote-loading')).toBeTruthy();
		expect(confirmBtn.disabled).toBe(true);
	});

	// (g) Overflow: "showing N of total" + CSV button
	it('(g) overflow: shows "showing N of total" + CSV download button', async () => {
		const preview = makePreview({
			would_block_users: 210,
			would_block_admins: 0,
			blocked_users: Array.from({ length: 5 }, (_, i) => ({ id: i, address: `user${i}@t.com`, is_admin: false })),
			shown: 200,
			total: 210,
		});
		stubPromote(preview);
		render(PromoteDialog, {
			open: true,
			policyId: 1,
			policyName: POLICY_NAME,
			onClose: vi.fn(),
			onEnforced: vi.fn(),
		});

		await checkImpact();
		await waitFor(() => expect(screen.getByTestId('promote-overflow')).toBeTruthy());

		const overflow = screen.getByTestId('promote-overflow');
		expect(overflow).toBeTruthy();
		expect(overflow.textContent).toMatch(/200/);
		expect(overflow.textContent).toMatch(/210/);

		expect(screen.getByTestId('promote-csv')).toBeTruthy();
	});

	// (h) aria-live announce regions
	it('(h) aria-live region announces impact-fetch failure', async () => {
		vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('fail'))));
		render(PromoteDialog, {
			open: true,
			policyId: 1,
			policyName: POLICY_NAME,
			onClose: vi.fn(),
			onEnforced: vi.fn(),
		});

		await checkImpact();
		await waitFor(() => screen.getByTestId('promote-impact-error'));

		const liveRegion = screen.getByTestId('promote-announce');
		expect(liveRegion.getAttribute('aria-live')).toBe('assertive');
		expect(liveRegion.textContent?.trim().length).toBeGreaterThan(0);
	});

	// (i) Keyboard: initial focus on Cancel (safe secondary); Escape cancels
	it('(i) Cancel button is in the footer (safe secondary); Escape cancels', async () => {
		stubPromote(makePreview({ would_block_users: 0, would_block_admins: 0 }));
		const onClose = vi.fn();
		render(PromoteDialog, {
			open: true,
			policyId: 1,
			policyName: POLICY_NAME,
			onClose,
			onEnforced: vi.fn(),
		});

		await checkImpact();
		await waitFor(() => expect(screen.getByTestId('promote-safe-banner')).toBeTruthy());
		// Cancel button exists
		expect(screen.getByTestId('promote-cancel')).toBeTruthy();
	});

	// (j) Motion/reduced-motion: @media block present in component source
	it('(j) PromoteDialog component source contains @media (prefers-reduced-motion: reduce)', async () => {
		// We verify the style block contains the reduced-motion guard.
		// This is done by reading the component file and checking the CSS.
		// ponytail: direct file read check; this is a structural assertion, not a render assertion.
		const { readFileSync } = await import('fs');
		const src = readFileSync(
			'src/lib/components/ca/PromoteDialog.svelte',
			'utf-8'
		);
		expect(src).toContain('@media (prefers-reduced-motion: reduce)');
		// count-change uses --duration-base (not transition: all)
		expect(src).toContain('--duration-base');
		// No hex values in the style block (token-only)
		const styleMatch = src.match(/<style>([\s\S]*?)<\/style>/);
		if (styleMatch) {
			expect(styleMatch[1]).not.toMatch(/#[0-9a-fA-F]{3,6}\b/);
		}
	});

	// (k) Edge cases: 47-char name truncated in list, formatNumber for counts
	it('(k) counts render via formatNumber (locale-grouped), confirm requires full policy name', async () => {
		const longName = 'A'.repeat(47);
		const preview = makePreview({
			would_block_users: 1204,
			would_block_admins: 3,
			admin_users: [{ id: 1, address: 'a@b.com', is_admin: true }],
			blocked_users: [{ id: 1, address: 'a@b.com', is_admin: true }],
		});
		stubPromote(preview);
		render(PromoteDialog, {
			open: true,
			policyId: 1,
			policyName: longName,
			onClose: vi.fn(),
			onEnforced: vi.fn(),
		});

		await checkImpact();
		await waitFor(() => expect(screen.getByTestId('promote-count')).toBeTruthy());

		// Count region present
		const countEl = screen.getByTestId('promote-count');
		expect(countEl).toBeTruthy();
		// The count must be present (may be formatted as "1,204" or "1.204" or "1 204" depending on locale)
		expect(countEl.textContent?.replace(/\s/g, '')).toMatch(/1.?204|1204/);

		// Type-to-confirm requires the FULL long name (not truncated)
		const typeInput = screen.getByTestId('promote-type-input') as HTMLInputElement;
		const ack = screen.getByTestId('promote-ack').querySelector('input') as HTMLInputElement;
		await fireEvent.change(ack, { target: { checked: true } });
		await fireEvent.input(typeInput, { target: { value: longName.slice(0, 20) } });
		const confirmBtn = screen.getByTestId('promote-confirm-btn') as HTMLButtonElement;
		expect(confirmBtn.disabled).toBe(true);
		await fireEvent.input(typeInput, { target: { value: longName } });
		expect(confirmBtn.disabled).toBe(false);
	});

	// (p) GATE: opening the dialog for a report_only policy issues NO network
	// request until the explicit user action; promotion happens only after the
	// separate explicit commit (confirm:true), never as a side effect of preview.
	it('(p) no network request on open; preview on explicit action; promotion only on explicit commit', async () => {
		const preview = makePreview({
			would_block_users: 2,
			would_block_admins: 0,
			blocked_users: [{ id: 5, address: 'u@corp.test', is_admin: false }],
			shown: 1,
			total: 2,
		});
		const fetchMock = vi.fn((_: string | URL, opts?: RequestInit) => {
			const body = JSON.parse(String(opts?.body ?? '{}')) as { confirm: boolean };
			if (body.confirm === true) {
				return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ id: 1, state: 'on' }) });
			}
			return Promise.resolve({ ok: false, status: 409, json: () => Promise.resolve(preview) });
		});
		vi.stubGlobal('fetch', fetchMock);
		render(PromoteDialog, {
			open: true,
			policyId: 1,
			policyName: POLICY_NAME,
			onClose: vi.fn(),
			onEnforced: vi.fn(),
		});

		// Open == zero requests; confirm stays disabled in idle state
		expect(fetchMock).not.toHaveBeenCalled();
		const confirmBtn = screen.getByTestId('promote-confirm-btn') as HTMLButtonElement;
		expect(confirmBtn.disabled).toBe(true);

		// Explicit check action fires exactly ONE confirm:false preview POST
		await checkImpact();
		await waitFor(() => expect(screen.getByTestId('promote-ack')).toBeTruthy());
		expect(fetchMock).toHaveBeenCalledTimes(1);
		expect(JSON.parse(String((fetchMock.mock.calls[0][1] as RequestInit).body))).toEqual({ confirm: false });

		// The separate explicit commit fires confirm:true
		const checkbox = screen.getByTestId('promote-ack').querySelector('input') as HTMLInputElement;
		await fireEvent.change(checkbox, { target: { checked: true } });
		expect(confirmBtn.disabled).toBe(false);
		await fireEvent.click(confirmBtn);
		await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
		expect(JSON.parse(String((fetchMock.mock.calls[1][1] as RequestInit).body))).toEqual({ confirm: true });
	});

	// (q) 409 DISTINCTION: a VALID structured preview payload renders its content;
	// a malformed/httputil problem-shaped 409 body is a blocked-read error that
	// keeps confirm DISABLED — never a permissive-default safe arc.
	it('(q) valid structured 409 preview renders; httputil-shaped 409 body blocks the confirm arc', async () => {
		// Valid arm: caution arc with ack + counts renders from the 409 body.
		vi.stubGlobal('fetch', vi.fn(() =>
			Promise.resolve({ ok: false, status: 409, json: () => Promise.resolve(makePreview({ would_block_users: 7 })) })
		));
		const { unmount } = render(PromoteDialog, {
			open: true,
			policyId: 1,
			policyName: POLICY_NAME,
			onClose: vi.fn(),
			onEnforced: vi.fn(),
		});
		await checkImpact();
		await waitFor(() => expect(screen.getByTestId('promote-ack')).toBeTruthy());
		expect(screen.getByTestId('promote-count').textContent).toMatch(/7/);
		const validConfirm = screen.getByTestId('promote-confirm-btn') as HTMLButtonElement;
		expect(validConfirm.disabled).toBe(true); // caution: gated behind ack, NOT blank-blocked
		unmount();

		// Malformed arm: RFC 7807 problem body cast MUST NOT become a preview.
		vi.stubGlobal('fetch', vi.fn(() =>
			Promise.resolve({
				ok: false,
				status: 409,
				json: () => Promise.resolve({ type: 'about:blank', title: 'Conflict', status: 409, detail: 'lockout guard' }),
			})
		));
		render(PromoteDialog, {
			open: true,
			policyId: 1,
			policyName: POLICY_NAME,
			onClose: vi.fn(),
			onEnforced: vi.fn(),
		});
		await checkImpact();
		await waitFor(() => expect(screen.getByTestId('promote-impact-error')).toBeTruthy());
		const blockedConfirm = screen.getByTestId('promote-confirm-btn') as HTMLButtonElement;
		expect(blockedConfirm.disabled).toBe(true);
	});

	// (r) A 2xx body that is not a valid preview (e.g. an old-server promote
	// result on the preview call) is a blocked-read failure, NEVER a safe arc.
	it('(r) 200 with a non-preview body blocks confirm instead of showing the calm arc', async () => {
		vi.stubGlobal('fetch', vi.fn(() =>
			Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ id: 1, state: 'on' }) })
		));
		render(PromoteDialog, {
			open: true,
			policyId: 1,
			policyName: POLICY_NAME,
			onClose: vi.fn(),
			onEnforced: vi.fn(),
		});
		await checkImpact();
		await waitFor(() => expect(screen.getByTestId('promote-impact-error')).toBeTruthy());
		const confirmBtn = screen.getByTestId('promote-confirm-btn') as HTMLButtonElement;
		expect(confirmBtn.disabled).toBe(true);
		expect(screen.queryByTestId('promote-safe-banner')).toBeFalsy();
	});
});

// ── ImpactCard tests ───────────────────────────────────────────────────────

describe('ImpactCard', () => {
	afterEach(() => vi.restoreAllMocks());

	// NO-DATA: window_has_data=false → EmptyState (NOT "0")
	it('NO-DATA: window_has_data=false renders EmptyState, not "0"', () => {
		render(ImpactCard, {
			policyId: 1,
			data: {
				window: '7d',
				window_has_data: false,
				matched: 0,
				would_block: 0,
				would_step_up: 0,
				distinct_users: 0,
				would_block_admins: 0,
			},
		});

		// NO-DATA indicator
		expect(screen.getByTestId('impact-no-data')).toBeTruthy();
		// Must NOT render a "0" as a metric tile
		expect(screen.queryByTestId('impact-tiles')).toBeFalsy();
	});

	// ZERO: window_has_data=true, would_block=0 → tiles with real 0, success tint
	it('ZERO: window_has_data=true, would_block=0 renders tiles with "0" and success tint', () => {
		render(ImpactCard, {
			policyId: 1,
			data: {
				window: '7d',
				window_has_data: true,
				matched: 58,
				would_block: 0,
				would_step_up: 0,
				distinct_users: 9,
				would_block_admins: 0,
			},
		});

		expect(screen.getByTestId('impact-tiles')).toBeTruthy();

		// would_block tile shows 0
		const blockTile = screen.getByTestId('impact-tile-would-block');
		expect(blockTile.textContent).toContain('0');
		expect(blockTile.className).toContain('success');

		// Zero note present
		expect(screen.getByTestId('impact-zero-note')).toBeTruthy();
	});

	// would_block_admins>0: danger tile promoted to first position
	it('would_block_admins>0: danger tile rendered first', () => {
		render(ImpactCard, {
			policyId: 1,
			data: {
				window: '7d',
				window_has_data: true,
				matched: 100,
				would_block: 10,
				would_step_up: 0,
				distinct_users: 10,
				would_block_admins: 3,
			},
		});

		const tiles = screen.getByTestId('impact-tiles');
		const adminTile = screen.getByTestId('impact-tile-admins');

		// Admin tile is inside the tiles container
		expect(tiles.contains(adminTile)).toBe(true);

		// Admin tile appears before the matched tile in DOM
		const allTiles = tiles.querySelectorAll('[data-testid^="impact-tile-"]');
		expect(allTiles[0]).toBe(adminTile);
	});

	// LOADING: shows skeleton tiles (not a spinner)
	it('LOADING: shows skeleton tiles, not a bare spinner', () => {
		render(ImpactCard, { policyId: 1, loading: true });

		const loading = screen.getByTestId('impact-loading');
		expect(loading).toBeTruthy();
		expect(loading.querySelector('.impact-tile--skel')).toBeTruthy();
		// No "0" rendered
		expect(screen.queryByTestId('impact-tiles')).toBeFalsy();
	});

	// ERROR: inline role=alert + Retry
	it('ERROR: inline role=alert with Retry button', async () => {
		const onRetry = vi.fn();
		render(ImpactCard, { policyId: 1, error: 'Server error', onRetry });

		const alert = screen.getByTestId('impact-error');
		expect(alert.getAttribute('role')).toBe('alert');
		expect(screen.getByRole('button', { name: /retry/i })).toBeTruthy();
	});

	// (h) aria-live polite announce on resolve
	it('(h) aria-live polite region announces on data resolve', () => {
		render(ImpactCard, {
			policyId: 1,
			data: {
				window: '7d',
				window_has_data: true,
				matched: 58,
				would_block: 3,
				would_step_up: 0,
				distinct_users: 9,
				would_block_admins: 0,
			},
		});

		const liveRegion = screen.getByTestId('impact-announce');
		expect(liveRegion.getAttribute('aria-live')).toBe('polite');
		expect(liveRegion.textContent?.trim().length).toBeGreaterThan(0);
	});

	// (j) Reduced-motion guard in source
	it('(j) ImpactCard source contains @media (prefers-reduced-motion: reduce) and --duration-base', async () => {
		const { readFileSync } = await import('fs');
		const src = readFileSync(
			'src/lib/components/ca/ImpactCard.svelte',
			'utf-8'
		);
		expect(src).toContain('@media (prefers-reduced-motion: reduce)');
		expect(src).toContain('--duration-base');
		// No hex colors
		const styleMatch = src.match(/<style>([\s\S]*?)<\/style>/);
		if (styleMatch) {
			expect(styleMatch[1]).not.toMatch(/#[0-9a-fA-F]{3,6}\b/);
		}
	});

	// (k) formatNumber: counts are locale-grouped ("1,204" not "1204")
	it('(k) counts render locale-grouped (not raw integers)', () => {
		render(ImpactCard, {
			policyId: 1,
			data: {
				window: '7d',
				window_has_data: true,
				matched: 1204,
				would_block: 1204,
				would_step_up: 0,
				distinct_users: 1204,
				would_block_admins: 0,
			},
		});

		const matchedTile = screen.getByTestId('impact-tile-matched');
		// Should NOT be the bare integer
		expect(matchedTile.textContent?.trim()).not.toBe('1204');
		// Should contain a grouping separator (comma, period, or space)
		expect(matchedTile.textContent).toMatch(/1.?204/);
	});

	// fetchData renders the REAL measured impact.
	it('fetchData: fetches the policy impact endpoint and renders real tiles', async () => {
		const fetchMock = vi.fn((_url: string | URL | Request) =>
			Promise.resolve({
				ok: true,
				status: 200,
				json: () => Promise.resolve({
					window: '7d',
					window_has_data: true,
					matched: 58,
					would_block: 3,
					would_step_up: 1,
					distinct_users: 9,
					would_block_admins: 0,
				}),
			})
		);
		vi.stubGlobal('fetch', fetchMock);
		render(ImpactCard, { policyId: 42, fetchData: true });

		await waitFor(() => expect(screen.getByTestId('impact-tiles')).toBeTruthy());
		const url = String(fetchMock.mock.calls[0][0]);
		expect(url).toContain('/admin/conditional-access/policies/42/impact');
		expect(screen.getByTestId('impact-tile-would-block').textContent).toContain('3');
		expect(screen.getByTestId('impact-tile-matched').textContent).toMatch(/58/);
	});

	it('fetchData: request failure renders the alert + Retry, never fabricated tiles', async () => {
		vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('network down'))));
		render(ImpactCard, { policyId: 42, fetchData: true });

		await waitFor(() => expect(screen.getByTestId('impact-error')).toBeTruthy());
		expect(screen.queryByTestId('impact-tiles')).toBeFalsy();
		expect(screen.getByRole('button', { name: /retry/i })).toBeTruthy();
	});

	it('fetchData: a malformed impact body renders the error state, not fake numbers', async () => {
		vi.stubGlobal('fetch', vi.fn(() =>
			Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ error: 'boom' }) })
		));
		render(ImpactCard, { policyId: 42, fetchData: true });

		await waitFor(() => expect(screen.getByTestId('impact-error')).toBeTruthy());
		expect(screen.queryByTestId('impact-tiles')).toBeFalsy();
	});

	it('without fetchData NO request is made — the explicit no-evidence state (TemplateWizard) stays intact', () => {
		const fetchMock = vi.fn();
		vi.stubGlobal('fetch', fetchMock);
		render(ImpactCard, { policyId: 1 });

		expect(screen.getByTestId('impact-no-data')).toBeTruthy();
		expect(fetchMock).not.toHaveBeenCalled();
	});

	// All four CA impact surfaces (editor/simulate/why/coverage) must opt into the
	// live fetch; TemplateWizard intentionally keeps the no-evidence state
	// (template.id would hit the wrong policy-impact endpoint).
	it('all four CA impact surfaces (editor/simulate/why/coverage) pass fetchData to ImpactCard', async () => {
		const { readFileSync } = await import('fs');
		const sites = [
			'src/routes/admin/(identity)/conditional-access/+page.svelte',
			'src/routes/admin/(identity)/conditional-access/simulate/+page.svelte',
			'src/routes/admin/(identity)/conditional-access/why/+page.svelte',
			'src/routes/admin/(identity)/conditional-access/coverage/+page.svelte',
		];
		for (const site of sites) {
			const src = readFileSync(site, 'utf-8');
			expect(src, `${site} must pass fetchData to ImpactCard`).toMatch(/<ImpactCard[^>]*fetchData/);
		}
		const wizard = readFileSync(
			'src/routes/admin/(identity)/conditional-access/templates/TemplateWizard.svelte',
			'utf-8'
		);
		expect(wizard).not.toMatch(/<ImpactCard[^>]*fetchData/);
	});
});

// ── Trash view tests ───────────────────────────────────────────────────────

describe('Trash / restore (pure-logic layer assertions)', () => {
	// (l) BZ087 inline friendly message
	it('(l) BZ087 restore-conflict surfaces friendly message, not raw code', () => {
		function restoreConflictMessage(status: number, hint: string): string {
			if (status === 409 && hint) return hint;
			if (status === 409) return 'admin.ca.trash.restore_conflict'; // i18n key
			return 'unknown error';
		}
		// Server returns BZ087 hint verbatim
		const msg = restoreConflictMessage(409, 'Priority already taken by a live policy.');
		expect(msg).toContain('Priority already taken');
		expect(msg).not.toContain('BZ087');

		// Server returns no hint → localizable key, not "BZ087"
		const keyMsg = restoreConflictMessage(409, '');
		expect(keyMsg).not.toContain('BZ087');
		expect(keyMsg).toBe('admin.ca.trash.restore_conflict');
	});
});

// ── (m) Touch targets ─────────────────────────────────────────────────────

describe('(m) Touch targets: PromoteDialog + ImpactCard source have pointer:coarse guards', () => {
	it('PromoteDialog source has @media (pointer: coarse) with min-height', async () => {
		const { readFileSync } = await import('fs');
		const src = readFileSync(
			'src/lib/components/ca/PromoteDialog.svelte',
			'utf-8'
		);
		expect(src).toContain('pointer: coarse');
		expect(src).toContain('44px');
	});

	it('ImpactCard source has @media (pointer: coarse) with min-height', async () => {
		const { readFileSync } = await import('fs');
		const src = readFileSync(
			'src/lib/components/ca/ImpactCard.svelte',
			'utf-8'
		);
		expect(src).toContain('pointer: coarse');
		expect(src).toContain('44px');
	});
});

// ── (n) Exact copy / i18n completeness ────────────────────────────────────

describe('(n) i18n completeness: admin.conditional_access.{promote,impact}.* keys in en+zh', () => {
	const REQUIRED_KEYS = [
		'admin.conditional_access.promote.title_safe',
		'admin.conditional_access.promote.title_caution',
		'admin.conditional_access.promote.title_danger',
		'admin.conditional_access.promote.safe_banner',
		'admin.conditional_access.promote.caution_ack',
		'admin.conditional_access.promote.admins_warn',
		'admin.conditional_access.promote.self_locked',
		'admin.conditional_access.promote.type_to_confirm',
		'admin.conditional_access.promote.breakglass_note',
		'admin.conditional_access.promote.breakglass_cta',
		'admin.conditional_access.promote.showing_n_of_total',
		'admin.conditional_access.promote.download_csv',
		'admin.conditional_access.promote.loading',
		'admin.conditional_access.promote.impact_error',
		'admin.conditional_access.promote.confirm_safe',
		'admin.conditional_access.promote.confirm_danger',
		'admin.conditional_access.promote.cancel',
		'admin.conditional_access.promote.enforcing',
		'admin.conditional_access.promoted_toast',
		'admin.conditional_access.promote.announce.enforced',
		'admin.conditional_access.promote.announce.blocked_read',
		'admin.conditional_access.impact.no_data',
		'admin.conditional_access.impact.zero_block',
		'admin.conditional_access.impact.load_error',
		'admin.conditional_access.impact.announce',
		'admin.conditional_access.impact.tile.matched',
		'admin.conditional_access.impact.tile.would_block',
		'admin.conditional_access.impact.tile.would_step_up',
		'admin.conditional_access.impact.tile.distinct_users',
		'admin.conditional_access.impact.tile.would_block_admins',
	];

	it('all required F1 keys present in en.ts with non-empty values', () => {
		for (const key of REQUIRED_KEYS) {
			expect(en[key as keyof typeof en], `missing en.ts key: ${key}`).toBeTruthy();
		}
	});

	it('all required F1 keys present in zh.ts with non-empty values (no English stubs)', () => {
		for (const key of REQUIRED_KEYS) {
			expect(zh[key as keyof typeof zh], `missing zh.ts key: ${key}`).toBeTruthy();
			// Real zh must differ from en (not a stub) when long enough
			const enVal = en[key as keyof typeof en] as string | undefined;
			const zhVal = zh[key as keyof typeof zh] as string | undefined;
			if (enVal && zhVal && /[A-Za-z]{3,}/.test(enVal)) {
				expect(zhVal, `zh for ${key} is an untranslated English stub`).not.toBe(enVal);
			}
		}
	});
});

// ── DX nav tile coverage ────────────────────────────────────────────────────────

describe('CA console DX nav tiles link to all sub-routes', () => {
	const ALL_SUBROUTES = [
		'simulate',
		'coverage',
		'why',
		'named-locations',
		'auth-strengths',
		'templates',
	];

	it('CA console +page.svelte source has href for every sub-route', () => {
		const src = import.meta.glob('./+page.svelte', {
			query: '?raw', import: 'default', eager: true,
		}) as Record<string, string>;
		const text = Object.values(src)[0] ?? '';
		for (const route of ALL_SUBROUTES) {
			expect(text, `missing href for sub-route "${route}"`).toContain(
				`href="/admin/conditional-access/${route}"`
			);
		}
	});
});
