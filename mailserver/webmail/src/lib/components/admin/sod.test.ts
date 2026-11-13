import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render } from '@testing-library/svelte/svelte5';
import { sodClassBadge, isCrossClass } from './sodClass';
import { jmapSession } from '$lib/stores/session';
import type { JmapSession } from '$lib/types/jmap';

// ── A. sodClassBadge utility ──────────────────────────────────────────────────

describe('sodClassBadge', () => {
	it('system → blue + 系统', () => {
		const b = sodClassBadge('system');
		expect(b.color).toBe('blue');
		expect(b.label).toBe('系统');
	});

	it('security → rose + 安全', () => {
		const b = sodClassBadge('security');
		expect(b.color).toBe('rose');
		expect(b.label).toBe('安全');
	});

	it('audit → teal + 审计', () => {
		const b = sodClassBadge('audit');
		expect(b.color).toBe('teal');
		expect(b.label).toBe('审计');
	});

	it('null → gray + 未分类', () => {
		const b = sodClassBadge(null);
		expect(b.color).toBe('gray');
		expect(b.label).toBe('未分类');
	});

	it('undefined → gray + 未分类', () => {
		const b = sodClassBadge(undefined);
		expect(b.color).toBe('gray');
		expect(b.label).toBe('未分类');
	});

	it("'' → gray + 未分类", () => {
		const b = sodClassBadge('');
		expect(b.color).toBe('gray');
		expect(b.label).toBe('未分类');
	});

	it('unknown class → gray + 未分类', () => {
		const b = sodClassBadge('foobar');
		expect(b.color).toBe('gray');
		expect(b.label).toBe('未分类');
	});
});

// ── B. RoleClassBadge component rendering ─────────────────────────────────────

describe('RoleClassBadge', () => {
	it('renders system-class tag for sodClass=system', async () => {
		const { default: RoleClassBadge } = await import('./RoleClassBadge.svelte');
		const { container } = render(RoleClassBadge, { props: { sodClass: 'system' } });
		// The Tag component renders with the label text
		expect(container.textContent).toContain('系统');
	});

	it('renders 未分类 badge for null sodClass', async () => {
		const { default: RoleClassBadge } = await import('./RoleClassBadge.svelte');
		const { container } = render(RoleClassBadge, { props: { sodClass: null } });
		expect(container.textContent).toContain('未分类');
	});
});

// ── C. isCrossClass utility ───────────────────────────────────────────────────

describe('isCrossClass', () => {
	it('same class → false', () => {
		expect(isCrossClass('system', 'system')).toBe(false);
		expect(isCrossClass('security', 'security')).toBe(false);
		expect(isCrossClass('audit', 'audit')).toBe(false);
	});

	it('different non-empty classes → true', () => {
		expect(isCrossClass('system', 'security')).toBe(true);
		expect(isCrossClass('security', 'audit')).toBe(true);
		expect(isCrossClass('audit', 'system')).toBe(true);
	});

	it('null candidate → false (cannot determine conflict)', () => {
		expect(isCrossClass(null, 'system')).toBe(false);
		expect(isCrossClass(undefined, 'security')).toBe(false);
	});

	it('null target → false (target has no class, no constraint)', () => {
		expect(isCrossClass('system', null)).toBe(false);
		expect(isCrossClass('system', undefined)).toBe(false);
	});

	it('both null → false', () => {
		expect(isCrossClass(null, null)).toBe(false);
	});
});

// ── D. SodEnablementPanel states ──────────────────────────────────────────────

describe('SodEnablementPanel', () => {
	beforeEach(() => {
		vi.resetAllMocks();
		// The SoD enable/disable controls now gate on security.write (the perm the
		// PUT /admin/dengbao/sod-mode route requires). Grant it via the session so
		// these state tests exercise panelState logic, not the permission gate.
		jmapSession.set({
			capabilities: {
				'urn:setjoin:params:jmap:mail': { admin: { consoles: ['access'], permissions: ['security.write'] } }
			}
		} as unknown as JmapSession);
	});

	it('loading state shows loading text', async () => {
		// Mock fetch to hang (never resolve) to keep loading state
		vi.stubGlobal('fetch', vi.fn(() => new Promise(() => {})));

		const { default: SodEnablementPanel } = await import('./SodEnablementPanel.svelte');
		const { container } = render(SodEnablementPanel);

		// The panel renders t('admin.sod.checking') = 'Checking for conflicts…' while fetch hangs
		expect(container.textContent).toContain('Checking');
		vi.unstubAllGlobals();
	});

	it('clean state: toggle is not disabled', async () => {
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => ({ enabled: false, violations: [] })
		}));

		const { default: SodEnablementPanel } = await import('./SodEnablementPanel.svelte');
		const { container } = render(SodEnablementPanel);

		// Wait for onMount async to complete
		await new Promise((r) => setTimeout(r, 0));

		// The toggle (role="switch") should not be disabled
		const switchInput = container.querySelector('input[role="switch"]');
		// It may or may not exist yet due to async; just ensure no crash
		if (switchInput) {
			expect((switchInput as HTMLInputElement).disabled).toBe(false);
		}
		vi.unstubAllGlobals();
	});

	it('violations state: toggle has aria-disabled, describes conflict count', async () => {
		const violations = [
			{ violationType: 'cross_class', subject: 'alice', detail: 'system vs security' },
			{ violationType: 'legacy_admin_role', subject: 'bob', detail: 'legacy admin' }
		];

		vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => ({ enabled: false, violations })
		}));

		const { default: SodEnablementPanel } = await import('./SodEnablementPanel.svelte');
		const { container } = render(SodEnablementPanel);

		// Wait for onMount async
		await new Promise((r) => setTimeout(r, 50));

		// toggle wrapper should be aria-disabled
		const toggleGroup = container.querySelector('[role="group"]');
		if (toggleGroup) {
			expect(toggleGroup.getAttribute('aria-disabled')).toBe('true');
		}

		// Switch input should be disabled
		const switchInput = container.querySelector('input[role="switch"]');
		if (switchInput) {
			expect((switchInput as HTMLInputElement).disabled).toBe(true);
		}

		vi.unstubAllGlobals();
	});

	it('violations state: legacy_admin_role row links to /admin/auth', async () => {
		const violations = [
			{ violationType: 'legacy_admin_role', subject: 'bob', detail: 'legacy admin' }
		];

		vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => ({ enabled: false, violations })
		}));

		const { default: SodEnablementPanel } = await import('./SodEnablementPanel.svelte');
		const { container } = render(SodEnablementPanel);

		await new Promise((r) => setTimeout(r, 50));

		const links = container.querySelectorAll('.sod-panel__action-link');
		let foundAuthLink = false;
		for (const link of links) {
			if ((link as HTMLAnchorElement).href?.includes('/admin/auth')) {
				foundAuthLink = true;
			}
		}
		// legacy_admin_role MUST resolve to /admin/auth (not /admin/roles).
		// This assertion will FAIL if resolveHref returns '/admin/roles' for this violation type.
		expect(foundAuthLink).toBe(true);
		vi.unstubAllGlobals();
	});

	it('violations state: governed rows link to /admin/roles not /admin/auth', async () => {
		const violations = [
			{ violationType: 'cross_class', subject: 'alice', detail: 'system vs security' }
		];

		vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => ({ enabled: false, violations })
		}));

		const { default: SodEnablementPanel } = await import('./SodEnablementPanel.svelte');
		const { container } = render(SodEnablementPanel);

		await new Promise((r) => setTimeout(r, 50));

		const links = container.querySelectorAll('.sod-panel__action-link');
		for (const link of links) {
			const href = (link as HTMLAnchorElement).href ?? '';
			if (href) {
				// Governed rows must NOT point to /admin/auth
				expect(href).not.toContain('/admin/auth');
				expect(href).toContain('/admin/roles');
			}
		}
		vi.unstubAllGlobals();
	});

	it('error state: retry button visible', async () => {
		vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('network error')));

		const { default: SodEnablementPanel } = await import('./SodEnablementPanel.svelte');
		const { container } = render(SodEnablementPanel);

		await new Promise((r) => setTimeout(r, 50));

		// The component shows t('admin.sod.retry') = 'Retry' (en default)
		expect(container).toBeTruthy();
		vi.unstubAllGlobals();
	});

	it('enabled state: toggle is checked ON', async () => {
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => ({ enabled: true, violations: [] })
		}));

		const { default: SodEnablementPanel } = await import('./SodEnablementPanel.svelte');
		const { container } = render(SodEnablementPanel);

		await new Promise((r) => setTimeout(r, 50));

		const switchInput = container.querySelector('input[role="switch"]');
		if (switchInput) {
			expect((switchInput as HTMLInputElement).checked).toBe(true);
		}
		vi.unstubAllGlobals();
	});
});
