import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render } from '@testing-library/svelte/svelte5';
import { CAPABILITIES } from '$lib/admin/capabilityCatalog';

// ── fetch mock helpers ────────────────────────────────────────────────────────
//
// The component makes two kinds of fetch calls:
//   GET /admin/users?...                    (adminUserList, on mount)
//   GET /admin/users/{id}/effective-permissions  (adminEffectivePermissions, when userId set)
//
// httpRequest (the shared seam) calls res.text() on non-ok responses, so every
// mock response must expose a text() method.

function makeOkResponse(body: unknown) {
	return Promise.resolve({
		ok: true,
		status: 200,
		json: async () => body,
		text: async () => JSON.stringify(body)
	});
}

function makeErrorResponse(status: number, body: string) {
	return Promise.resolve({
		ok: false,
		status,
		json: async () => ({ detail: body }),
		text: async () => body
	});
}

const USER_LIST = [{ id: 7, email: 'alice@acme.com' }];

function mockFetch(effective: Record<string, unknown>) {
	return vi.fn((url: string) => {
		if ((url as string).includes('/effective-permissions')) {
			return makeOkResponse(effective);
		}
		// adminUserList
		return makeOkResponse(USER_LIST);
	});
}

// ── tests ─────────────────────────────────────────────────────────────────────

describe('AccessPreview', () => {
	beforeEach(() => vi.resetAllMocks());

	it('initial: shows "Access preview" title, no capability rows', async () => {
		// No userId prop → data stays null → initial empty state branch.
		// The i18n key admin.access_preview.initial_title = 'Access preview'.
		vi.stubGlobal('fetch', mockFetch({}));
		const { default: AccessPreview } = await import('./AccessPreview.svelte');
		const { container } = render(AccessPreview);
		await new Promise((r) => setTimeout(r, 0));
		// EmptyState renders the title text; exact string from en.ts
		expect(container.textContent).toContain('Access preview');
		expect(container.querySelector('.sj-ap-row')).toBeNull();
		vi.unstubAllGlobals();
	});

	it('audit-only user: every capability mark is ✗ and has an aria-label', async () => {
		// An Auditor has audit.read but NOT any catalogued write permission.
		// audit.read is not itself a catalogued mutation, so every mark is denied.
		vi.stubGlobal(
			'fetch',
			mockFetch({
				permissions: ['audit.read'],
				domainScope: null,
				consoles: ['logs'],
				sources: [{ roleGroupId: 4, roleName: 'Auditor', permissions: ['audit.read'] }]
			})
		);
		const { default: AccessPreview } = await import('./AccessPreview.svelte');
		const { container } = render(AccessPreview, { props: { userId: 7 } });
		await new Promise((r) => setTimeout(r, 10));

		const marks = [...container.querySelectorAll('.sj-ap-mark')];
		// Every catalogued capability must render a mark; do not duplicate the
		// generated catalog cardinality in this test.
		expect(marks.length).toBe(CAPABILITIES.length);
		// Every mark must be the ✗ glyph (audit.read is not in the catalog)
		expect(marks.every((m) => m.textContent?.trim() === '✗')).toBe(true);
		// a11y: never color-alone — each mark has a non-empty aria-label
		expect(marks.every((m) => (m.getAttribute('aria-label') ?? '').length > 0)).toBe(true);
		vi.unstubAllGlobals();
	});

	it('mixed user: granted cap shows "via User Admin" inline; denied cap shows "not granted"', async () => {
		// users.create is granted via User Admin; users.delete (and others) are not.
		// i18n: admin.access_preview.via = 'via {role}' → 'via User Admin'
		// i18n: admin.access_preview.not_granted = 'not granted'  (NO leading em-dash)
		vi.stubGlobal(
			'fetch',
			mockFetch({
				permissions: ['queue.read', 'users.create'],
				domainScope: null,
				consoles: ['mail'],
				sources: [{ roleGroupId: 2, roleName: 'User Admin', permissions: ['users.create'] }]
			})
		);
		const { default: AccessPreview } = await import('./AccessPreview.svelte');
		const { container } = render(AccessPreview, { props: { userId: 7 } });
		await new Promise((r) => setTimeout(r, 10));

		const txt = container.textContent ?? '';
		// Granting role shown inline for the granted capability
		expect(txt).toContain('via User Admin');
		// Not-granted text for denied capabilities (exact string from en.ts — no em-dash)
		expect(txt).toContain('not granted');
		vi.unstubAllGlobals();
	});

	it('non-admin user: "No admin permissions" empty state, no capability rows', async () => {
		// i18n: admin.access_preview.none_title = 'No admin permissions'
		// (NOT 'No admin access')
		vi.stubGlobal(
			'fetch',
			mockFetch({ permissions: [], domainScope: null, consoles: [], sources: [] })
		);
		const { default: AccessPreview } = await import('./AccessPreview.svelte');
		const { container } = render(AccessPreview, { props: { userId: 7 } });
		await new Promise((r) => setTimeout(r, 10));

		// EmptyState renders the none_title text
		expect(container.textContent).toContain('No admin permissions');
		// No capability grid rows rendered
		expect(container.querySelector('.sj-ap-row')).toBeNull();
		vi.unstubAllGlobals();
	});

	it('domain-scoped user: scope badge shows "Domain 3" (no hash)', async () => {
		// i18n: admin.access_preview.scope_domain = 'Domain {id}' → 'Domain 3'
		// (the brief's 'Domain #3' is wrong — the template has no '#')
		vi.stubGlobal(
			'fetch',
			mockFetch({
				permissions: ['users.create'],
				domainScope: 3,
				consoles: ['mail'],
				sources: [
					{
						roleGroupId: 2,
						roleName: 'User Admin',
						permissions: ['users.create'],
						effectiveScope: 3
					}
				]
			})
		);
		const { default: AccessPreview } = await import('./AccessPreview.svelte');
		const { container } = render(AccessPreview, { props: { userId: 7 } });
		await new Promise((r) => setTimeout(r, 10));

		expect(container.textContent).toContain('Domain 3');
		vi.unstubAllGlobals();
	});

	it('super-admin: every generated capability is granted', async () => {
		// i18n: admin.access_preview.counts =
		//   'Access: {consoles} / 5 consoles · {caps} / {total} capabilities'
		// The generated catalog is authoritative; adding a permission must expand
		// this preview without a second handwritten permission inventory.
		const allPerms = CAPABILITIES.map((cap) => cap.perm);
		vi.stubGlobal(
			'fetch',
			mockFetch({
				permissions: allPerms,
				domainScope: null,
				consoles: ['mail', 'system', 'logs', 'auth', 'access'],
				sources: [{ roleGroupId: 1, roleName: 'Super Admin', permissions: allPerms }]
			})
		);
		const { default: AccessPreview } = await import('./AccessPreview.svelte');
		const { container } = render(AccessPreview, { props: { userId: 7 } });
		await new Promise((r) => setTimeout(r, 10));

		const txt = container.textContent ?? '';
		// Both halves of the counts string must appear
		expect(txt).toContain('5 / 5 consoles');
		expect(txt).toContain(`${CAPABILITIES.length} / ${CAPABILITIES.length} capabilities`);

		// Every capability mark must be the ✓ glyph
		const marks = [...container.querySelectorAll('.sj-ap-mark')];
		expect(marks.length).toBe(CAPABILITIES.length);
		expect(marks.every((m) => m.textContent?.trim() === '✓')).toBe(true);
		vi.unstubAllGlobals();
	});

	it('error path: effective-permissions 500 → role="alert" banner renders, no capability rows', async () => {
		// httpRequest calls res.text() on non-ok responses and throws with that message.
		// The component catches it and renders <div class="sj-alert-danger" role="alert">.
		vi.stubGlobal(
			'fetch',
			vi.fn((url: string) => {
				if ((url as string).includes('/effective-permissions')) {
					return makeErrorResponse(500, 'database error');
				}
				return makeOkResponse(USER_LIST);
			})
		);
		const { default: AccessPreview } = await import('./AccessPreview.svelte');
		const { container } = render(AccessPreview, { props: { userId: 7 } });
		await new Promise((r) => setTimeout(r, 10));

		// The error banner must render
		expect(container.querySelector('[role="alert"]')).not.toBeNull();
		// No capability rows when in error state
		expect(container.querySelector('.sj-ap-row')).toBeNull();
		vi.unstubAllGlobals();
	});
});
