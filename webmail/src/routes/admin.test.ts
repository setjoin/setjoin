import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderAsUser, resetStores, mockSessionLoad } from '$lib/test-utils';
import { waitFor } from '@testing-library/svelte/svelte5';

import AdminDashboard from './admin/+page.svelte';
import AdminUsers from './admin/(mail)/users/+page.svelte';
import AdminDomains from './admin/(mail)/domains/+page.svelte';
import AdminQueue from './admin/(mail)/queue/+page.svelte';
import AdminSystem from './admin/(system)/system/+page.svelte';
import AdminAlerts from './admin/(logs)/alerts/+page.svelte';
import AdminAudit from './admin/(logs)/audit/+page.svelte';
import AdminDepartments from './admin/(mail)/departments/+page.svelte';
import AdminDmarc from './admin/(mail)/dmarc/+page.svelte';
import AdminDns from './admin/(mail)/dns/+page.svelte';
import AdminEdiscovery from './admin/ediscovery/+page.svelte';
import AdminContentSearch from './admin/content-search/+page.svelte';
import AdminFeatures from './admin/(system)/features/+page.svelte';
import AdminIdentity from './admin/(identity)/identity/+page.svelte';
import AdminMailboxes from './admin/(mail)/mailboxes/+page.svelte';
import AdminMigration from './admin/(mail)/migration/+page.svelte';
import AdminQ from './admin/(mail)/quarantine/+page.svelte';
import AdminReports from './admin/(mail)/reports/+page.svelte';
import AdminRetention from './admin/(mail)/retention/+page.svelte';
import AdminRules from './admin/(mail)/rules/+page.svelte';
import AdminStorage from './admin/(mail)/storage/+page.svelte';
import AdminTrace from './admin/(mail)/trace/+page.svelte';

describe('Admin CA-3b Routes', () => {
	it('includes the terms-of-use and user-risk admin routes', async () => {
		const tou = await import('./admin/(identity)/terms-of-use/+page.svelte');
		const risk = await import('./admin/(access)/user-risk/+page.svelte');
		expect(tou.default).toBeTruthy();
		expect(risk.default).toBeTruthy();
	});
});

describe('Admin Pages', () => {
	beforeEach(() => {
		resetStores();
		mockSessionLoad();
	});

	// Phase 35d — existing
	it('mounts admin dashboard', async () => {
		const { container } = await renderAsUser(AdminDashboard, {}, { isAdmin: true });
		expect(container).toBeTruthy();
	});
	it('mounts admin users page', async () => {
		const { container } = await renderAsUser(AdminUsers, {}, { isAdmin: true });
		expect(container).toBeTruthy();
	});
	it('mounts admin domains page', async () => {
		const { container } = await renderAsUser(AdminDomains, {}, { isAdmin: true });
		expect(container).toBeTruthy();
	});
	it('mounts admin queue page', async () => {
		const { container } = await renderAsUser(AdminQueue, {}, { isAdmin: true });
		expect(container).toBeTruthy();
	});
	it('mounts admin system page', async () => {
		const { container } = await renderAsUser(AdminSystem, {}, { isAdmin: true });
		expect(container).toBeTruthy();
	});

	// Phase 35e — deferred
	it('mounts admin alerts page', async () => {
		const { container } = await renderAsUser(AdminAlerts, {}, { isAdmin: true });
		expect(container).toBeTruthy();
	});
	it('mounts admin audit page', async () => {
		const { container } = await renderAsUser(AdminAudit, {}, { isAdmin: true });
		expect(container).toBeTruthy();
	});
	it('mounts admin departments page', async () => {
		const { container } = await renderAsUser(AdminDepartments, {}, { isAdmin: true });
		expect(container).toBeTruthy();
	});
	it('mounts admin dmarc page', async () => {
		vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, status: 200, json: async () => ({ pass: 0, fail: 0, none: 0, temperror: 0, byDomain: [], failures: [], days: [] }), text: async () => '' })));
		const { container } = await renderAsUser(AdminDmarc, {}, { isAdmin: true });
		expect(container).toBeTruthy();
	});
	it('mounts admin dns page', async () => {
		const { container } = await renderAsUser(AdminDns, {}, { isAdmin: true });
		expect(container).toBeTruthy();
	});
	it('mounts admin ediscovery page', async () => {
		const { container } = await renderAsUser(AdminEdiscovery, {}, { isAdmin: true });
		expect(container).toBeTruthy();
	});
	it('mounts admin content search page', async () => {
		const { container } = await renderAsUser(AdminContentSearch, {}, { isAdmin: true });
		expect(container).toBeTruthy();
	});
	it('mounts admin features page', async () => {
		const { container } = await renderAsUser(AdminFeatures, {}, { isAdmin: true });
		expect(container).toBeTruthy();
	});
	it('mounts admin identity page', async () => {
		const { container } = await renderAsUser(AdminIdentity, {}, { isAdmin: true });
		expect(container).toBeTruthy();
	});
	it('mounts admin mailboxes page', async () => {
		const { container } = await renderAsUser(AdminMailboxes, {}, { isAdmin: true });
		expect(container).toBeTruthy();
	});
	it('mounts admin migration page', async () => {
		const { container } = await renderAsUser(AdminMigration, {}, { isAdmin: true });
		expect(container).toBeTruthy();
	});
	it('mounts admin quarantine page', async () => {
		const { container } = await renderAsUser(AdminQ, {}, { isAdmin: true });
		expect(container).toBeTruthy();
	});
	it('mounts admin reports page', async () => {
		vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, status: 200, json: async () => ({ daily: [], totalSent: 0, totalReceived: 0, totalSpam: 0, spamCount: 0, totalBounced: 0, topSenders: [], topRecipients: [], ruleTriggers: [] }), text: async () => '' })));
		const { container } = await renderAsUser(AdminReports, {}, { isAdmin: true });
		expect(container).toBeTruthy();
	});
	it('mounts admin retention page', async () => {
		const { container } = await renderAsUser(AdminRetention, {}, { isAdmin: true });
		expect(container).toBeTruthy();
	});
	it('mounts admin rules page', async () => {
		const { container } = await renderAsUser(AdminRules, {}, { isAdmin: true });
		expect(container).toBeTruthy();
	});
	it('mounts admin storage page', async () => {
		vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, status: 200, json: async () => ({ objects: { count: 0, totalSize: 0 }, buckets: [], orphans: 0, usage: { size: 0 }, backend: { onlineDisks: 0, offlineDisks: 0 }, capacity: { used: 0, total: 1, percent: 0 } }), text: async () => '' })));
		const { container } = await renderAsUser(AdminStorage, {}, { isAdmin: true });
		expect(container).toBeTruthy();
	});
	it('mounts admin trace page', async () => {
		vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, status: 200, json: async () => ({ records: [], total: 0 }), text: async () => '' })));
		const { container } = await renderAsUser(AdminTrace, {}, { isAdmin: true });
		expect(container).toBeTruthy();
	});
});

describe('Admin Dashboard Error Differentiation', () => {
	beforeEach(() => {
		resetStores();
	});

	it('shows user-friendly message for network errors (TypeError), not raw exception', async () => {
		vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input.toString();
			if (url.includes('/admin/health')) {
				return { ok: true, status: 200, json: async () => ({ checks: [], status: 'ok' }), text: async () => '' };
			}
			throw new TypeError('Failed to fetch');
		}));
		const { findByText } = await renderAsUser(AdminDashboard, {}, { isAdmin: true });
		expect(await findByText(/network error/i)).toBeTruthy();
	});
});

describe('Admin Mailboxes Error States', () => {
	beforeEach(() => {
		resetStores();
	});

	it('shows error when user list fails to load', async () => {
		vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input.toString();

			// Mailbox list succeeds
			if (url.includes('/admin/mailboxes')) {
				return {
					ok: true, status: 200,
					json: async () => [],
					text: async () => ''
				};
			}

			// User list FAILS
			if (url.includes('/admin/users')) {
				throw new Error('Failed to load users');
			}

			return { ok: true, status: 200, json: async () => ({}), text: async () => '' };
		}));

		const { findByText } = await renderAsUser(AdminMailboxes, {}, { isAdmin: true });
		expect(await findByText(/failed to load users/i)).toBeTruthy();
	});
});

describe('Admin Users Error States', () => {
	beforeEach(() => {
		resetStores();
	});

	it('shows error when department list fails to load', async () => {
		vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input.toString();
			const method = init?.method || 'GET';

			// User list succeeds
			if (url.includes('/admin/users') && method === 'GET') {
				return {
					ok: true, status: 200,
					json: async () => [],
					text: async () => ''
				};
			}

			// Department tree FAILS
			if (url.includes('/admin/departments/tree')) {
				throw new Error('Failed to load departments');
			}

			return { ok: true, status: 200, json: async () => ({}), text: async () => '' };
		}));

		const { findByText } = await renderAsUser(AdminUsers, {}, { isAdmin: true });
		expect(await findByText(/failed to load departments/i)).toBeTruthy();
	});
});

describe('Admin Identity Error States', () => {
	beforeEach(() => {
		resetStores();
	});

	it('shows user-friendly error instead of raw TypeError on admin identity page', async () => {
		vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('Failed to fetch'); }));
		const { container } = await renderAsUser(AdminIdentity, {}, { isAdmin: true });
		await waitFor(() => {
			expect(container.textContent).toContain('Network error');
			expect(container.textContent).not.toContain('Failed to fetch');
			expect(container.textContent).not.toContain('TypeError');
		});
	});
});

describe('Admin Queue Error States', () => {
	beforeEach(() => {
		resetStores();
	});

	it('shows user-friendly error instead of raw TypeError on queue page', async () => {
		vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('Failed to fetch'); }));
		const { container } = await renderAsUser(AdminQueue, {}, { isAdmin: true });
		await waitFor(() => {
			expect(container.textContent).toContain('Network error');
			expect(container.textContent).not.toContain('Failed to fetch');
			expect(container.textContent).not.toContain('TypeError');
		});
	});
});

describe('Admin Departments Error States', () => {
	beforeEach(() => {
		resetStores();
	});

	it('shows error when user list fails to load', async () => {
		vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input.toString();
			// Department tree succeeds
			if (url.includes('/admin/departments/tree')) {
				return { ok: true, status: 200, json: async () => [], text: async () => '' };
			}
			// User list FAILS
			if (url.includes('/admin/users')) {
				return { ok: false, status: 500, json: async () => ({}), text: async () => 'Internal server error' };
			}
			return { ok: true, status: 200, json: async () => ({}), text: async () => '' };
		}));
		const { findByText } = await renderAsUser(AdminDepartments, {}, { isAdmin: true });
		// The raw server body ('Internal server error') must NOT leak into the UI;
		// the default httpRequest error path surfaces a generic status string.
		expect(await findByText(/request failed \(500\)/i)).toBeTruthy();
	});
});
