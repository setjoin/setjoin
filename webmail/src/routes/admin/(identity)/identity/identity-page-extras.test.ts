/**
 * COV-2 — additional coverage for the identity admin page itself
 * (`(identity)/identity/+page.svelte`), complementing `identity.test.ts`:
 *
 * - `?user=` deep-link into the per-user sign-in activity drill-down
 * - the overview tab's IdentityModelConsole mount
 * - failure arms of the AD/LDAP save, test, and sync actions
 * - AD/LDAP password-with-save branches
 * - LDAP enable-cancel and disable paths
 * - LDAP preview action variants (update / unknown) and both empty states
 * - the audited-reason prompt gate on group-mapping saves
 *
 * IdentityModelConsole is stubbed — the console's own behaviour is
 * `identity.test.ts`'s subject; here only the page-level wiring is under test.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor, within } from '@testing-library/svelte/svelte5';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { page } from '$app/state';
import { jmapSession } from '$lib/stores/session';

const api = vi.hoisted(() => ({
	authList: vi.fn(), authUpdate: vi.fn(),
	adConfig: vi.fn(), adSet: vi.fn(), adTest: vi.fn(), adSync: vi.fn(), adHealth: vi.fn(),
	conflicts: vi.fn(), resolve: vi.fn(), resolveAll: vi.fn(),
	getMappings: vi.fn(), updateMappings: vi.fn(),
	ldapConfig: vi.fn(), ldapSet: vi.fn(), ldapTest: vi.fn(), ldapPreview: vi.fn(),
	ldapSync: vi.fn(), ldapHealth: vi.fn(), ldapLog: vi.fn(),
	auditPolicy: vi.fn(),
	signIns: vi.fn(), sessions: vi.fn(), secureAccount: vi.fn()
}));

vi.mock('$lib/admin/client', () => ({
	adminAuthMethodList: api.authList, adminAuthMethodUpdate: api.authUpdate,
	adminADConfig: api.adConfig, adminADSetConfig: api.adSet, adminADTestConnection: api.adTest,
	adminADSync: api.adSync, adminADHealth: api.adHealth, adminADConflicts: api.conflicts,
	adminADResolveConflict: api.resolve, adminADResolveAllConflicts: api.resolveAll,
	adminGetGroupMappings: api.getMappings, adminUpdateGroupMappings: api.updateMappings,
	adminLDAPConfig: api.ldapConfig, adminLDAPSetConfig: api.ldapSet,
	adminLDAPTestConnection: api.ldapTest, adminLDAPPreview: api.ldapPreview,
	adminLDAPSync: api.ldapSync, adminLDAPHealth: api.ldapHealth, adminLDAPSyncLog: api.ldapLog,
	getAuditPolicy: api.auditPolicy,
	adminGetSignIns: api.signIns, adminGetSessions: api.sessions, adminSecureAccount: api.secureAccount
}));

const consoleStub = vi.hoisted(() => ({ mounts: 0 }));
vi.mock('$lib/components/admin/identity/IdentityModelConsole.svelte', () => ({
	default: () => { consoleStub.mounts += 1; return null; }
}));

import Page from './+page.svelte';

const health = {
	status: 'healthy', lastSync: '2026-07-20T01:02:03Z', checked: 10, created: 2,
	updated: 3, disabled: 1, skipped: 4, errors: 0, pendingConflicts: 0
};

function grantPermissions() {
	jmapSession.set({ accounts: {}, primaryAccounts: {}, capabilities: {
		'urn:setjoin:params:jmap:mail': { admin: { consoles: ['auth'], permissions: ['identity.write'] } }
	} } as never);
}

async function renderPage() {
	const rendered = await renderAsUser(Page, {}, { isAdmin: true });
	grantPermissions();
	await waitFor(() => expect(screen.queryByText('Loading…')).not.toBeInTheDocument());
	return rendered;
}

describe('identity page extras — deep link and overview mount', () => {
	beforeEach(() => {
		resetStores();
		vi.clearAllMocks();
		consoleStub.mounts = 0;
		api.authList.mockResolvedValue([{ slug: 'password', name: 'Password', priority: 10, enabled: true }]);
		api.adConfig.mockResolvedValue({ ad_sync_domain: 'corp.local', ad_sync_bind_dn: 'CN=svc', ad_sync_interval_min: '30' });
		api.adSet.mockResolvedValue({}); api.adTest.mockResolvedValue({}); api.adSync.mockResolvedValue({});
		api.adHealth.mockResolvedValue(health);
		api.conflicts.mockResolvedValue([]);
		api.getMappings.mockResolvedValue({ saml: { corp: [{ idp_group: 'Engineering', distribution_group_id: 2, admin_role: null, department_id: 4 }] }, oidc: {} });
		api.updateMappings.mockResolvedValue({});
		api.ldapConfig.mockResolvedValue({ ldap_sync_host: 'ldap.corp.local', ldap_sync_port: '636', ldap_sync_tls: 'true', ldap_sync_bind_dn: 'cn=svc', ldap_sync_base_dn: 'dc=corp,dc=local', ldap_sync_user_filter: '(objectClass=person)', ldap_sync_interval_min: '15', ldap_sync_auto_create_depts: 'true', ldap_sync_enabled: 'false' });
		api.ldapSet.mockResolvedValue({}); api.ldapTest.mockResolvedValue({ checked: 12 });
		api.ldapPreview.mockResolvedValue({ total: 0, rows: [] });
		api.ldapSync.mockResolvedValue({}); api.ldapHealth.mockResolvedValue(health);
		api.ldapLog.mockResolvedValue([]);
		api.auditPolicy.mockResolvedValue({ reasonRequiredAreas: [] });
		api.signIns.mockResolvedValue({ status: 200, items: [] });
		api.sessions.mockResolvedValue({ sessions: [] });
	});

	afterEach(() => {
		(page.url as { searchParams: URLSearchParams }).searchParams = new URLSearchParams();
		resetStores();
	});

	it('deep-links ?user= into the sign-in drill-down and mounts the overview console', async () => {
		(page.url as { searchParams: URLSearchParams }).searchParams = new URLSearchParams('user=42');
		await renderPage();

		await waitFor(() => expect(api.signIns).toHaveBeenCalledWith(42));
		expect(api.sessions).toHaveBeenCalledWith(42);

		await fireEvent.click(screen.getByRole('tab', { name: 'Identity model' }));
		expect(consoleStub.mounts).toBe(1);
	});

	it('keeps the drill-down closed without a usable ?user= value', async () => {
		(page.url as { searchParams: URLSearchParams }).searchParams = new URLSearchParams('user=nope');
		await renderPage();
		await waitFor(() => expect(api.adConfig).toHaveBeenCalled());
		expect(api.signIns).not.toHaveBeenCalled();
		expect(consoleStub.mounts).toBe(0);
	});
});

describe('identity page extras — AD failure arms and password save', () => {
	beforeEach(() => {
		resetStores();
		vi.clearAllMocks();
		api.authList.mockResolvedValue([{ slug: 'password', name: 'Password', priority: 10, enabled: true }]);
		api.adConfig.mockResolvedValue({ ad_sync_domain: 'corp.local', ad_sync_bind_dn: 'CN=svc', ad_sync_interval_min: '30' });
		api.adSet.mockResolvedValue({}); api.adTest.mockResolvedValue({}); api.adSync.mockResolvedValue({});
		api.adHealth.mockResolvedValue(health);
		api.conflicts.mockResolvedValue([]);
		api.getMappings.mockResolvedValue({ saml: {}, oidc: {} });
		api.updateMappings.mockResolvedValue({});
		api.ldapConfig.mockResolvedValue({ ldap_sync_host: '', ldap_sync_port: '636', ldap_sync_tls: 'true', ldap_sync_bind_dn: '', ldap_sync_base_dn: '', ldap_sync_user_filter: '(objectClass=person)', ldap_sync_interval_min: '15', ldap_sync_auto_create_depts: 'false', ldap_sync_enabled: 'false' });
		api.ldapSet.mockResolvedValue({}); api.ldapTest.mockResolvedValue({ checked: 0 });
		api.ldapPreview.mockResolvedValue({ total: 0, rows: [] });
		api.ldapSync.mockResolvedValue({}); api.ldapHealth.mockResolvedValue(health);
		api.ldapLog.mockResolvedValue([]);
		api.auditPolicy.mockResolvedValue({ reasonRequiredAreas: [] });
	});

	it('reports AD save, test, and sync failures without leaving the page', async () => {
		api.adSet.mockRejectedValueOnce(new Error('ad config rejected'));
		api.adTest.mockRejectedValueOnce(new Error('ad unreachable'));
		api.adSync.mockRejectedValueOnce(new Error('ad sync failed'));
		await renderPage();

		await fireEvent.click(screen.getByRole('tab', { name: 'Active directory' }));
		await fireEvent.click(screen.getByRole('button', { name: 'Save config' }));
		expect(await screen.findByText('ad config rejected')).toBeInTheDocument();

		await fireEvent.click(screen.getByRole('button', { name: 'Test connection' }));
		expect(await screen.findByText('ad unreachable')).toBeInTheDocument();

		await fireEvent.click(screen.getByRole('button', { name: 'Sync now' }));
		expect(await screen.findByText('ad sync failed')).toBeInTheDocument();
	});

	it('sends a fresh AD password when one is entered and clears it after save', async () => {
		await renderPage();
		await fireEvent.click(screen.getByRole('tab', { name: 'Active directory' }));

		await fireEvent.input(screen.getByLabelText('Password (encrypted at rest)'), { target: { value: 's3cret' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Save config' }));
		await waitFor(() => expect(api.adSet).toHaveBeenCalledWith(
			expect.objectContaining({ ad_sync_password_enc: 's3cret' })
		));
		expect(screen.getByLabelText('Password (encrypted at rest)')).toHaveValue('');
	});
});

describe('identity page extras — LDAP failure arms, variants, empty states, toggle paths', () => {
	beforeEach(() => {
		resetStores();
		vi.clearAllMocks();
		api.authList.mockResolvedValue([{ slug: 'password', name: 'Password', priority: 10, enabled: true }]);
		api.adConfig.mockResolvedValue({ ad_sync_domain: 'corp.local', ad_sync_bind_dn: 'CN=svc', ad_sync_interval_min: '30' });
		api.adSet.mockResolvedValue({}); api.adTest.mockResolvedValue({}); api.adSync.mockResolvedValue({});
		api.adHealth.mockResolvedValue(health);
		api.conflicts.mockResolvedValue([]);
		api.getMappings.mockResolvedValue({ saml: {}, oidc: {} });
		api.updateMappings.mockResolvedValue({});
		api.ldapConfig.mockResolvedValue({ ldap_sync_host: 'ldap.corp.local', ldap_sync_port: '636', ldap_sync_tls: 'true', ldap_sync_bind_dn: 'cn=svc', ldap_sync_base_dn: 'dc=corp,dc=local', ldap_sync_user_filter: '(objectClass=person)', ldap_sync_interval_min: '15', ldap_sync_auto_create_depts: 'true', ldap_sync_enabled: 'false' });
		api.ldapSet.mockResolvedValue({}); api.ldapTest.mockResolvedValue({ checked: 12 });
		api.ldapPreview.mockResolvedValue({ total: 0, rows: [] });
		api.ldapSync.mockResolvedValue({}); api.ldapHealth.mockResolvedValue(health);
		api.ldapLog.mockResolvedValue([]);
		api.auditPolicy.mockResolvedValue({ reasonRequiredAreas: [] });
	});

	it('reports LDAP test/save/sync failures and sends a fresh bind password', async () => {
		api.ldapTest.mockRejectedValueOnce(new Error('ldap bind rejected'));
		api.ldapSet.mockRejectedValueOnce(new Error('ldap save rejected'));
		api.ldapSync.mockRejectedValueOnce(new Error('ldap sync failed'));
		await renderPage();

		await fireEvent.click(screen.getByRole('tab', { name: 'Custom LDAP' }));

		await fireEvent.click(screen.getByRole('button', { name: 'Test connection' }));
		expect(await screen.findByText('ldap bind rejected')).toBeInTheDocument();

		await fireEvent.click(screen.getByRole('button', { name: 'Save config' }));
		expect(await screen.findByText('ldap save rejected')).toBeInTheDocument();

		await fireEvent.click(screen.getByRole('button', { name: 'Sync now' }));
		expect(await screen.findByText('ldap sync failed')).toBeInTheDocument();

		await fireEvent.input(screen.getByLabelText('Password (encrypted at rest)'), { target: { value: 'bind-s3cret' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Save config' }));
		await waitFor(() => expect(api.ldapSet).toHaveBeenCalledWith(
			expect.objectContaining({ ldap_sync_password_enc: 'bind-s3cret' })
		));
		expect(screen.getByLabelText('Password (encrypted at rest)')).toHaveValue('');
	});

	it('labels preview actions and shows both empty states', async () => {
		api.ldapPreview.mockResolvedValue({
			total: 2,
			rows: [
				{ email: 'u1@example.test', displayName: 'U One', action: 'update', reason: null },
				{ email: 'u2@example.test', displayName: 'U Two', action: 'teleport', reason: 'unmatched' }
			]
		});
		await renderPage();
		await fireEvent.click(screen.getByRole('tab', { name: 'Custom LDAP' }));

		expect(screen.getByText('No sync runs yet')).toBeInTheDocument();

		await fireEvent.click(screen.getByRole('button', { name: 'Preview' }));
		expect(await screen.findByText('u1@example.test')).toBeInTheDocument();
		expect(screen.getByText('u2@example.test')).toBeInTheDocument();
		expect(screen.getByText('Update')).toBeInTheDocument();
		expect(screen.getByText('Skip')).toBeInTheDocument();

		api.ldapPreview.mockResolvedValue({ total: 0, rows: [] });
		await fireEvent.click(screen.getByRole('button', { name: 'Preview' }));
		expect(await screen.findByText(/to see what a sync would do/)).toBeInTheDocument();
	});

	it('cancels out of the LDAP enable confirmation without saving', async () => {
		await renderPage();
		await fireEvent.click(screen.getByRole('tab', { name: 'Custom LDAP' }));

		await fireEvent.click(screen.getByRole('switch', { name: 'Enable sync' }));
		const dialog = screen.getByRole('dialog');
		expect(dialog).toHaveTextContent('Enable custom LDAP sync?');
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
		await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
		expect(api.ldapSet).not.toHaveBeenCalled();
	});

	it('disables an enabled LDAP sync directly without a confirmation dialog', async () => {
		api.ldapConfig.mockResolvedValue({ ldap_sync_host: 'ldap.corp.local', ldap_sync_port: '636', ldap_sync_tls: 'true', ldap_sync_bind_dn: 'cn=svc', ldap_sync_base_dn: 'dc=corp,dc=local', ldap_sync_user_filter: '(objectClass=person)', ldap_sync_interval_min: '15', ldap_sync_auto_create_depts: 'true', ldap_sync_enabled: 'true' });
		await renderPage();
		await fireEvent.click(screen.getByRole('tab', { name: 'Custom LDAP' }));

		const enable = screen.getByRole('switch', { name: 'Enable sync' });
		await waitFor(() => expect(enable).toBeChecked());
		await fireEvent.click(enable);
		await waitFor(() => expect(api.ldapSet).toHaveBeenCalledWith(
			expect.objectContaining({ ldap_sync_enabled: 'false', ldap_sync_host: 'ldap.corp.local' })
		));
		expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
	});
});

describe('identity page extras — audited group-mapping saves', () => {
	beforeEach(() => {
		resetStores();
		vi.clearAllMocks();
		api.authList.mockResolvedValue([{ slug: 'password', name: 'Password', priority: 10, enabled: true }]);
		api.adConfig.mockResolvedValue({ ad_sync_domain: 'corp.local', ad_sync_bind_dn: 'CN=svc', ad_sync_interval_min: '30' });
		api.adSet.mockResolvedValue({}); api.adTest.mockResolvedValue({}); api.adSync.mockResolvedValue({});
		api.adHealth.mockResolvedValue(health);
		api.conflicts.mockResolvedValue([]);
		api.getMappings.mockResolvedValue({ saml: { corp: [{ idp_group: 'Engineering', distribution_group_id: 2, admin_role: null, department_id: 4 }] }, oidc: {} });
		api.updateMappings.mockResolvedValue({});
		api.ldapConfig.mockResolvedValue({ ldap_sync_host: '', ldap_sync_port: '636', ldap_sync_tls: 'true', ldap_sync_bind_dn: '', ldap_sync_base_dn: '', ldap_sync_user_filter: '(objectClass=person)', ldap_sync_interval_min: '15', ldap_sync_auto_create_depts: 'false', ldap_sync_enabled: 'false' });
		api.ldapSet.mockResolvedValue({}); api.ldapTest.mockResolvedValue({ checked: 0 });
		api.ldapPreview.mockResolvedValue({ total: 0, rows: [] });
		api.ldapSync.mockResolvedValue({}); api.ldapHealth.mockResolvedValue(health);
		api.ldapLog.mockResolvedValue([]);
		api.auditPolicy.mockResolvedValue({ reasonRequiredAreas: ['identity'] });
	});

	it('gates the mapping save behind the reason prompt and reports save failures', async () => {
		api.updateMappings.mockRejectedValueOnce(new Error('mapping write rejected'));
		await renderPage();

		await fireEvent.click(screen.getByRole('tab', { name: 'Groups' }));
		await fireEvent.change(screen.getByLabelText('Provider'), { target: { value: 'corp' } });
		expect(screen.getByDisplayValue('Engineering')).toBeInTheDocument();

		// Policy requires an audited reason: plain Save opens the prompt, and the
		// reason travels with the (failing) write.
		await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
		const dialog = screen.getByRole('dialog');
		expect(dialog).toHaveTextContent('Reason for change');
		await fireEvent.input(within(dialog).getByLabelText('Reason'), { target: { value: 'Quarterly access audit' } });
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
		await waitFor(() => expect(api.updateMappings).toHaveBeenCalledWith(
			'saml', 'corp', expect.anything(), 'Quarterly access audit'
		));
		expect(await screen.findByText('mapping write rejected')).toBeInTheDocument();

		// Cancel keeps the mappings untouched.
		await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
		await fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Cancel' }));
		await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
		expect(api.updateMappings).toHaveBeenCalledTimes(1);

		// A retry with a fresh reason succeeds and clears the prompt.
		await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
		const retry = screen.getByRole('dialog');
		await fireEvent.input(within(retry).getByLabelText('Reason'), { target: { value: 'Corrected dept mapping' } });
		await fireEvent.click(within(retry).getByRole('button', { name: 'Save' }));
		await waitFor(() => expect(api.updateMappings).toHaveBeenCalledTimes(2));
		expect(api.updateMappings).toHaveBeenLastCalledWith('saml', 'corp', expect.anything(), 'Corrected dept mapping');
		await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
	});
});
