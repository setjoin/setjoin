import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as admin from './client';

type Contract = [name: keyof typeof admin, args: unknown[], path: string, method?: string];

// These are public REST-boundary contracts, not implementation snapshots. A
// renamed endpoint, lost identifier encoding, or mutation that silently falls
// back to GET must fail with the exact helper name that drifted.
const contracts: Contract[] = [
	['adminUserUpdate', [7, { enabled: false }], '/api/admin/users/7', 'PUT'],
	['adminUserDelete', [7], '/api/admin/users/7', 'DELETE'],
	['adminMailboxLifecyclePreview', [9], '/api/admin/mailboxes/9/lifecycle/preview'],
	['adminRetainedMailboxes', [], '/api/admin/mailboxes/retained'],
	['adminUserImportCSV', [new File(['email\n'], 'users.csv')], '/api/admin/users/import', 'POST'],
	['adminUserAppAccess', [7], '/api/admin/users/7/app-access'],
	['adminUserSetAppAccess', [7, 'meet', false], '/api/admin/users/7/app-access/meet', 'PUT'],
	['adminRetentionPolicies', [], '/api/admin/retention/policies'],
	['adminRetentionCreate', [{ name: 'Legal', retainDays: 90 }], '/api/admin/retention/policies', 'POST'],
	['adminRetentionUpdate', [4, { retainDays: 30 }], '/api/admin/retention/policies/4', 'PUT'],
	['adminRetentionDelete', [4], '/api/admin/retention/policies/4', 'DELETE'],
	['adminLogRetention', [], '/api/admin/retention/logs'],
	['adminLogRetentionSet', [{ messageTraceDays: 30 }], '/api/admin/retention/logs', 'PUT'],
	['adminRetentionPrune', [], '/api/admin/retention/prune', 'POST'],
	['adminDomainList', [], '/api/admin/domains'],
	['adminDomainCreate', [{ name: 'example.test' }], '/api/admin/domains', 'POST'],
	['adminDomainUpdate', [3, { dmarcPolicy: 'reject' }], '/api/admin/domains/3', 'PUT'],
	['adminDomainDelete', [3], '/api/admin/domains/3', 'DELETE'],
	['adminRuleUpdate', [2, { enabled: false }], '/api/admin/rules/2', 'PUT'],
	['adminRuleDelete', [2], '/api/admin/rules/2', 'DELETE'],
	['adminConfigGet', ['smtp.host'], '/api/admin/system/config/smtp.host'],
	['adminConfigSet', ['smtp.host', 'mx.test', true], '/api/admin/system/config/smtp.host', 'PUT'],
	['adminAuthMethodList', [], '/api/admin/auth/methods'],
	['adminAuthMethodUpdate', ['oidc', { enabled: true }], '/api/admin/auth/methods/oidc', 'PUT'],
	['adminDeptCreate', [{ name: 'Sales' }], '/api/admin/departments', 'POST'],
	['adminDeptUpdate', [8, { name: 'Field Sales' }], '/api/admin/departments/8', 'PUT'],
	['adminDeptDelete', [8], '/api/admin/departments/8', 'DELETE'],
	['adminDeptAssignUser', [7, 8], '/api/admin/departments/assign-user', 'POST'],
	['adminDNSGenerate', ['example.test'], '/api/admin/dns/records?domain=example.test'],
	['adminDNSVerify', ['example.test'], '/api/admin/dns/verify?domain=example.test'],
	['adminGetTLSPolicy', [], '/api/admin/outbound-tls-policy'],
	['adminPutTLSPolicy', [{ mode: 'enforce' }], '/api/admin/outbound-tls-policy', 'PUT'],
	['adminAlertList', [], '/api/admin/alerts'],
	['adminAlertAck', ['db_ping'], '/api/admin/alerts/ack', 'POST'],
	['adminAlertUnsuppress', ['db_ping'], '/api/admin/alerts/unsuppress', 'POST'],
	['adminMailboxList', ['alice', 7], '/api/admin/mailboxes?q=alice&user_id=7'],
	['adminMailboxCreate', [{ userId: 7, name: 'Archive' }], '/api/admin/mailboxes', 'POST'],
	['adminMailboxUpdate', [9, { enabled: false }], '/api/admin/mailboxes/9', 'PUT'],
	['adminMailboxDelete', [9], '/api/admin/mailboxes/9', 'DELETE'],
	['adminMailboxFolders', [9], '/api/admin/mailboxes/9/folders'],
	['adminMailboxCreateFolder', [9, { name: 'Projects' }], '/api/admin/mailboxes/9/folders', 'POST'],
	['adminMailboxDeleteFolder', [9, 12], '/api/admin/mailboxes/9/folders/12', 'DELETE'],
	['adminReportsSummary', [14], '/api/admin/reports/summary?days=14'],
	['adminStorageStatus', [], '/api/admin/storage'],
	['adminStorageDRScanStart', [], '/api/admin/storage/dr-scan', 'POST'],
	['adminStorageDRScanList', [], '/api/admin/storage/dr-scan'],
	['adminStorageDRScanGet', [11], '/api/admin/storage/dr-scan/11'],
	['adminStorageDRScanReconcile', [11], '/api/admin/storage/dr-scan/11/reconcile', 'POST'],
	['adminFeatureList', [], '/api/admin/features'],
	['adminFeatureSet', ['feature.assist', true, 'enable assist'], '/api/admin/features/feature.assist', 'PUT'],
	['adminFeatureDeleteUnknown', ['legacy.feature', 'remove drift'], '/api/admin/features/legacy.feature', 'DELETE'],
	['adminFeatureRegistryModeSet', ['enforce', 'registry clean'], '/api/admin/features/registry-mode', 'PUT'],
	['adminADHealth', [], '/api/admin/ad/health'],
	['adminADConfig', [], '/api/admin/ad/config'],
	['adminADSetConfig', [{ server: 'dc.test' }], '/api/admin/ad/config', 'PUT'],
	['adminADTestConnection', [], '/api/admin/ad/test', 'POST'],
	['adminADSync', [], '/api/admin/ad/sync', 'POST'],
	['adminADConflicts', [], '/api/admin/ad/conflicts'],
	['adminADResolveConflict', [5, 'keep_local'], '/api/admin/ad/conflicts/5', 'POST'],
	['adminADResolveAllConflicts', ['accept_remote'], '/api/admin/ad/conflicts/resolve-all', 'POST'],
	['adminLDAPHealth', [], '/api/admin/ldap/health'],
	['adminLDAPConfig', [], '/api/admin/ldap/config'],
	['adminLDAPSetConfig', [{ url: 'ldap://directory.test' }], '/api/admin/ldap/config', 'PUT'],
	['adminLDAPTestConnection', [], '/api/admin/ldap/test', 'POST'],
	['adminLDAPPreview', [10], '/api/admin/ldap/preview?limit=10'],
	['adminLDAPSync', [], '/api/admin/ldap/sync', 'POST'],
	['adminLDAPSyncLog', [12], '/api/admin/ldap/sync-log?limit=12'],
	['getGlobalSourceConfig', ['imap'], '/api/admin/migration/source/imap'],
	['saveGlobalIMAPConfig', [{ host: 'imap.test' }], '/api/admin/migration/source/imap', 'PUT'],
	['saveGlobalEWSConfig', [{ endpoint: 'https://ews.test' }], '/api/admin/migration/source/ews', 'PUT'],
	['saveM365Config', [{ client_id: 'id', client_secret: 'secret', cloud: 'global' }], '/api/admin/migration/source/m365', 'PUT'],
	['deleteGlobalSourceConfig', ['imap'], '/api/admin/migration/source/imap', 'DELETE'],
	['adminGetGroupMappings', [], '/api/admin/identity/group-mappings'],
	['adminListEAPolicies', [], '/api/admin/email-address-policies'],
	['adminDeleteEAPolicy', [6], '/api/admin/email-address-policies/6', 'DELETE'],
	['adminReorderEAPolicies', [[6, 4]], '/api/admin/email-address-policies/reorder', 'POST'],
	['adminApplyEAPolicy', [6], '/api/admin/email-address-policies/apply', 'POST'],
	['adminApplyStatusEAPolicy', [15], '/api/admin/email-address-policies/apply/15'],
	['adminMAMListDevices', [], '/api/admin/mam/devices'],
	['adminMAMLockDevice', [4], '/api/admin/mam/devices/4/lock', 'POST'],
	['adminMAMUnlockDevice', [4], '/api/admin/mam/devices/4/unlock', 'POST'],
	['adminMAMGetDeviceEvents', [4, 20], '/api/admin/mam/devices/4/events?limit=20'],
	['adminMAMSetPerDevicePolicy', [4, { clipboard: 'deny' }], '/api/admin/mam/devices/4/policy', 'PUT'],
	['adminMAMUnsetPerDevicePolicy', [4, 'clipboard'], '/api/admin/mam/devices/4/policy/clipboard', 'DELETE'],
	['adminMAMListPolicies', [], '/api/admin/mam/policies'],
	['adminMAMSetGlobalPolicy', [{ screenshot: 'deny' }], '/api/admin/mam/policies', 'PUT'],
	['adminMAMSetGroupPolicy', ['department', 8, { export: 'deny' }], '/api/admin/mam/policies/group', 'PUT'],
	['adminMAMUnsetGroupPolicy', ['department', 8, 'export'], '/api/admin/mam/policies/group/department/8/export', 'DELETE'],
	['listIPRules', [25, 5], '/api/admin/threat/ip-rules?limit=25&offset=5'],
	['deleteIPRule', [13], '/api/admin/threat/ip-rules/13', 'DELETE'],
	['exportAuditCSV', [], '/api/admin/audit/csv'],
	['verifyAuditChain', [10, 20], '/api/admin/audit/verify?from_id=10&to_id=20'],
	['adminGetSignIns', [7], '/api/admin/users/7/sign-ins'],
	['adminGetSessions', [7], '/api/admin/users/7/sessions'],
	['adminSecureAccount', [7], '/api/admin/users/7/secure', 'POST'],
	['adminOfflinePolicyList', [], '/api/admin/offline/policies'],
	['adminOfflinePolicyDelete', [3], '/api/admin/offline/policies/3', 'DELETE'],
	['adminOfflineGetEnabled', [], '/api/admin/offline/enabled'],
	['adminOfflineSetEnabled', [true], '/api/admin/offline/enabled', 'PUT'],
	['offlineOptIn', [true], '/api/user/offline/opt-in', 'POST'],
	['adminOfflineListPendingDevices', [], '/api/admin/offline/devices/pending'],
	['getBulkRoleJob', [18], '/api/admin/jobs/bulk_role/18'],
	['getAuditPolicy', [], '/api/admin/audit/policy'],
	['putAuditPolicy', [{ enabled: true, reason: 'quarterly review' }], '/api/admin/audit/policy', 'PUT'],
	['adminListScopeSets', [], '/api/admin/scope-sets'],
	['adminGetScopeSet', [2], '/api/admin/scope-sets/2'],
	['adminDeleteScopeSet', [2, 'expired'], '/api/admin/scope-sets/2', 'DELETE'],
	['adminListDirectoryGroups', [], '/api/admin/distribution-groups'],
	['adminMyRoles', [], '/api/admin/me/roles'],
	['adminDeactivateRole', [4], '/api/admin/me/roles/4/deactivate', 'POST'],
	['adminGetActivationPolicy', [5], '/api/admin/roles/5/activation-policy'],
	['adminPutActivationPolicy', [5, { maxDurationMinutes: 60 }], '/api/admin/roles/5/activation-policy', 'PUT'],
	['adminGetJitDefaults', [], '/api/admin/system/jit-defaults'],
	['adminPutJitDefaults', [{ maxDurationMinutes: 60 }], '/api/admin/system/jit-defaults', 'PUT'],
	['adminDeleteApprovalPolicy', [3], '/api/admin/approval-policies/3', 'DELETE'],
	['adminListChatRetentionPolicies', [], '/api/admin/chat-retention-policies'],
	['adminDeleteChatRetentionPolicy', [3, true], '/api/admin/chat-retention-policies/3?confirm=DESTROY', 'DELETE'],
	['adminListChatEDiscoveryCases', [], '/api/admin/chat-ediscovery/cases'],
	['adminListChatCaseHolds', [9], '/api/admin/chat-ediscovery/holds?caseId=9'],
	['adminReleaseChatCaseHold', [6, 'case closed'], '/api/admin/chat-ediscovery/holds/6/release', 'POST'],
	['adminPreviewChatPurge', [], '/api/admin/chat-purge/preview'],
	['adminGetChatComplianceOverview', [], '/api/admin/chat-compliance/overview'],
	['adminVerifyChatChannelAudit', [2], '/api/admin/chat-channels/2/audit/verify'],
	['adminListSharingDefaults', [], '/api/admin/sharing/defaults'],
	['adminDeleteSharingDefault', [2, 'retired'], '/api/admin/sharing/defaults/2', 'DELETE'],
	['adminSharingUserOversight', [7], '/api/admin/sharing/users/7'],
	['adminListFederationPeers', [], '/api/admin/federation/peers'],
	['adminDeleteFederationPeer', ['peer.test'], '/api/admin/federation/peers/peer.test', 'DELETE'],
];

describe('admin REST helper endpoint contracts', () => {
	let fetchMock: ReturnType<typeof vi.fn>;

	beforeEach(() => {
		fetchMock = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => [],
			text: async () => '',
			blob: async () => new Blob(),
		});
		vi.stubGlobal('fetch', fetchMock);
		vi.stubGlobal('window', { location: { href: '' } });
	});

	afterEach(() => vi.unstubAllGlobals());

	it.each(contracts)('%s preserves its endpoint and HTTP method', async (name, args, path, method = 'GET') => {
		const invoke = admin[name] as unknown as (...values: unknown[]) => Promise<unknown>;
		await invoke(...args);
		expect(fetchMock).toHaveBeenCalledTimes(1);
		const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toContain(path);
		expect(options.method ?? 'GET').toBe(method);
		expect(options.credentials).toBe('include');
		if (url.startsWith('/api/admin')) expect(options.cache).toBe('no-store');
	});

	// Path-segment guard contract (S19-URL-CONSTRUCTION hardening): a hostile
	// segment must never reach the wire as a request-retargeting primitive —
	// it is either percent-encoded into a single segment or the helper throws.
	it('encodes hostile path segments and refuses segment-boundary values', async () => {
		// '..' and '/' cannot be smuggled through: the guard throws before fetch.
		await expect(
			(admin.adminUserSetAppAccess as unknown as (a: unknown, b: unknown, c: unknown) => Promise<unknown>)(
				'7',
				'../users',
				false,
			),
		).rejects.toThrow('adminPathSegment');

		// A hostile-but-encodable segment is encoded, so the request stays on
		// the same path the caller named (single segment, no traversal).
		fetchMock.mockClear();
		await (admin.adminUserSetAppAccess as unknown as (a: unknown, b: unknown, c: unknown) => Promise<unknown>)(
			'7',
			'app;x y',
			false,
		);
		const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe('/api/admin/users/7/app-access/app%3Bx%20y');

		// The guarded helper itself: hostile values rejected, benign encoded.
		expect(() => admin.adminPathSegment('')).toThrow(RangeError);
		expect(() => admin.adminPathSegment('a/b')).toThrow(RangeError);
		expect(() => admin.adminPathSegment('a?b')).toThrow(RangeError);
		expect(() => admin.adminPathSegment('a#b')).toThrow(RangeError);
		expect(() => admin.adminPathSegment('..')).toThrow(RangeError);
		expect(() => admin.adminPathSegment('a..b')).toThrow(RangeError);
		expect(admin.adminPathSegment('smtp.host')).toBe('smtp.host');
		expect(admin.adminPathSegment('app access;x')).toBe('app%20access%3Bx');
	});
});

describe('admin feature operator projection wire contract', () => {
	const base = {
		key: 'feature.imap',
		enabled: true,
		storedEnabled: true,
		defaultEnabled: true,
		classification: 'known',
		registryMode: 'observe',
		gatewayEffective: true,
		gatewaySource: 'database',
		authserverEffective: null,
		authserverSource: 'not_reported'
	};

	afterEach(() => vi.unstubAllGlobals());

	function respond(rows: unknown[]) {
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => rows,
			text: async () => ''
		}));
	}

	it('accepts typed operator metadata and normalizes a rolling old-server row to no warning', async () => {
		respond([
			{
				...base,
				changeMode: 'disconnect-live-clients',
				disableBehavior: 'immediate',
				dependencies: [],
				confirmationRequired: false
			},
			{ ...base, key: 'feature.spf' }
		]);

		const rows = await admin.adminFeatureList();
		expect(rows[0]).toMatchObject({ changeMode: 'disconnect-live-clients', disableBehavior: 'immediate' });
		expect(rows[1]).toMatchObject({
			changeMode: '',
			disableBehavior: '',
			dependencies: [],
			confirmationRequired: false
		});
	});

	it('rejects malformed operator axes and dependencies', async () => {
		for (const invalid of [
			{ ...base, changeMode: 'restart-process' },
			{ ...base, dependencies: ['feature.meet', 7] }
		]) {
			respond([invalid]);
			await expect(admin.adminFeatureList()).rejects.toThrow('invalid feature registry response');
		}
	});
});
