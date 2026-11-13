import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor } from '@testing-library/svelte/svelte5';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { jmapSession } from '$lib/stores/session';

const api = vi.hoisted(() => ({
	authList: vi.fn(), authUpdate: vi.fn(), adConfig: vi.fn(), adSet: vi.fn(), adTest: vi.fn(),
	adSync: vi.fn(), adHealth: vi.fn(), conflicts: vi.fn(), resolve: vi.fn(), resolveAll: vi.fn(),
	getMappings: vi.fn(), updateMappings: vi.fn(), ldapConfig: vi.fn(), ldapSet: vi.fn(),
	ldapTest: vi.fn(), ldapPreview: vi.fn(), ldapSync: vi.fn(), ldapHealth: vi.fn(), ldapLog: vi.fn(),
	identitySources: vi.fn(), identityPeople: vi.fn(), identityConflicts: vi.fn(),
	identityTransitions: vi.fn(), identityEvents: vi.fn(), identityPreview: vi.fn(),
	identityDetail: vi.fn(), identityChallenge: vi.fn(), identityChallengeComplete: vi.fn(),
	identityRequest: vi.fn(), identityExecute: vi.fn(), identityReport: vi.fn(),
	identitySourceDetail: vi.fn(), identitySourcePlan: vi.fn(), identitySourceApply: vi.fn(),
	identitySourceDryRun: vi.fn(), identitySourceActivate: vi.fn(), identitySourcePause: vi.fn(),
	identitySourceResume: vi.fn(), identitySourceRetire: vi.fn(), identitySourceSecret: vi.fn(),
	identityPersonDetail: vi.fn(), identityConflictDetail: vi.fn(), identityConflictDecide: vi.fn(),
	identityApprove: vi.fn(), identityDeny: vi.fn(), identityCancel: vi.fn(),
	identityRetry: vi.fn(), identityRollbackPreview: vi.fn(), identityRollback: vi.fn(),
	identityUpgradeStatus: vi.fn(),
	auditPolicy: vi.fn()
}));

vi.mock('$lib/admin/client', () => ({
	adminAuthMethodList: api.authList, adminAuthMethodUpdate: api.authUpdate,
	adminADConfig: api.adConfig, adminADSetConfig: api.adSet, adminADTestConnection: api.adTest,
	adminADSync: api.adSync, adminADHealth: api.adHealth, adminADConflicts: api.conflicts,
	adminADResolveConflict: api.resolve, adminADResolveAllConflicts: api.resolveAll,
	adminGetGroupMappings: api.getMappings, adminUpdateGroupMappings: api.updateMappings,
	adminLDAPConfig: api.ldapConfig, adminLDAPSetConfig: api.ldapSet, adminLDAPTestConnection: api.ldapTest,
	adminLDAPPreview: api.ldapPreview, adminLDAPSync: api.ldapSync, adminLDAPHealth: api.ldapHealth,
	adminLDAPSyncLog: api.ldapLog,
	adminIdentitySources: api.identitySources, adminIdentityPeople: api.identityPeople,
	adminIdentityConflicts: api.identityConflicts, adminIdentityTransitions: api.identityTransitions,
	adminIdentityEvents: api.identityEvents, adminIdentityTransitionPreview: api.identityPreview,
	adminIdentitySourceDetail: api.identitySourceDetail,
	adminIdentitySourcePlan: api.identitySourcePlan,
	adminIdentitySourceApply: api.identitySourceApply,
	adminIdentitySourceDryRun: api.identitySourceDryRun,
	adminIdentitySourceActivate: api.identitySourceActivate,
	adminIdentitySourcePause: api.identitySourcePause,
	adminIdentitySourceResume: api.identitySourceResume,
	adminIdentitySourceRetire: api.identitySourceRetire,
	adminIdentitySourceSecret: api.identitySourceSecret,
	adminIdentityPersonDetail: api.identityPersonDetail,
	adminIdentityConflictDetail: api.identityConflictDetail,
	adminIdentityConflictDecide: api.identityConflictDecide,
	adminIdentityTransitionDetail: api.identityDetail,
	adminIdentityTransitionChallenge: api.identityChallenge,
	adminIdentityTransitionChallengeComplete: api.identityChallengeComplete,
	adminIdentityTransitionRequest: api.identityRequest,
	adminIdentityTransitionApprove: api.identityApprove,
	adminIdentityTransitionDeny: api.identityDeny,
	adminIdentityTransitionExecute: api.identityExecute, adminIdentityTransitionReport: api.identityReport,
	adminIdentityTransitionCancel: api.identityCancel,
	adminIdentityTransitionRetry: api.identityRetry,
	adminIdentityTransitionRollbackPreview: api.identityRollbackPreview,
	adminIdentityTransitionRollback: api.identityRollback,
	adminIdentityUpgradeStatus: api.identityUpgradeStatus,
	getAuditPolicy: api.auditPolicy
}));

import Page from './+page.svelte';
import IdentityModelConsole from '$lib/components/admin/identity/IdentityModelConsole.svelte';

const health = {
	status: 'healthy', lastSync: '2026-07-20T01:02:03Z', checked: 10, created: 2,
	updated: 3, disabled: 1, skipped: 4, errors: 1, pendingConflicts: 1
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
	await waitFor(() => expect(screen.queryByText(/Loading identity data/)).not.toBeInTheDocument());
	return rendered;
}

async function renderIdentityConsole(props: {
	initialSection?: 'overview' | 'sources' | 'people' | 'conflicts' | 'transitions' | 'audit';
	selectedId?: string;
	sourceSetup?: boolean;
} = {}) {
	const rendered = await renderAsUser(IdentityModelConsole, props, { isAdmin: true });
	grantPermissions();
	return rendered;
}

describe('admin identity workflows', () => {
	beforeEach(() => {
		resetStores();
		vi.clearAllMocks();
		api.authList.mockResolvedValue([{ slug: 'password', name: 'Password', priority: 10, enabled: true }]);
		api.authUpdate.mockResolvedValue({});
		api.adConfig.mockResolvedValue({ ad_sync_domain: 'corp.local', ad_sync_bind_dn: 'CN=svc', ad_sync_interval_min: '30', ad_sync_auto_create_depts: 'true', ad_sync_proxy_as_aliases: 'false' });
		api.adSet.mockResolvedValue({}); api.adTest.mockResolvedValue({}); api.adSync.mockResolvedValue({});
		api.adHealth.mockResolvedValue(health);
		api.conflicts.mockResolvedValue([{ id: 8, email: 'alice@example.test', field: 'display_name', localValue: 'Alice', remoteValue: 'Alicia' }]);
		api.resolve.mockResolvedValue({}); api.resolveAll.mockResolvedValue({});
		api.getMappings.mockResolvedValue({ saml: { corp: [{ idp_group: 'Engineering', distribution_group_id: 2, admin_role: null, department_id: 4 }] }, oidc: {} });
		api.updateMappings.mockResolvedValue({});
		api.ldapConfig.mockResolvedValue({ ldap_sync_host: 'ldap.corp.local', ldap_sync_port: '636', ldap_sync_tls: 'true', ldap_sync_bind_dn: 'cn=svc', ldap_sync_base_dn: 'dc=corp,dc=local', ldap_sync_user_filter: '(objectClass=person)', ldap_sync_interval_min: '15', ldap_sync_auto_create_depts: 'true', ldap_sync_enabled: 'false' });
		api.ldapSet.mockResolvedValue({}); api.ldapTest.mockResolvedValue({ checked: 12 });
		api.ldapPreview.mockResolvedValue({ total: 2, rows: [
			{ email: 'new@example.test', displayName: 'New User', action: 'create', reason: null },
			{ email: 'old@example.test', displayName: 'Old User', action: 'disable', reason: 'missing' }
		] });
		api.ldapSync.mockResolvedValue({}); api.ldapHealth.mockResolvedValue(health);
		api.ldapLog.mockResolvedValue([{ syncedAt: '2026-07-20T01:02:03Z', checked: 10, created: 2, updated: 3, disabled: 1, skipped: 4, errors: 0 }]);
		api.identitySources.mockResolvedValue([{ sourceKey: 'legacy:ad', displayName: 'Corporate AD', kind: 'ad', state: 'active', generation: '3', capabilities: {}, attentionCount: 0 }]);
		api.identityPeople.mockResolvedValue([{ userId: '42', email: 'alice@example.test', displayName: 'Alice', enabled: true, lifecycleAuthority: 'source', sourceKey: 'legacy:ad', activeLinks: 2, detachedLinks: 0 }]);
		api.identityConflicts.mockResolvedValue([{ id: '00000000-0000-0000-0000-000000000001', sourceKey: 'legacy:ad', evidenceClass: 'conflict', state: 'pending', generation: '1', explanation: 'Anchor collision requires proof' }]);
		api.identityTransitions.mockResolvedValue([{ id: '00000000-0000-0000-0000-000000000002', userId: '42', kind: 'directory_to_local', state: 'completed', sourceKey: 'legacy:ad', protected: false, pendingEffects: 0 }]);
		api.identityEvents.mockResolvedValue([{ id: '9', occurredAt: '2026-07-25T00:00:00Z', action: 'authority_changed', reason: 'approved migration', correlationId: '00000000-0000-0000-0000-000000000003' }]);
		const sourceDocument = {
			apiVersion: 'setjoin.io/v1',
			kind: 'IdentitySource',
			metadata: { sourceKey: 'legacy:ad', displayName: 'Corporate AD' },
			spec: { type: 'ad', capabilities: ['immutableSubject'] },
		};
		const sourceDetail = {
			sourceKey: 'legacy:ad',
			displayName: 'Corporate AD',
			kind: 'ad',
			state: 'active',
			generation: '3',
			mappingVersion: '7',
			capabilities: { immutableSubject: true },
			lastSuccessAt: '2026-07-25T00:00:00Z',
			lastFailureAt: 'not-a-date',
			lastErrorCode: 'LDAP_TIMEOUT',
			document: sourceDocument,
			secretConfigured: { bindPassword: true },
		};
		api.identitySourceDetail.mockResolvedValue(sourceDetail);
		api.identitySourcePlan.mockResolvedValue({
			sourceKey: 'corp-ldap',
			create: true,
			changed: true,
			desired: sourceDocument,
			operations: ['create draft', 'validate mapping'],
		});
		api.identitySourceApply.mockResolvedValue({ sourceKey: 'corp-ldap', generation: '1' });
		api.identitySourceDryRun.mockResolvedValue({ generation: '3', valid: true, personWrites: 12 });
		api.identitySourceActivate.mockResolvedValue({ generation: '4', state: 'active' });
		api.identitySourcePause.mockResolvedValue({ generation: '4', state: 'paused' });
		api.identitySourceResume.mockResolvedValue({ generation: '4', state: 'active' });
		api.identitySourceRetire.mockResolvedValue({ generation: '4', state: 'retired' });
		api.identitySourceSecret.mockResolvedValue({ generation: '4', secretConfigured: { bindPassword: true } });
		api.identityPersonDetail.mockResolvedValue({
			userId: '42',
			email: 'alice@example.test',
			displayName: 'Alice',
			enabled: true,
			relationship: 'member',
			protected: true,
			lifecycleAuthority: {
				kind: 'source',
				generation: '5',
				linkId: 'link-1',
				sourceKey: 'legacy:ad',
			},
			recovery: {
				hasLocalPassword: true,
				passkeyCount: 2,
				activeAuthenticationLinks: 1,
			},
			links: [{
				id: 'link-1',
				sourceKey: 'legacy:ad',
				sourceKind: 'ad',
				purposes: ['authentication', 'lifecycle'],
				state: 'active',
				generation: '5',
				linkMethod: 'immutable_subject',
				subjectFingerprint: 'sha256:subject',
				firstSeenAt: '2026-07-20T00:00:00Z',
				lastSeenAt: '2026-07-25T00:00:00Z',
			}],
			fieldAuthority: [{
				field: 'display_name',
				authorityKind: 'source',
				sourceKey: 'legacy:ad',
				linkId: 'link-1',
				generation: '5',
				localOverrideState: 'none',
			}],
			entitlementProvenance: [{
				id: 'grant-1',
				targetKind: 'person',
				targetId: '42',
				entitlementKind: 'group',
				entitlementId: 'engineering',
				provenanceKind: 'source',
				sourceKey: 'legacy:ad',
				linkId: 'link-1',
				sourceGeneration: '5',
			}],
			transitionHistory: [{
				id: 'transition-old',
				kind: 'directory_to_local',
				state: 'completed',
				protected: false,
				generation: '2',
				createdAt: '2026-07-20T00:00:00Z',
				updatedAt: '2026-07-21T00:00:00Z',
				completedAt: '2026-07-21T00:00:00Z',
			}],
			linkHistory: [{
				id: 'event-link',
				occurredAt: '2026-07-25T00:00:00Z',
				action: 'linked',
				sourceKey: 'legacy:ad',
				linkId: 'link-1',
				reason: 'immutable subject verified',
				correlationId: 'corr-link',
			}],
		});
		api.identityConflictDetail.mockResolvedValue({
			id: '00000000-0000-0000-0000-000000000001',
			source: {
				sourceKey: 'legacy:ad',
				displayName: 'Corporate AD',
				kind: 'ad',
				state: 'active',
				generation: '3',
			},
			subjectFingerprint: 'sha256:subject',
			evidenceClass: 'soft',
			evidenceDigest: 'sha256:evidence',
			explanation: 'Email is review evidence, not durable linking proof',
			state: 'pending',
			generation: '1',
			createdAt: '2026-07-25T00:00:00Z',
			expiresAt: '2026-07-26T00:00:00Z',
			candidatePerson: {
				userId: '42',
				email: 'alice@example.test',
				displayName: 'Alice',
				enabled: true,
				protected: true,
			},
			allowedDecisions: ['link', 'create', 'reject', 'defer'],
			decisionHistory: [{
				id: 'decision-1',
				decision: 'defer',
				reason: 'await immutable evidence',
				decidedBy: '7',
				occurredAt: '2026-07-25T00:00:00Z',
			}],
		});
		api.identityConflictDecide.mockResolvedValue({
			decision: 'defer',
			status: 'decided',
			generation: '2',
		});
		const preview = {
			transitionId: '00000000-0000-0000-0000-000000000004',
			state: 'previewed', transitionGeneration: '2', previewDigest: 'a'.repeat(64),
			previewExpiresAt: '2026-07-25T12:05:00Z', protected: false,
			recoveryReady: true, sourceGeneration: '3', linkGeneration: '2',
			lifecycleGeneration: '1', replayed: false,
		};
		const detail = {
			transitionId: preview.transitionId, correlationId: 'corr', personId: '42',
			type: 'directory_to_local', state: 'authorized', transitionGeneration: '3',
			previewVersion: '1', previewDigest: preview.previewDigest,
			previewExpiresAt: preview.previewExpiresAt, protected: false,
			requestedBy: '7', requestedAt: '2026-07-25T00:00:00Z',
			approvalRequestId: '17', approvedBy: '8',
			rollback: { boundary: 'not_committed' },
			steps: [{
				ordinal: 1, stage: 'commit_authority', state: 'completed',
				attemptCount: 1, errorCode: null,
			}],
			effects: [{
				effectId: 'effect-1', kind: 'revoke_sessions', state: 'failed',
				attemptCount: 2, nextAttemptAt: '2026-07-25T12:10:00Z',
				lastErrorCode: 'LIVEKIT_UNAVAILABLE',
			}, {
				effectId: 'effect-2', kind: 'refresh_entitlements', state: 'completed',
				attemptCount: 1, nextAttemptAt: '2026-07-25T12:10:00Z',
			}],
		};
		api.identityPreview.mockResolvedValue(preview);
		api.identityDetail.mockResolvedValue(detail);
		api.identityChallenge.mockResolvedValue({
			challengeId: 'challenge-id', transitionId: preview.transitionId,
			transitionGeneration: '2', previewDigest: preview.previewDigest,
			expiresAt: preview.previewExpiresAt, handoffMethod: 'browser',
			displayCode: 'ABC12345', completed: false, invalidated: false,
		});
		api.identityChallengeComplete.mockResolvedValue({
			challengeId: 'challenge-id', elevationId: 'elevation-id',
			transitionId: preview.transitionId, transitionGeneration: '2',
			expiresAt: preview.previewExpiresAt, consumed: false,
			invalidated: false, replayed: false,
		});
		api.identityRequest.mockResolvedValue(detail);
		api.identityApprove.mockResolvedValue({ ...detail, state: 'authorized' });
		api.identityDeny.mockResolvedValue({ ...detail, state: 'cancelled' });
		api.identityExecute.mockResolvedValue({ ...detail, state: 'effects_pending' });
		api.identityCancel.mockResolvedValue({ ...detail, state: 'cancelled' });
		api.identityRetry.mockResolvedValue({ ...detail, state: 'effects_pending' });
		api.identityRollbackPreview.mockResolvedValue({
			...detail,
			state: 'failed_recoverable',
			rollback: {
				boundary: 'effects_pending',
				previewDigest: 'b'.repeat(64),
				approvalRequestId: '23',
			},
		});
		api.identityRollback.mockResolvedValue({ ...detail, state: 'rolled_back' });
		api.identityReport.mockResolvedValue(new Blob(['{}'], { type: 'application/json' }));
		api.identityUpgradeStatus.mockResolvedValue({
			schemaVersion: 164,
			requiredSchemaVersion: 164,
			schemaReady: true,
			masterEnabled: false,
			normalizedReadsEnabled: false,
			transitionsEnabled: false,
			sources: { shadow: 1, canary: 0, normalized: 0 },
			blockers: {
				pendingConflicts: 1,
				criticalDivergences: 0,
				unresolvedTransitions: 0,
				pendingEffects: 0,
				failedEffects: 0,
			},
		});
		api.auditPolicy.mockResolvedValue({ reasonRequiredAreas: [] });
	});

	afterEach(() => resetStores());

	it('loads and toggles an authentication method', async () => {
		const { container } = await renderPage();
		expect(screen.getByText('Password')).toBeInTheDocument();
		const toggle = container.querySelector('input[type="checkbox"]') as HTMLInputElement;
		await waitFor(() => expect(toggle).toBeEnabled());
		await fireEvent.click(toggle);
		await waitFor(() => expect(api.authUpdate).toHaveBeenCalledWith('password', { enabled: false, priority: 10 }));
	});

	it('saves, tests, syncs, and resolves AD configuration conflicts', async () => {
		await renderPage();
		await fireEvent.click(screen.getByRole('tab', { name: 'Active directory' }));
		expect(screen.getByDisplayValue('corp.local')).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Save config' }));
		await waitFor(() => expect(api.adSet).toHaveBeenCalledWith(expect.objectContaining({ ad_sync_domain: 'corp.local', ad_sync_interval_min: '30' })));
		await fireEvent.click(screen.getByRole('button', { name: 'Test connection' }));
		await waitFor(() => expect(screen.getByText('Connected successfully')).toBeInTheDocument());
		await fireEvent.click(screen.getByRole('button', { name: 'Sync now' }));
		await waitFor(() => expect(api.adSync).toHaveBeenCalled());
		await fireEvent.click(screen.getByRole('button', { name: /pending conflicts/ }));
		expect(screen.getByText('alice@example.test')).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Accept AD' }));
		await waitFor(() => expect(api.resolve).toHaveBeenCalledWith(8, 'accept_remote'));
		await fireEvent.click(screen.getByRole('button', { name: 'Keep all local' }));
		await waitFor(() => expect(api.resolveAll).toHaveBeenCalledWith('keep_local'));
		await fireEvent.click(screen.getByRole('button', { name: /Attribute mapping/ }));
		expect(screen.getByText('userPrincipalName')).toBeInTheDocument();
	});

	it('edits and persists SAML group mappings', async () => {
		await renderPage();
		await fireEvent.click(screen.getByRole('tab', { name: 'Groups' }));
		await fireEvent.change(screen.getByLabelText('Provider'), { target: { value: 'corp' } });
		expect(screen.getByDisplayValue('Engineering')).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Add mapping' }));
		expect(screen.getAllByPlaceholderText('e.g. Engineering')).toHaveLength(2);
		await fireEvent.click(screen.getAllByRole('button', { name: 'Remove' }).at(-1)!);
		await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
		await waitFor(() => expect(api.updateMappings).toHaveBeenCalledWith('saml', 'corp', expect.arrayContaining([expect.objectContaining({ idp_group: 'Engineering' })]), undefined));
	});

	it('previews, tests, syncs, and explicitly confirms LDAP enablement', async () => {
		const { container } = await renderPage();
		await fireEvent.click(screen.getByRole('tab', { name: 'Custom LDAP' }));
		expect(screen.getByDisplayValue('ldap.corp.local')).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Test connection' }));
		await waitFor(() => expect(screen.getByText('12 found')).toBeInTheDocument());
		await fireEvent.click(screen.getByRole('button', { name: 'Preview' }));
		await waitFor(() => expect(screen.getByText('new@example.test')).toBeInTheDocument());
		expect(screen.getByText('old@example.test')).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Sync now' }));
		await waitFor(() => expect(api.ldapSync).toHaveBeenCalled());
		const enable = [...container.querySelectorAll('input[type="checkbox"]')].at(-1) as HTMLInputElement;
		await fireEvent.click(enable);
		expect(screen.getByRole('dialog')).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Enable sync' }));
		await waitFor(() => expect(api.ldapSet).toHaveBeenCalledWith(expect.objectContaining({ ldap_sync_enabled: 'true', ldap_sync_host: 'ldap.corp.local' })));
	});

	it('shows normalized identity evidence and requires two one-use step-ups', async () => {
		await renderIdentityConsole();
		expect(await screen.findByText(/alice@example\.test/)).toBeInTheDocument();
		expect(document.body).toHaveTextContent('1 / 1');
		expect(document.body).toHaveTextContent('Anchor collision requires proof');
		expect(document.body).toHaveTextContent('approved migration');

		expect(screen.getByRole('button', { name: 'Preview' })).toBeDisabled();
		await fireEvent.input(screen.getByLabelText('User ID'), { target: { value: '42' } });
		await fireEvent.input(screen.getByLabelText('Audited reason'), { target: { value: 'Approved directory retirement' } });
		expect(screen.getByRole('button', { name: 'Preview' })).toBeEnabled();
		await fireEvent.click(screen.getByRole('button', { name: 'Preview' }));
		await waitFor(() => expect(api.identityPreview).toHaveBeenCalledWith(
			'42', 'Approved directory retirement', expect.any(String), undefined
		));
		expect(screen.getByText('ready')).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Authorize exact preview' }));
		await waitFor(() => expect(api.identityChallenge).toHaveBeenCalledWith(
			expect.objectContaining({ previewDigest: 'a'.repeat(64) }),
			expect.any(String),
		));
		expect(screen.getByText('ABC12345')).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'I completed MFA' }));
		await waitFor(() => expect(api.identityRequest).toHaveBeenCalledWith(
			expect.objectContaining({ previewDigest: 'a'.repeat(64) }),
			'elevation-id',
			'Approved directory retirement',
			expect.any(String),
		));
		await fireEvent.click(screen.getByRole('button', {
			name: 'Complete final step-up and execute',
		}));
		await waitFor(() => expect(api.identityChallenge).toHaveBeenCalledTimes(2));
		await fireEvent.click(screen.getByRole('button', { name: 'I completed MFA' }));
		await waitFor(() => expect(api.identityExecute).toHaveBeenCalledWith(
			expect.objectContaining({ previewDigest: 'a'.repeat(64) }),
			'elevation-id',
			'Approved directory retirement',
			expect.any(String),
			'17'
		));
	});

	it('binds a source-to-source preview to the exact target provisioning link', async () => {
		await renderIdentityConsole();
		await screen.findByText(/alice@example\.test/);
		await fireEvent.input(screen.getByLabelText('User ID'), { target: { value: '42' } });
		await fireEvent.input(screen.getByLabelText('Target provisioning link ID (optional)'), {
			target: { value: 'link-target-9' },
		});
		await fireEvent.input(screen.getByLabelText('Audited reason'), {
			target: { value: 'Move lifecycle authority to the verified SCIM source' },
		});
		await fireEvent.click(screen.getByRole('button', { name: 'Preview' }));
		await waitFor(() => expect(api.identityPreview).toHaveBeenCalledWith(
			'42',
			'Move lifecycle authority to the verified SCIM source',
			expect.any(String),
			'link-target-9',
		));
	});

	it('surfaces a primary load failure and keeps optional integrations non-fatal', async () => {
		api.authList.mockRejectedValueOnce(new Error('identity unavailable'));
		api.adConfig.mockRejectedValueOnce(new Error('not configured'));
		api.ldapConfig.mockRejectedValueOnce(new Error('not configured'));
		await renderPage();
		expect(screen.getByText('identity unavailable')).toBeInTheDocument();
	});

	it('preserves successful overview sections when one inventory fails and retries only that section', async () => {
		api.identityPeople.mockRejectedValue(new Error(
			'identity transition preflight failed — BZ234 · enroll recovery and re-preview'
		));
		await renderIdentityConsole();
		expect(await screen.findByRole('alert')).toHaveTextContent('BZ234');
		expect(document.body).toHaveTextContent('1 / 1');
		expect(document.body).toHaveTextContent('Anchor collision requires proof');
		expect(document.body).toHaveTextContent('approved migration');
		expect(screen.queryByText(/alice@example\.test/)).not.toBeInTheDocument();
		api.identityPeople.mockResolvedValue([{ userId: '42', email: 'alice@example.test', displayName: 'Alice', enabled: true, lifecycleAuthority: 'source', sourceKey: 'legacy:ad', activeLinks: 2, detachedLinks: 0 }]);
		await fireEvent.click(screen.getByRole('button', { name: 'Retry people' }));
		await waitFor(() => expect(api.identityPeople).toHaveBeenCalledTimes(2));
		expect(screen.queryByRole('button', { name: 'Retry people' })).not.toBeInTheDocument();
		expect(screen.getByText(/alice@example\.test/)).toBeInTheDocument();
	});

	it('plans and applies a source document without activating it', async () => {
		await renderIdentityConsole({ initialSection: 'sources', sourceSetup: true });
		const plan = await screen.findByRole('button', { name: 'Plan source' });
		await waitFor(() => expect(plan).toBeEnabled());
		await fireEvent.click(plan);
		await waitFor(() => expect(api.identitySourcePlan).toHaveBeenCalledWith(
			expect.objectContaining({
				apiVersion: 'setjoin.io/v1',
				kind: 'IdentitySource',
			})
		));
		expect(screen.getByText('Create draft')).toBeInTheDocument();
		expect(screen.getByText(/create draft, validate mapping/)).toBeInTheDocument();
		await fireEvent.input(screen.getByLabelText('Audited reason'), {
			target: { value: 'Add the approved corporate directory' },
		});
		await fireEvent.click(screen.getByRole('button', { name: 'Save draft' }));
		await waitFor(() => expect(api.identitySourceApply).toHaveBeenCalledWith(
			expect.objectContaining({ kind: 'IdentitySource' }),
			'Add the approved corporate directory',
			expect.any(String),
			undefined,
		));
		expect(api.identitySourceActivate).not.toHaveBeenCalled();
	});

	it('operates an active source with generation-fenced dry run, secret rotation, pause, and retire', async () => {
		await renderIdentityConsole({ initialSection: 'sources', selectedId: 'legacy:ad' });
		expect(await screen.findByText('LDAP_TIMEOUT')).toBeInTheDocument();
		expect(screen.getByText('configured')).toBeInTheDocument();
		await fireEvent.input(screen.getByLabelText('Audited reason'), {
			target: { value: 'Operator-approved source maintenance' },
		});
		await fireEvent.input(screen.getByLabelText('bindPassword value'), {
			target: { value: 'replacement-secret' },
		});
		await fireEvent.click(screen.getByRole('button', { name: 'Rotate secret' }));
		await waitFor(() => expect(api.identitySourceSecret).toHaveBeenCalledWith(
			'legacy:ad',
			'bindPassword',
			'replacement-secret',
			'3',
			'Operator-approved source maintenance',
			expect.any(String),
			true,
		));
		await fireEvent.click(screen.getByRole('button', { name: 'Run dry run' }));
		await waitFor(() => expect(api.identitySourceDryRun).toHaveBeenCalledWith(
			'legacy:ad', '3', 'Operator-approved source maintenance', expect.any(String)
		));
		await fireEvent.click(screen.getByRole('button', { name: 'Pause' }));
		await waitFor(() => expect(api.identitySourcePause).toHaveBeenCalled());
		await fireEvent.click(screen.getByRole('button', { name: 'Retire permanently' }));
		await waitFor(() => expect(api.identitySourceRetire).toHaveBeenCalled());
	});

	it('exposes only the source lifecycle action valid for draft and paused states', async () => {
		const source = await api.identitySourceDetail('fixture');
		api.identitySourceDetail.mockClear();
		api.identitySourceDetail.mockResolvedValue({ ...source, state: 'draft', secretConfigured: {} });
		const draft = await renderIdentityConsole({ initialSection: 'sources', selectedId: 'legacy:ad' });
		expect(await screen.findByRole('button', { name: 'Activate' })).toBeInTheDocument();
		await fireEvent.input(screen.getByLabelText('Audited reason'), {
			target: { value: 'Validated source activation' },
		});
		await fireEvent.click(screen.getByRole('button', { name: 'Activate' }));
		await waitFor(() => expect(api.identitySourceActivate).toHaveBeenCalled());
		draft.unmount();

		api.identitySourceDetail.mockResolvedValue({ ...source, state: 'paused' });
		await renderIdentityConsole({ initialSection: 'sources', selectedId: 'legacy:ad' });
		expect(await screen.findByRole('button', { name: 'Resume' })).toBeInTheDocument();
		await fireEvent.input(screen.getByLabelText('Audited reason'), {
			target: { value: 'Resume after successful repair' },
		});
		await fireEvent.click(screen.getByRole('button', { name: 'Resume' }));
		await waitFor(() => expect(api.identitySourceResume).toHaveBeenCalled());
	});

	it('renders person authority, recovery, link, grant, and history evidence', async () => {
		await renderIdentityConsole({ initialSection: 'people', selectedId: '42' });
		expect(await screen.findByText('Lifecycle and recovery')).toBeInTheDocument();
		expect(screen.getByText('protected')).toBeInTheDocument();
		expect(screen.getByText('sha256:subject')).toBeInTheDocument();
		expect(screen.getByText('display_name')).toBeInTheDocument();
		expect(screen.getByText('group engineering')).toBeInTheDocument();
		expect(screen.getByText('directory_to_local')).toBeInTheDocument();
		expect(screen.getByText('immutable subject verified')).toBeInTheDocument();
	});

	it('records each conflict disposition with exact evidence and candidate fencing', async () => {
		await renderIdentityConsole({
			initialSection: 'conflicts',
			selectedId: '00000000-0000-0000-0000-000000000001',
		});
		expect(await screen.findByText(/Direct linking is prohibited/)).toBeInTheDocument();
		expect(screen.getByText(/never linking proof/)).toBeInTheDocument();
		expect(screen.getByText('await immutable evidence')).toBeInTheDocument();
		await fireEvent.input(screen.getByLabelText('Audited reason'), {
			target: { value: 'Evidence reviewed by directory operator' },
		});
		for (const name of [
			'Link evidenced person',
			'Create new person',
			'Reject candidate',
			'Defer review',
		]) {
			await fireEvent.click(screen.getByRole('button', { name }));
		}
		await waitFor(() => expect(api.identityConflictDecide).toHaveBeenCalledTimes(4));
		expect(api.identityConflictDecide).toHaveBeenNthCalledWith(
			1,
			expect.objectContaining({ evidenceDigest: 'sha256:evidence' }),
			'link',
			'Evidence reviewed by directory operator',
			expect.any(String),
			'42',
		);
		expect(api.identityConflictDecide).toHaveBeenNthCalledWith(
			4,
			expect.any(Object),
			'defer',
			'Evidence reviewed by directory operator',
			expect.any(String),
			undefined,
		);
	});

	it('recovers exact failed transition effects and downloads a sanitized report', async () => {
		const createObjectURL = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:transition');
		const revokeObjectURL = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {});
		await renderIdentityConsole({
			initialSection: 'transitions',
			selectedId: '00000000-0000-0000-0000-000000000004',
		});
		expect(await screen.findByText('LIVEKIT_UNAVAILABLE')).toBeInTheDocument();
		expect(screen.getByText('Worker-owned')).toBeInTheDocument();
		await fireEvent.input(screen.getByLabelText('Audited reason'), {
			target: { value: 'Recover the exact durable side effect' },
		});
		const retry = screen.getByRole('button', { name: 'Retry this effect' });
		await waitFor(() => expect(retry).toBeEnabled());
		await fireEvent.click(retry);
		await waitFor(() => expect(api.identityRetry).toHaveBeenCalledWith(
			expect.objectContaining({ transitionId: expect.any(String) }),
			'effect-1',
			'Recover the exact durable side effect',
			expect.any(String),
		));
		await fireEvent.click(screen.getByRole('button', { name: 'Download sanitized report' }));
		await waitFor(() => expect(api.identityReport).toHaveBeenCalled());
		expect(createObjectURL).toHaveBeenCalled();
		expect(revokeObjectURL).toHaveBeenCalledWith('blob:transition');
	});

	it('cancels an authorized transition before its durable commit boundary', async () => {
		await renderIdentityConsole({
			initialSection: 'transitions',
			selectedId: '00000000-0000-0000-0000-000000000004',
		});
		await fireEvent.input(await screen.findByLabelText('Audited reason'), {
			target: { value: 'Stop before any authority commit' },
		});
		const cancel = screen.getByRole('button', { name: 'Cancel pre-commit transition' });
		await waitFor(() => expect(cancel).toBeEnabled());
		await fireEvent.click(cancel);
		await waitFor(() => expect(api.identityCancel).toHaveBeenCalledWith(
			expect.objectContaining({ state: 'authorized' }),
			'Stop before any authority commit',
			expect.any(String),
		));
	});

	it('previews rollback and rejects a rollback step-up without an independent approval ID', async () => {
		const detail = await api.identityDetail('fixture');
		api.identityDetail.mockClear();
		api.identityDetail.mockResolvedValue({
			...detail,
			state: 'failed_recoverable',
			rollback: { boundary: 'effects_pending' },
		});
		await renderIdentityConsole({ initialSection: 'transitions', selectedId: detail.transitionId });
		await fireEvent.input(await screen.findByLabelText('Audited reason'), {
			target: { value: 'Return to the last durable authority boundary' },
		});
		await fireEvent.click(screen.getByRole('button', { name: 'Preview rollback boundary' }));
		await waitFor(() => expect(api.identityRollbackPreview).toHaveBeenCalled());
		expect(await screen.findByLabelText('Rollback approval request ID')).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Step up for approved rollback' }));
		await fireEvent.click(await screen.findByRole('button', { name: 'I completed MFA' }));
		await waitFor(() => expect(api.identityRollback).toHaveBeenCalledWith(
			expect.any(Object),
			'elevation-id',
			'Return to the last durable authority boundary',
			expect.any(String),
			'23',
		));
	});

	it('approves and denies awaiting transitions only after fresh digest-bound step-up', async () => {
		const detail = await api.identityDetail('fixture');
		api.identityDetail.mockClear();
		api.identityDetail.mockResolvedValue({ ...detail, state: 'awaiting_approval' });
		await renderIdentityConsole({ initialSection: 'transitions', selectedId: detail.transitionId });
		await fireEvent.input(await screen.findByLabelText('Audited reason'), {
			target: { value: 'Independent protected-account review' },
		});
		await fireEvent.click(screen.getByRole('button', { name: 'Step up and approve' }));
		expect(await screen.findByText(/requester cannot review/)).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'I completed MFA' }));
		await waitFor(() => expect(api.identityApprove).toHaveBeenCalled());

		api.identityDetail.mockResolvedValue({ ...detail, state: 'awaiting_approval' });
		await fireEvent.click(screen.getByRole('button', { name: 'Step up and deny' }));
		await fireEvent.click(await screen.findByRole('button', { name: 'I completed MFA' }));
		await waitFor(() => expect(api.identityDeny).toHaveBeenCalled());
	});

	it('filters and exports redacted audit events with spreadsheet-formula neutralization', async () => {
		api.identityEvents.mockResolvedValue([{
			id: '9',
			occurredAt: '2026-07-25T00:00:00Z',
			userId: '42',
			sourceKey: 'legacy:ad',
			transitionId: 'transition-1',
			action: '=authority_changed',
			reason: '+approved migration',
			correlationId: 'correlation-1',
			metadata: { actorUserId: 7 },
		}, {
			id: '10',
			occurredAt: '2026-07-20T00:00:00Z',
			action: 'linked',
			reason: 'immutable proof',
			correlationId: 'correlation-2',
		}]);
		const createObjectURL = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:audit');
		const revokeObjectURL = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {});
		const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
		await renderIdentityConsole({ initialSection: 'audit' });
		expect(await screen.findByText('2 of 2 loaded events match the current filters.')).toBeInTheDocument();
		await fireEvent.input(screen.getByLabelText('Person ID'), { target: { value: '42' } });
		await fireEvent.input(screen.getByLabelText('Source key'), { target: { value: 'legacy' } });
		await fireEvent.input(screen.getByLabelText('Transition ID'), { target: { value: 'transition' } });
		await fireEvent.input(screen.getByLabelText('Actor ID'), { target: { value: '7' } });
		await fireEvent.input(screen.getByLabelText('Outcome'), { target: { value: 'authority' } });
		await fireEvent.input(screen.getByLabelText('From date'), { target: { value: '2026-07-24' } });
		await fireEvent.input(screen.getByLabelText('To date'), { target: { value: '2026-07-26' } });
		expect(await screen.findByText('1 of 2 loaded events match the current filters.')).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Export redacted CSV' }));
		expect(createObjectURL).toHaveBeenCalled();
		expect(click).toHaveBeenCalled();
		expect(revokeObjectURL).toHaveBeenCalledWith('blob:audit');
	});

	it('supports keyboard navigation across identity section tabs', async () => {
		await renderIdentityConsole({ initialSection: 'sources' });
		const tabs = await screen.findAllByRole('tab');
		await fireEvent.keyDown(tabs[1], { key: 'ArrowRight' });
		expect(tabs[2]).toHaveFocus();
		await fireEvent.keyDown(tabs[2], { key: 'ArrowLeft' });
		expect(tabs[1]).toHaveFocus();
		await fireEvent.keyDown(tabs[1], { key: 'End' });
		expect(tabs.at(-1)).toHaveFocus();
		await fireEvent.keyDown(tabs.at(-1)!, { key: 'Home' });
		expect(tabs[0]).toHaveFocus();
	});
});
