import { describe, expect, it } from 'vitest';
import {
	decodeOfficeAdminState,
	decodeOfficeAppOperationAccepted,
	decodeOfficeAppsState,
	isOfficeAppOperationTerminal
} from './office';

const operation = {
	operationId: '11111111-1111-4111-8111-111111111111',
	kind: 'install',
	state: 'pulling',
	stateGeneration: 3,
	phase: 'pulling',
	progress: { step: 2, steps: 7 },
	error: null,
	providerId: 'collabora',
	allowedActions: [],
	recovery: null,
	createdAt: '2026-08-25T00:00:00Z',
	updatedAt: '2026-08-25T00:01:00Z'
};

const provider = {
	providerId: 'collabora',
	enabled: false,
	draining: false,
	generation: 2,
	routeState: 'connected_inactive',
	configSha256: 'a'.repeat(64),
	activeQualificationId: null,
	allowedClassifications: ['regular'],
	allowedPlatforms: ['web'],
	allowedFileFamilies: ['word'],
	entitlementState: 'unknown',
	entitlementRef: null,
	buildId: '25.04',
	proofDiscoveryUrl: 'https://office.test/hosting/discovery',
	wopiPublicBaseUrl: 'https://setjoin.test',
	editorUrl: 'https://office.test/browser/editor.html',
	removedAt: null,
	updatedAt: '2026-08-25T00:00:00Z'
};

describe('Office admin wire decoders', () => {
	it('decodes the complete Office and application projections', () => {
		const {
			providerId: _providerId,
			allowedActions: _allowedActions,
			recovery: _recovery,
			...officeOperation
		} = operation;
		expect(decodeOfficeAdminState({
			providers: [provider],
			qualifications: [],
			health: [],
			operations: [{ ...officeOperation, appId: 'collabora-code' }],
			features: {
				driveHistory: true,
				officeEditing: false,
				officeLocalOpen: false,
				officeManagedDelivery: true
			}
		}).providers[0].providerId).toBe('collabora');

		const apps = decodeOfficeAppsState({
			app: {
				appId: 'collabora-code',
				name: 'Collabora CODE',
				channel: 'test',
				managedDeliveryEnabled: true,
				allowedActions: ['install'],
				providerReadiness: {
					providerId: 'collabora', generation: 2, ready: true,
					state: 'connected_inactive', remedy: 'ready'
				}
			},
			revisions: [],
			operations: [operation]
		});
		expect(apps.app.allowedActions).toEqual(['install']);
		expect(apps.app.providerReadiness?.generation).toBe(2);
	});

	it('fails closed on missing fields, unknown actions, and malformed nested records', () => {
		const base = {
			app: {
				appId: 'collabora-code', name: 'Collabora CODE', channel: 'test',
				managedDeliveryEnabled: true, allowedActions: ['install'], providerReadiness: null
			},
			revisions: [], operations: []
		};
		expect(() => decodeOfficeAppsState({ ...base, app: { ...base.app, allowedActions: ['execute-shell'] } }))
			.toThrow('invalid Office applications response');
		expect(() => decodeOfficeAppsState({ ...base, operations: [{ ...operation, recovery: { problem: 'x' } }] }))
			.toThrow('invalid Office applications response');
		expect(() => decodeOfficeAdminState({ providers: [], qualifications: [], health: [], operations: [] }))
			.toThrow('invalid Office admin response');
	});

	it('decodes accepted operations and centralizes terminal-state knowledge', () => {
		expect(decodeOfficeAppOperationAccepted({
			operationId: operation.operationId,
			state: 'requested',
			stateGeneration: 1,
			phase: 'requested',
			replayed: false
		}).state).toBe('requested');
		expect(isOfficeAppOperationTerminal('failed_terminal')).toBe(true);
		expect(isOfficeAppOperationTerminal('paused_recoverable')).toBe(false);
	});
});
