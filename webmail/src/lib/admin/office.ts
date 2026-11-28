export type OfficeEntitlementState =
	| 'unknown'
	| 'evaluation'
	| 'valid'
	| 'expiring'
	| 'expired'
	| 'build_mismatch'
	| 'not_permitted';

export type OfficeRouteState =
	| 'disconnected'
	| 'connected_inactive'
	| 'active_for_scope'
	| 'draining'
	| 'fenced';

export type OfficeAppAction =
	| 'install'
	| 'update'
	| 'rollback'
	| 'disable'
	| 'uninstall'
	| 'recover'
	| 'resume'
	| 'retry'
	| 'cancel';

export type OfficeAppOperationState =
	| 'requested'
	| 'claimed'
	| 'preflight'
	| 'pulling'
	| 'verifying'
	| 'staging'
	| 'starting'
	| 'qualifying'
	| 'connected_inactive'
	| 'disabling_launches'
	| 'draining'
	| 'blocked_drain'
	| 'rolling_back'
	| 'rolled_back'
	| 'retention_pending'
	| 'removed'
	| 'paused_recoverable'
	| 'failed_terminal'
	| 'cancelled';

export interface OfficeProviderPolicy {
	providerId: string;
	enabled: boolean;
	draining: boolean;
	generation: number;
	routeState: OfficeRouteState;
	configSha256: string;
	activeQualificationId: string | null;
	allowedClassifications: string[];
	allowedPlatforms: string[];
	allowedFileFamilies: string[];
	entitlementState: OfficeEntitlementState;
	entitlementRef: string | null;
	buildId: string | null;
	proofDiscoveryUrl: string | null;
	wopiPublicBaseUrl: string | null;
	editorUrl: string | null;
	removedAt: string | null;
	updatedAt: string;
}

export interface OfficeAppRecovery {
	problem: string;
	effect: string;
	remedy: string;
}

export interface OfficeAppOperation {
	operationId: string;
	appId?: string;
	kind: string;
	state: OfficeAppOperationState;
	stateGeneration: number;
	phase: string;
	progress: Record<string, unknown>;
	error: Record<string, unknown> | null;
	providerId?: string;
	allowedActions: OfficeAppAction[];
	recovery: OfficeAppRecovery | null;
	createdAt: string;
	updatedAt: string;
}

export interface OfficeAdminState {
	providers: OfficeProviderPolicy[];
	qualifications: Array<{
		qualificationId: string;
		providerId: string;
		providerGeneration: number;
		configSha256: string;
		status: 'passed' | 'failed' | 'expired';
		profile: string;
		checks: Record<string, string>;
		buildDigest: string | null;
		routeRevision: number;
		createdAt: string;
		expiresAt: string;
	}>;
	health: Array<{
		providerId: string;
		providerGeneration: number;
		state: string;
		capacityState: string;
		facts: Record<string, unknown>;
		observedAt: string;
		expiresAt: string;
	}>;
	operations: OfficeAppOperation[];
	features: {
		driveHistory: boolean;
		officeEditing: boolean;
		officeLocalOpen: boolean;
		officeManagedDelivery: boolean;
	};
}

export interface OfficeProviderReadiness {
	providerId: string;
	generation: number;
	ready: boolean;
	state: string;
	remedy: string | null;
}

export interface OfficeAppsState {
	app: {
		appId: 'collabora-code';
		name: string;
		channel: 'test';
		managedDeliveryEnabled: boolean;
		allowedActions: OfficeAppAction[];
		providerReadiness: OfficeProviderReadiness | null;
	};
	revisions: Array<{
		revisionId: string;
		revision: number;
		providerId: string;
		state: string;
		imageReference: string;
		imageDigest: string;
		artifactReceipt: Record<string, unknown>;
		runtimeConfig: Record<string, unknown>;
		createdAt: string;
		updatedAt: string;
	}>;
	operations: OfficeAppOperation[];
}

export interface OfficeProviderConfigureResult {
	providerId: string;
	generation: number;
	routeState: 'connected_inactive';
	configSha256: string;
	qualified: false;
}

export interface OfficeProviderQualificationResult {
	providerId: string;
	generation: number;
	routeState: 'connected_inactive';
	qualificationId: string;
	expiresAt: string;
	qualified: true;
}

export interface OfficeProviderActivationResult {
	providerId: string;
	generation: number;
	routeState: 'active_for_scope';
	qualificationId: string;
	scope: Record<string, unknown>;
}

export interface OfficeAppOperationAccepted {
	operationId: string;
	state: OfficeAppOperationState;
	stateGeneration: number;
	phase: string;
	replayed: boolean;
}

const routeStates = new Set<OfficeRouteState>([
	'disconnected', 'connected_inactive', 'active_for_scope', 'draining', 'fenced'
]);
const entitlementStates = new Set<OfficeEntitlementState>([
	'unknown', 'evaluation', 'valid', 'expiring', 'expired', 'build_mismatch', 'not_permitted'
]);
const operationStates = new Set<OfficeAppOperationState>([
	'requested', 'claimed', 'preflight', 'pulling', 'verifying', 'staging', 'starting',
	'qualifying', 'connected_inactive', 'disabling_launches', 'draining', 'blocked_drain',
	'rolling_back', 'rolled_back', 'retention_pending', 'removed', 'paused_recoverable',
	'failed_terminal', 'cancelled'
]);
const terminalOperationStates = new Set<OfficeAppOperationState>([
	'connected_inactive', 'rolled_back', 'retention_pending', 'removed', 'failed_terminal', 'cancelled'
]);
const appActions = new Set<OfficeAppAction>([
	'install', 'update', 'rollback', 'disable', 'uninstall', 'recover', 'resume', 'retry', 'cancel'
]);

function invalid(contract: string, path: string): never {
	throw new Error(`invalid ${contract} response at ${path}`);
}

function object(value: unknown, contract: string, path: string): Record<string, unknown> {
	if (typeof value !== 'object' || value === null || Array.isArray(value)) invalid(contract, path);
	return value as Record<string, unknown>;
}

function exact(value: Record<string, unknown>, keys: readonly string[], contract: string, path: string): void {
	const allowed = new Set(keys);
	if (Object.keys(value).some((key) => !allowed.has(key))) invalid(contract, path);
}

function string(value: unknown, contract: string, path: string): string {
	if (typeof value !== 'string' || value.length === 0) invalid(contract, path);
	return value;
}

function nullableString(value: unknown, contract: string, path: string): string | null {
	return value === null ? null : string(value, contract, path);
}

function boolean(value: unknown, contract: string, path: string): boolean {
	if (typeof value !== 'boolean') invalid(contract, path);
	return value;
}

function integer(value: unknown, contract: string, path: string, minimum = 0): number {
	if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum) invalid(contract, path);
	return value;
}

function array<T>(value: unknown, contract: string, path: string, decode: (entry: unknown, path: string) => T): T[] {
	if (!Array.isArray(value)) invalid(contract, path);
	return value.map((entry, index) => decode(entry, `${path}[${index}]`));
}

function stringArray(value: unknown, contract: string, path: string): string[] {
	return array(value, contract, path, (entry, entryPath) => string(entry, contract, entryPath));
}

function record(value: unknown, contract: string, path: string): Record<string, unknown> {
	return object(value, contract, path);
}

function stringRecord(value: unknown, contract: string, path: string): Record<string, string> {
	const raw = object(value, contract, path);
	return Object.fromEntries(Object.entries(raw).map(([key, entry]) => [key, string(entry, contract, `${path}.${key}`)]));
}

function enumValue<T extends string>(value: unknown, values: Set<T>, contract: string, path: string): T {
	const decoded = string(value, contract, path) as T;
	if (!values.has(decoded)) invalid(contract, path);
	return decoded;
}

function decodeActions(value: unknown, contract: string, path: string): OfficeAppAction[] {
	const actions = array(value, contract, path, (entry, entryPath) => enumValue(entry, appActions, contract, entryPath));
	if (new Set(actions).size !== actions.length) invalid(contract, path);
	return actions;
}

function decodeRecovery(value: unknown, contract: string, path: string): OfficeAppRecovery | null {
	if (value === null) return null;
	const raw = object(value, contract, path);
	exact(raw, ['problem', 'effect', 'remedy'], contract, path);
	return {
		problem: string(raw.problem, contract, `${path}.problem`),
		effect: string(raw.effect, contract, `${path}.effect`),
		remedy: string(raw.remedy, contract, `${path}.remedy`)
	};
}

function decodeOperation(
	value: unknown,
	contract: string,
	path: string,
	requireActionProjection = true
): OfficeAppOperation {
	const raw = object(value, contract, path);
	exact(raw, [
		'operationId', 'appId', 'kind', 'state', 'stateGeneration', 'phase', 'progress', 'error',
		'providerId', 'allowedActions', 'recovery', 'createdAt', 'updatedAt'
	], contract, path);
	const hasActionProjection = raw.allowedActions !== undefined || raw.recovery !== undefined;
	if ((raw.allowedActions === undefined) !== (raw.recovery === undefined)) invalid(contract, path);
	if (requireActionProjection && !hasActionProjection) invalid(contract, path);
	const error = raw.error === null ? null : record(raw.error, contract, `${path}.error`);
	return {
		operationId: string(raw.operationId, contract, `${path}.operationId`),
		...(raw.appId === undefined ? {} : { appId: string(raw.appId, contract, `${path}.appId`) }),
		kind: string(raw.kind, contract, `${path}.kind`),
		state: enumValue(raw.state, operationStates, contract, `${path}.state`),
		stateGeneration: integer(raw.stateGeneration, contract, `${path}.stateGeneration`, 1),
		phase: string(raw.phase, contract, `${path}.phase`),
		progress: record(raw.progress, contract, `${path}.progress`),
		error,
		...(raw.providerId === undefined ? {} : { providerId: string(raw.providerId, contract, `${path}.providerId`) }),
		allowedActions: hasActionProjection
			? decodeActions(raw.allowedActions, contract, `${path}.allowedActions`)
			: [],
		recovery: hasActionProjection
			? decodeRecovery(raw.recovery, contract, `${path}.recovery`)
			: null,
		createdAt: string(raw.createdAt, contract, `${path}.createdAt`),
		updatedAt: string(raw.updatedAt, contract, `${path}.updatedAt`)
	};
}

function decodeProvider(value: unknown, path: string): OfficeProviderPolicy {
	const contract = 'Office admin';
	const raw = object(value, contract, path);
	exact(raw, [
		'providerId', 'enabled', 'draining', 'generation', 'routeState', 'configSha256',
		'activeQualificationId', 'allowedClassifications', 'allowedPlatforms', 'allowedFileFamilies',
		'entitlementState', 'entitlementRef', 'buildId', 'proofDiscoveryUrl', 'wopiPublicBaseUrl',
		'editorUrl', 'removedAt', 'updatedAt'
	], contract, path);
	return {
		providerId: string(raw.providerId, contract, `${path}.providerId`),
		enabled: boolean(raw.enabled, contract, `${path}.enabled`),
		draining: boolean(raw.draining, contract, `${path}.draining`),
		generation: integer(raw.generation, contract, `${path}.generation`, 1),
		routeState: enumValue(raw.routeState, routeStates, contract, `${path}.routeState`),
		configSha256: string(raw.configSha256, contract, `${path}.configSha256`),
		activeQualificationId: nullableString(raw.activeQualificationId, contract, `${path}.activeQualificationId`),
		allowedClassifications: stringArray(raw.allowedClassifications, contract, `${path}.allowedClassifications`),
		allowedPlatforms: stringArray(raw.allowedPlatforms, contract, `${path}.allowedPlatforms`),
		allowedFileFamilies: stringArray(raw.allowedFileFamilies, contract, `${path}.allowedFileFamilies`),
		entitlementState: enumValue(raw.entitlementState, entitlementStates, contract, `${path}.entitlementState`),
		entitlementRef: nullableString(raw.entitlementRef, contract, `${path}.entitlementRef`),
		buildId: nullableString(raw.buildId, contract, `${path}.buildId`),
		proofDiscoveryUrl: nullableString(raw.proofDiscoveryUrl, contract, `${path}.proofDiscoveryUrl`),
		wopiPublicBaseUrl: nullableString(raw.wopiPublicBaseUrl, contract, `${path}.wopiPublicBaseUrl`),
		editorUrl: nullableString(raw.editorUrl, contract, `${path}.editorUrl`),
		removedAt: nullableString(raw.removedAt, contract, `${path}.removedAt`),
		updatedAt: string(raw.updatedAt, contract, `${path}.updatedAt`)
	};
}

export function decodeOfficeAdminState(value: unknown): OfficeAdminState {
	const contract = 'Office admin';
	const raw = object(value, contract, '$');
	exact(raw, ['providers', 'qualifications', 'health', 'operations', 'features'], contract, '$');
	const qualifications = array(raw.qualifications, contract, '$.qualifications', (entry, path) => {
		const item = object(entry, contract, path);
		exact(item, [
			'qualificationId', 'providerId', 'providerGeneration', 'configSha256', 'status',
			'profile', 'checks', 'buildDigest', 'routeRevision', 'createdAt', 'expiresAt'
		], contract, path);
		const status = string(item.status, contract, `${path}.status`);
		if (!['passed', 'failed', 'expired'].includes(status)) invalid(contract, `${path}.status`);
		return {
			qualificationId: string(item.qualificationId, contract, `${path}.qualificationId`),
			providerId: string(item.providerId, contract, `${path}.providerId`),
			providerGeneration: integer(item.providerGeneration, contract, `${path}.providerGeneration`, 1),
			configSha256: string(item.configSha256, contract, `${path}.configSha256`),
			status: status as 'passed' | 'failed' | 'expired',
			profile: string(item.profile, contract, `${path}.profile`),
			checks: stringRecord(item.checks, contract, `${path}.checks`),
			buildDigest: nullableString(item.buildDigest, contract, `${path}.buildDigest`),
			routeRevision: integer(item.routeRevision, contract, `${path}.routeRevision`, 1),
			createdAt: string(item.createdAt, contract, `${path}.createdAt`),
			expiresAt: string(item.expiresAt, contract, `${path}.expiresAt`)
		};
	});
	const health = array(raw.health, contract, '$.health', (entry, path) => {
		const item = object(entry, contract, path);
		exact(item, ['providerId', 'providerGeneration', 'state', 'capacityState', 'facts', 'observedAt', 'expiresAt'], contract, path);
		return {
			providerId: string(item.providerId, contract, `${path}.providerId`),
			providerGeneration: integer(item.providerGeneration, contract, `${path}.providerGeneration`, 1),
			state: string(item.state, contract, `${path}.state`),
			capacityState: string(item.capacityState, contract, `${path}.capacityState`),
			facts: record(item.facts, contract, `${path}.facts`),
			observedAt: string(item.observedAt, contract, `${path}.observedAt`),
			expiresAt: string(item.expiresAt, contract, `${path}.expiresAt`)
		};
	});
	const features = object(raw.features, contract, '$.features');
	exact(features, ['driveHistory', 'officeEditing', 'officeLocalOpen', 'officeManagedDelivery'], contract, '$.features');
	return {
		providers: array(raw.providers, contract, '$.providers', decodeProvider),
		qualifications,
		health,
		operations: array(raw.operations, contract, '$.operations', (entry, path) => decodeOperation(entry, contract, path, false)),
		features: {
			driveHistory: boolean(features.driveHistory, contract, '$.features.driveHistory'),
			officeEditing: boolean(features.officeEditing, contract, '$.features.officeEditing'),
			officeLocalOpen: boolean(features.officeLocalOpen, contract, '$.features.officeLocalOpen'),
			officeManagedDelivery: boolean(features.officeManagedDelivery, contract, '$.features.officeManagedDelivery')
		}
	};
}

export function decodeOfficeAppsState(value: unknown): OfficeAppsState {
	const contract = 'Office applications';
	const raw = object(value, contract, '$');
	exact(raw, ['app', 'revisions', 'operations'], contract, '$');
	const app = object(raw.app, contract, '$.app');
	exact(app, ['appId', 'name', 'channel', 'managedDeliveryEnabled', 'allowedActions', 'providerReadiness'], contract, '$.app');
	if (app.appId !== 'collabora-code' || app.channel !== 'test') invalid(contract, '$.app');
	let providerReadiness: OfficeProviderReadiness | null = null;
	if (app.providerReadiness !== null) {
		const readiness = object(app.providerReadiness, contract, '$.app.providerReadiness');
		exact(readiness, ['providerId', 'generation', 'ready', 'state', 'remedy'], contract, '$.app.providerReadiness');
		providerReadiness = {
			providerId: string(readiness.providerId, contract, '$.app.providerReadiness.providerId'),
			generation: integer(readiness.generation, contract, '$.app.providerReadiness.generation', 1),
			ready: boolean(readiness.ready, contract, '$.app.providerReadiness.ready'),
			state: string(readiness.state, contract, '$.app.providerReadiness.state'),
			remedy: nullableString(readiness.remedy, contract, '$.app.providerReadiness.remedy')
		};
	}
	const revisions = array(raw.revisions, contract, '$.revisions', (entry, path) => {
		const revision = object(entry, contract, path);
		exact(revision, [
			'revisionId', 'revision', 'providerId', 'state', 'imageReference', 'imageDigest',
			'artifactReceipt', 'runtimeConfig', 'createdAt', 'updatedAt'
		], contract, path);
		return {
			revisionId: string(revision.revisionId, contract, `${path}.revisionId`),
			revision: integer(revision.revision, contract, `${path}.revision`, 1),
			providerId: string(revision.providerId, contract, `${path}.providerId`),
			state: string(revision.state, contract, `${path}.state`),
			imageReference: string(revision.imageReference, contract, `${path}.imageReference`),
			imageDigest: string(revision.imageDigest, contract, `${path}.imageDigest`),
			artifactReceipt: record(revision.artifactReceipt, contract, `${path}.artifactReceipt`),
			runtimeConfig: record(revision.runtimeConfig, contract, `${path}.runtimeConfig`),
			createdAt: string(revision.createdAt, contract, `${path}.createdAt`),
			updatedAt: string(revision.updatedAt, contract, `${path}.updatedAt`)
		};
	});
	return {
		app: {
			appId: 'collabora-code',
			name: string(app.name, contract, '$.app.name'),
			channel: 'test',
			managedDeliveryEnabled: boolean(app.managedDeliveryEnabled, contract, '$.app.managedDeliveryEnabled'),
			allowedActions: decodeActions(app.allowedActions, contract, '$.app.allowedActions'),
			providerReadiness
		},
		revisions,
		operations: array(raw.operations, contract, '$.operations', (entry, path) => decodeOperation(entry, contract, path))
	};
}

export function isOfficeAppOperationTerminal(state: OfficeAppOperationState): boolean {
	return terminalOperationStates.has(state);
}

export function decodeOfficeProviderConfigureResult(value: unknown): OfficeProviderConfigureResult {
	const contract = 'Office provider configure';
	const raw = object(value, contract, '$');
	exact(raw, ['providerId', 'generation', 'routeState', 'configSha256', 'qualified'], contract, '$');
	if (raw.routeState !== 'connected_inactive' || raw.qualified !== false) invalid(contract, '$');
	return {
		providerId: string(raw.providerId, contract, '$.providerId'),
		generation: integer(raw.generation, contract, '$.generation', 1),
		routeState: 'connected_inactive',
		configSha256: string(raw.configSha256, contract, '$.configSha256'),
		qualified: false
	};
}

export function decodeOfficeProviderQualificationResult(value: unknown): OfficeProviderQualificationResult {
	const contract = 'Office provider qualification';
	const raw = object(value, contract, '$');
	exact(raw, ['providerId', 'generation', 'routeState', 'qualificationId', 'expiresAt', 'qualified'], contract, '$');
	if (raw.routeState !== 'connected_inactive' || raw.qualified !== true) invalid(contract, '$');
	return {
		providerId: string(raw.providerId, contract, '$.providerId'),
		generation: integer(raw.generation, contract, '$.generation', 1),
		routeState: 'connected_inactive',
		qualificationId: string(raw.qualificationId, contract, '$.qualificationId'),
		expiresAt: string(raw.expiresAt, contract, '$.expiresAt'),
		qualified: true
	};
}

export function decodeOfficeProviderActivationResult(value: unknown): OfficeProviderActivationResult {
	const contract = 'Office provider activation';
	const raw = object(value, contract, '$');
	exact(raw, ['providerId', 'generation', 'routeState', 'qualificationId', 'scope'], contract, '$');
	if (raw.routeState !== 'active_for_scope') invalid(contract, '$.routeState');
	return {
		providerId: string(raw.providerId, contract, '$.providerId'),
		generation: integer(raw.generation, contract, '$.generation', 1),
		routeState: 'active_for_scope',
		qualificationId: string(raw.qualificationId, contract, '$.qualificationId'),
		scope: record(raw.scope, contract, '$.scope')
	};
}

export function decodeOfficeAppOperationAccepted(value: unknown): OfficeAppOperationAccepted {
	const contract = 'Office application operation';
	const raw = object(value, contract, '$');
	exact(raw, ['operationId', 'state', 'stateGeneration', 'phase', 'replayed'], contract, '$');
	return {
		operationId: string(raw.operationId, contract, '$.operationId'),
		state: enumValue(raw.state, operationStates, contract, '$.state'),
		stateGeneration: integer(raw.stateGeneration, contract, '$.stateGeneration', 1),
		phase: string(raw.phase, contract, '$.phase'),
		replayed: boolean(raw.replayed, contract, '$.replayed')
	};
}
