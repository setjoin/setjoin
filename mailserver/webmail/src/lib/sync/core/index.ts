// Pure framework-free SyncCoordinator barrel (Wave 2.8, #555).
// Strictly `.js`-relative exports; never imports from `../webmail/`.

export {
	DEFAULT_SYNC_BUDGET_BYTES,
	DEFAULT_SYNC_BUDGET_MS,
	DEFAULT_SYNC_BUDGET_RECORDS,
	SCOPE_KINDS,
	isPreemptibleLane,
	scopeKeyString,
	type CriticalActivityLike,
	type OfflineWipeEvent,
	type RevocationFence,
	type ScopeKey,
	type ScopeKind,
	type ScopeRevokedEvent,
	type ScopeSyncState,
	type StepOutcome,
	type StepOutcomeKind,
	type SyncBudget,
	type SyncLane,
	type SyncScopeAdapter,
	type SyncStepContext,
	type SyncTriggerKind,
	type SyncWakeup,
	type WakeupTransport,
} from './types.js';

export {
	MAX_ATTACHED_SCOPES,
	MAX_SCOPE_ID_LENGTH,
	isValidAppKey,
	isValidScopeId,
	isValidScopeKind,
	isValidSeq,
	validateOfflineWipe,
	validateScopeAttachList,
	validateScopeRevoked,
	validateSyncWakeup,
	type ValidationWarnFn,
} from './validate.js';

export {
	DEFAULT_RECOVERY_BASE_MS,
	DEFAULT_RECOVERY_MAX_MS,
	SyncCoordinator,
	SyncFenceAbortedError,
	type SyncCoordinatorOptions,
} from './coordinator.js';
