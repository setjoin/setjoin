// Native offline-mail SyncScopeAdapter (Wave 2.8, #555).
//
// Routes wakeups through `$lib/offline/boot.ts`'s `ingestConnectivityPushTrigger()`
// — preserving E4-I default-inertness (`syncQoS` absent or `'off'` stays
// completely inert), `JobPersistence`, `LeaseFence`, `stagedPage` atomic commit,
// `FRESH_SNAPSHOT_MAX_AGE_MS`, `window.__setjoinConnectivityQueueState`, and
// `drainForRollback()`.
//
// Security lane (`offline.wipe` / `scope_revoked`) executes immediately even
// when `syncQoS` is `'off'` or `criticalActivity > 0`, honoring fail-closed
// `deviceId` targeting and `'mail'` vs `'drive'` wipe semantics.

import {
	drainActiveOfflineCoordinator,
	hasActiveOfflineCoordinator,
	ingestConnectivityPushTrigger,
} from '$lib/offline/boot';
import { MailPageCapacityError } from '$lib/offline/mailPagePersistence';
import { getNative, hasCapability, isNative } from '$lib/native';
import { readOwnDeviceId } from '$lib/native/deviceId';
import type { NativeDbAppKey } from '$lib/native/types';
import type {
	OfflineWipeEvent,
	StepOutcome,
	SyncScopeAdapter,
	SyncStepContext,
} from '../../core/types.js';

export interface OfflineMailSyncAdapterOptions {
	mailboxScopeId: string;
	consumerId?: string;
	/** Injectable trigger seam (defaults to `ingestConnectivityPushTrigger`). */
	ingestPushTrigger?: () => void;
	/** Optional storage-full callback surfaced when `MailPageCapacityError` occurs. */
	onCapacityExceeded?: (detail?: string) => void;
}

export function createOfflineMailSyncAdapter(options: OfflineMailSyncAdapterOptions): SyncScopeAdapter {
	const ingest = options.ingestPushTrigger ?? ingestConnectivityPushTrigger;

	return {
		consumerId: options.consumerId ?? `offline-mail:${options.mailboxScopeId}`,
		scope: { kind: 'mailbox', id: options.mailboxScopeId },
		lane: 'offline-native',
		debounceMs: 0,

		async runDeltaStep(ctx: SyncStepContext): Promise<StepOutcome> {
			ctx.fence.assertCommitAllowed();
			// E4-I default-inertness: if no offline coordinator is composed (syncQoS
			// absent or 'off'), `ingestConnectivityPushTrigger()` is a strict no-op.
			if (!hasActiveOfflineCoordinator() && !options.ingestPushTrigger) {
				return { kind: 'complete', recordsProcessed: 0 };
			}
			try {
				ingest();
			} catch (err) {
				if (err instanceof MailPageCapacityError) {
					return { kind: 'capacityExceeded', detail: err.message };
				}
				throw err;
			}
			ctx.fence.assertCommitAllowed();
			return { kind: 'complete', recordsProcessed: 1 };
		},

		onCapacityExceeded: options.onCapacityExceeded,
	};
}

export interface ExecuteOfflineWipeOptions {
	event: OfflineWipeEvent;
	abortSyncCoordinator?: () => Promise<void>;
	readDeviceId?: () => Promise<string | null>;
	wipeDb?: (appKey: NativeDbAppKey) => Promise<void>;
	logout?: () => void;
}

/**
 * Security-lane `offline.wipe` execution preserving fail-closed `deviceId`
 * targeting (`wipe.ts:95`) and aborting in-flight `SyncCoordinator` +
 * `offline/coordinator.ts` work BEFORE calling `db.wipe(appKey)`.
 *
 * Returns `true` if the wipe applied to this device, `false` if no-op'd by
 * fail-closed device targeting.
 */
export async function executeSecurityOfflineWipe(options: ExecuteOfflineWipeOptions): Promise<boolean> {
	const { event } = options;
	if (event.deviceId !== undefined) {
		const raw = await (options.readDeviceId ?? readOwnDeviceId)();
		const own = raw !== null ? Number(raw) : Number.NaN;
		if (!Number.isFinite(own) || own !== event.deviceId) {
			// Fail closed: sibling device or unreadable own device_id MUST no-op.
			return false;
		}
	}

	await Promise.allSettled([
		options.abortSyncCoordinator?.() ?? Promise.resolve(),
		drainActiveOfflineCoordinator(),
	]);

	const targetAppKey: NativeDbAppKey = event.appKey ?? 'mail';
	if (options.wipeDb) {
		await options.wipeDb(targetAppKey);
	} else if (isNative() && hasCapability('mailDb')) {
		await getNative().db?.wipe(targetAppKey);
	}

	options.logout?.();
	return true;
}
