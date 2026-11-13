/**
 * E4-I native bridge admission integration tests: the CLIENT-side platform
 * gate against the bridge shape the desktop shell projects now that the napi
 * bridge exports the E4 entries (`db_transaction_batch` /
 * `db_migrate_store`).
 *
 * Contract under test (boot.ts gating chain step 2 + the freeze doc):
 * - with `isNative() && db.transactionBatch` true, the durable coordinator is
 *   ADMISSIBLE: `durableJobPersistenceAvailable` admits, `store.init()` runs
 *   the versioned migrations through the native `migrateStore` entry, and
 *   `composeOfflineCoordinator` CONSTRUCTS the real engine (real native-store
 *   init, real durable persistence — no fake runner);
 * - the gate keys on exactly the atomic batch entry: the same bridge minus
 *   `transactionBatch` still refuses (`no-durable-persistence`);
 * - FLAGS STAY OFF: the bridge alone flips nothing. With the db present but
 *   neither a session-projected syncQoS block nor the E6 harness seam, the
 *   composition stays INERT (`inert-pair-off`) — the projected flag pair
 *   remains the only way to compose (boot.ts gating unchanged).
 *
 * The harness `createContractBridge()` is the N66-contract fake of the native
 * entries; the Rust-side oracles for the real exports live in
 * `clients/rust/offline-core/tests/transaction_batch_test.rs` and the
 * `native-shared` host lane.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('$lib/jmap/client', () => ({
	emailChanges: vi.fn(),
	emailGet: vi.fn(),
	emailQuery: vi.fn(),
	jmapCall: vi.fn(),
}));
vi.mock('$lib/db/offline', () => ({
	accountIdentity: (u: { userId?: number | null; email?: string } | null): string | null => {
		if (!u) return null;
		return u.userId != null ? `user:${u.userId}` : `email:${(u.email ?? '').toLowerCase()}`;
	},
}));

import {
	__resetBootForTests,
	composeOfflineCoordinator,
	composeOfflineCoordinatorForSession,
	readConnectivityCoordinatorState,
	resolveEffectiveGrant,
	readSessionOfflineGrant,
	type SessionOfflineGrant,
} from './boot';
import { makeNativeStore } from './store-native';
import { durableJobPersistenceAvailable } from './jobStore';
import { executeBatch, nativeBatchAvailable } from './nativeBatch';
import { nativeMigrationAvailable } from './migrations';
import { createContractBridge, type ContractBridge } from '$lib/native/testing/backgroundWorkHarness';
import type { OfflineDbBridge } from '$lib/native/types';

// ── fixtures ─────────────────────────────────────────────────────────────────

function sessionWithSyncQos(mode: string): Record<string, unknown> {
	return {
		effectiveCapabilities: {
			apps: { mail: true },
			features: {},
			offline: {
				allowed: true,
				approvalState: 'approved',
				maxOfflineDays: 30,
				wipeOnLogout: 'admin_default',
				requireApproval: false,
				syncQoS: {
					schemaVersion: 1,
					mode,
					backgroundAllowed: true,
					requested: { automaticNetwork: 'unmetered', attachmentPrefetch: 'unmetered' },
					effective: {
						automaticNetwork: 'unmetered',
						attachmentPrefetch: 'never',
						opportunisticRequiresCharging: true,
					},
					sources: {},
				},
			},
		},
	};
}

function grantFrom(mode: string): SessionOfflineGrant {
	const grant = readSessionOfflineGrant(sessionWithSyncQos(mode));
	if (grant === null) throw new Error('fixture must parse');
	return grant;
}

function compositionDeps(db: OfflineDbBridge): Record<string, unknown> {
	return {
		isNativeShell: () => true,
		bridgeDb: () => db,
		// The REAL native store path (store.init → applyMailMigrations) over the
		// bridge — the composed engine's own persistence substrate.
		openStore: () => makeNativeStore(db),
		// createJobs deliberately NOT injected: the composition constructs the
		// REAL durable job persistence over the bridge's transactionBatch.
		windowTarget: new EventTarget(),
		documentTarget: new EventTarget(),
		sessionSource: () => sessionWithSyncQos('execute'),
	};
}

beforeEach(() => {
	__resetBootForTests();
});

afterEach(() => {
	__resetBootForTests();
	vi.clearAllMocks();
	delete (window as unknown as Record<string, unknown>).setjoinNative;
});

// ── the gate ADMITS with the bridge present ───────────────────────────────────

describe('platform gate admits with the E4 native bridge present', () => {
	it('the projected db surface exposes both E4 entries and durable persistence admits', () => {
		const bridge = createContractBridge();
		const db = bridge as unknown as OfflineDbBridge;
		expect(nativeBatchAvailable(db)).toBe(true);
		expect(nativeMigrationAvailable(db)).toBe(true);
		expect(durableJobPersistenceAvailable(db)).toBe(true);
	});

	it('the coordinator CONSTRUCTS: real store init via native migrateStore + real durable persistence', async () => {
		const bridge = createContractBridge();
		const db = bridge as unknown as OfflineDbBridge;
		const composition = await composeOfflineCoordinator({
			accountId: 'user:1',
			grant: grantFrom('execute'),
			deps: compositionDeps(db) as never,
		});
		expect(composition.kind).toBe('composed');
		if (composition.kind !== 'composed') return;
		// store.init() ran the versioned migrations through the NATIVE entry —
		// never the legacy one-shot execSchemaInit seam (migrateStore wins when
		// present), and the store is current at v2.
		expect(bridge.log).toContainEqual(
			expect.objectContaining({ entry: 'migrateStore', disposition: 'admitted' }),
		);
		expect(bridge.log.some((e) => e.entry === 'execSchemaInit')).toBe(false);
		// The live saturation surface answers the COMPOSED snapshot — the E6
		// endpoint's observable flips from the gate diagnostic to real queue
		// state.
		const state = await readConnectivityCoordinatorState();
		expect(state).toMatchObject({
			composed: true,
			basis: 'engine-queue-observed',
			policyBasis: 'session-projected',
			mode: 'execute',
		});
		composition.dispose();
		await expect(readConnectivityCoordinatorState()).resolves.toEqual({
			composed: false,
			reason: 'not-composed',
		});
	});

	it('the gate keys on exactly the atomic batch entry: the same bridge minus transactionBatch refuses', async () => {
		const bridge = createContractBridge();
		const db = bridge as unknown as Record<string, unknown>;
		delete db.transactionBatch;
		const composition = await composeOfflineCoordinator({
			accountId: 'user:1',
			grant: grantFrom('execute'),
			deps: compositionDeps(db as unknown as OfflineDbBridge) as never,
		});
		expect(composition).toEqual({ kind: 'unavailable', reason: 'no-durable-persistence' });
	});

	it('executeBatch (the webmail admission wrapper) resolves through the bridge shape', async () => {
		const bridge = createContractBridge();
		const db = bridge as unknown as OfflineDbBridge;
		await db.open('mail');
		const changed = await executeBatch(db, 'mail', [
			{ sql: 'INSERT INTO meta_mail (key, value) VALUES (?, ?)', params: ['probe', 'v'] },
		]);
		expect(changed).toBeGreaterThan(0);
		expect(bridge.log).toContainEqual(
			expect.objectContaining({
				entry: 'transactionBatch',
				appKey: 'mail',
				disposition: 'admitted',
			}),
		);
	});
});

// ── flags stay OFF: the bridge alone composes nothing ────────────────────────

describe('flags stay OFF with the bridge present', () => {
	it('no session projection and no harness seam => INERT even with the full db surface', () => {
		// The electron-shaped injection: a contract-valid bridge whose db now
		// carries transactionBatch + migrateStore — and NO connectivity seam.
		(window as unknown as Record<string, unknown>).setjoinNative = {
			version: 1,
			capabilities: ['mailDb', 'secureStore', 'vault'],
			db: createContractBridge(),
		};
		const session = { effectiveCapabilities: { apps: { mail: true } } }; // no syncQoS block
		expect(resolveEffectiveGrant(session)).toBeNull();
		const disposer = composeOfflineCoordinatorForSession(session, { userId: 1, email: 'a@b.c' } as never);
		expect(disposer).toBeUndefined();
		// Nothing was constructed and no diagnostic/global exists.
		expect(window.__setjoinConnectivityQueueState).toBeUndefined();
	});

	it('the harness seam still requires the shell to project it: a bare db is not a flag', async () => {
		// Bridge present (isNative() true, durable persistence available) with a
		// flag-pair projection: composes ONLY because the session projects the
		// syncQoS block — the db surface is a capability, never a policy.
		(window as unknown as Record<string, unknown>).setjoinNative = {
			version: 1,
			capabilities: ['mailDb'],
			db: createContractBridge(),
		};
		const composition = await composeOfflineCoordinatorForSession(
			sessionWithSyncQos('execute'),
			{ userId: 2, email: 'flags@e6.test' } as never,
			{
				isNativeShell: () => true,
				bridgeDb: () => (window.setjoinNative as { db: OfflineDbBridge }).db,
				openStore: () =>
					makeNativeStore((window.setjoinNative as { db: OfflineDbBridge }).db),
				windowTarget: new EventTarget(),
				documentTarget: new EventTarget(),
			} as never,
		);
		expect(composition).toBeTypeOf('function');
		await new Promise((resolve) => setTimeout(resolve, 0));
		const state = await readConnectivityCoordinatorState();
		expect(state).toMatchObject({ composed: true, policyBasis: 'session-projected' });
		(composition as () => void)();
	});
});
