import { describe, it, expect } from 'vitest';

import type { OfflineDbBridge } from '$lib/native/types';
import { createContractBridge } from '$lib/native/testing/backgroundWorkHarness';
import {
	applyMailMigrations,
	BUNDLED_MANIFEST_DIGEST,
	detectMailSchemaVersion,
	legacySchemaInitSql,
	type MailMigrationManifest,
	MAIL_MIGRATION_MANIFEST,
	MAIL_SCHEMA_VERSION,
	migrationManifestDigest,
	planMigration,
	stableManifestJson,
} from './migrations';

function fakeDb(sqliteMaster: Array<{ name: string; sql: string | null }>): OfflineDbBridge {
	return {
		open: async () => {},
		isOpen: async () => true,
		exec: async () => 0,
		query: async <T = Record<string, unknown>>(_appKey: 'mail' | 'drive', _sql: string): Promise<T[]> =>
			sqliteMaster as unknown as T[],
		wipe: async () => {},
	};
}

describe('E4-I mail migrations', () => {
	it('the bundled manifest is finite, ordered and digest-stable', () => {
		expect(MAIL_MIGRATION_MANIFEST.appKey).toBe('mail');
		expect(MAIL_SCHEMA_VERSION).toBe(2);
		expect(MAIL_MIGRATION_MANIFEST.steps.map((step) => step.targetVersion)).toEqual([1, 2]);
		expect(stableManifestJson(MAIL_MIGRATION_MANIFEST)).toBe(stableManifestJson(MAIL_MIGRATION_MANIFEST));
		expect(BUNDLED_MANIFEST_DIGEST).toMatch(/^[0-9a-f]{8}$/);
	});

	it('plans fresh, v1 and current stores; refuses ahead, downgrade, unknown, foreign and forged manifests', () => {
		const fresh = planMigration({ version: 0, needsLegacyEligibilityReplay: false }, 2);
		expect(fresh.kind).toBe('ok');
		const current = planMigration({ version: 2, needsLegacyEligibilityReplay: false }, 2);
		expect(current).toEqual({ kind: 'ok', steps: [], legacyReplays: [] });
		expect(planMigration({ version: 2, needsLegacyEligibilityReplay: false }, 3)).toEqual({ kind: 'refused', reason: 'ahead-version' });
		expect(planMigration({ version: 2, needsLegacyEligibilityReplay: false }, 1)).toEqual({ kind: 'refused', reason: 'downgrade' });
		expect(planMigration({ version: 0, needsLegacyEligibilityReplay: false }, Number.NaN)).toEqual({ kind: 'refused', reason: 'unknown-version' });
		expect(planMigration({ version: 0, needsLegacyEligibilityReplay: false }, 2, MAIL_MIGRATION_MANIFEST, 'drive')).toEqual({ kind: 'refused', reason: 'foreign-app' });
		const forged = { ...MAIL_MIGRATION_MANIFEST, schemaVersion: 99 } as unknown as MailMigrationManifest;
		expect(planMigration({ version: 0, needsLegacyEligibilityReplay: false }, 2, forged)).toEqual({ kind: 'refused', reason: 'digest-mismatch' });
	});

	it('legacy dev stores replay the U6 eligibility upgrade inside the plan', () => {
		const legacy = planMigration({ version: 0, needsLegacyEligibilityReplay: true }, 2);
		expect(legacy.kind).toBe('ok');
		if (legacy.kind === 'ok') {
			expect(legacy.legacyReplays).toHaveLength(1);
			expect(legacy.legacyReplays[0]).toContain('ALTER TABLE recovery_artifacts');
		}
	});

	it('detects fresh, legacy, v1, partial-v2 and v2 stores from sqlite_master DDL', async () => {
		expect(await detectMailSchemaVersion(fakeDb([]))).toEqual({ version: 0, needsLegacyEligibilityReplay: false });
		expect(await detectMailSchemaVersion(fakeDb([
			{ name: 'recovery_artifacts', sql: 'CREATE TABLE recovery_artifacts (artifact_identity TEXT)' },
		]))).toEqual({ version: 0, needsLegacyEligibilityReplay: true });
		expect(await detectMailSchemaVersion(fakeDb([
			{ name: 'recovery_artifacts', sql: 'CREATE TABLE recovery_artifacts (artifact_identity TEXT, eligibility TEXT)' },
		]))).toEqual({ version: 1, needsLegacyEligibilityReplay: false });
		// Either optional-work table ALONE is an interrupted v2: it must recover
		// by replaying the v2 step, so detection reports v1 (Astra finding: v2
		// detected from either table prevented partial-migration recovery).
		expect(await detectMailSchemaVersion(fakeDb([
			{ name: 'recovery_artifacts', sql: 'CREATE TABLE recovery_artifacts (eligibility TEXT)' },
			{ name: 'optional_jobs', sql: 'CREATE TABLE optional_jobs (job_id TEXT)' },
		]))).toEqual({ version: 1, needsLegacyEligibilityReplay: false });
		expect(await detectMailSchemaVersion(fakeDb([
			{ name: 'recovery_artifacts', sql: 'CREATE TABLE recovery_artifacts (eligibility TEXT)' },
			{ name: 'attachment_transfers', sql: 'CREATE TABLE attachment_transfers (job_id TEXT)' },
		]))).toEqual({ version: 1, needsLegacyEligibilityReplay: false });
		// v2 requires BOTH optional-work tables.
		expect(await detectMailSchemaVersion(fakeDb([
			{ name: 'recovery_artifacts', sql: 'CREATE TABLE recovery_artifacts (eligibility TEXT)' },
			{ name: 'optional_jobs', sql: 'CREATE TABLE optional_jobs (job_id TEXT)' },
			{ name: 'attachment_transfers', sql: 'CREATE TABLE attachment_transfers (job_id TEXT)' },
		]))).toEqual({ version: 2, needsLegacyEligibilityReplay: false });
	});

	it('composes legacy one-shot SQL per detected generation', () => {
		const fresh = legacySchemaInitSql({ version: 0, needsLegacyEligibilityReplay: false });
		expect(fresh).toContain('CREATE TABLE IF NOT EXISTS messages');
		expect(fresh).toContain('eligibility TEXT NOT NULL');
		expect(fresh).toContain('CREATE TABLE IF NOT EXISTS optional_jobs');
		expect(fresh).toContain('CREATE TABLE IF NOT EXISTS attachment_transfers');
		expect(fresh).not.toContain('ALTER TABLE');
		const legacyDev = legacySchemaInitSql({ version: 0, needsLegacyEligibilityReplay: true });
		expect(legacyDev).toContain("ALTER TABLE recovery_artifacts ADD COLUMN eligibility TEXT NOT NULL DEFAULT 'received'");
		expect(legacySchemaInitSql({ version: 2, needsLegacyEligibilityReplay: false })).toBe('');
	});

	it('job/transfer tables stay content-minimal (no bearer, subject, URL, or location columns)', () => {
		const v2 = MAIL_MIGRATION_MANIFEST.steps[1].statements.join('\n').toLowerCase();
		for (const forbidden of ['bearer', 'token', 'subject', 'sender', 'filename', 'body', 'url', 'ssid', 'carrier']) {
			expect(v2.includes(forbidden), `column leak: ${forbidden}`).toBe(false);
		}
	});

	it('applyMailMigrations fails closed when no authorized seam exists', async () => {
		const bare = {
			open: async () => {},
			isOpen: async () => true,
			exec: async () => 0,
			query: async () => [] as Array<Record<string, unknown>>,
			wipe: async () => {},
		} as unknown as OfflineDbBridge;
		await expect(applyMailMigrations(bare)).rejects.toThrow(/authorized schema-init seam/);
	});

	it('an already-current legacy-shell store re-opens without issuing an empty one-shot batch', async () => {
		// Astra finding: the legacy path composed an EMPTY execSchemaInit batch
		// when already at v2 — the native seam rejects it and the one-shot gate
		// would be consumed, breaking every later reopen.
		const bridge = createContractBridge();
		const legacyShell = Object.create(bridge) as typeof bridge;
		Object.defineProperty(legacyShell, 'transactionBatch', { value: undefined });
		Object.defineProperty(legacyShell, 'migrateStore', { value: undefined });
		await legacyShell.open('mail');
		const initCalls: string[] = [];
		const originalInit = legacyShell.execSchemaInit!.bind(legacyShell);
		legacyShell.execSchemaInit = async (appKey, sql) => {
			initCalls.push(sql);
			return originalInit(appKey, sql);
		};
		const first = await applyMailMigrations(legacyShell);
		expect(first.via).toBe('execSchemaInit');
		expect(initCalls).toHaveLength(1);
		const reopen = await applyMailMigrations(legacyShell);
		// The reopen consumed NO one-shot call and issued no empty batch.
		expect(reopen).toEqual({ version: 2, via: 'current' });
		expect(initCalls).toHaveLength(1);
		expect(await detectMailSchemaVersion(legacyShell).then((d) => d.version)).toBe(2);
	});

	it('a partially migrated v2 store is detected at v1 and the replay completes it', async () => {
		// Astra finding: v2 detection from either optional table prevented
		// recovery of an interrupted v2 step.
		const bridge = createContractBridge();
		await bridge.open('mail');
		const partialSql = [
			...MAIL_MIGRATION_MANIFEST.steps[0].statements,
			MAIL_MIGRATION_MANIFEST.steps[1].statements[0], // optional_jobs only
		].map((statement) => `${statement};`).join('\n');
		await bridge.execSchemaInit!('mail', partialSql);
		expect(await detectMailSchemaVersion(bridge)).toEqual({ version: 1, needsLegacyEligibilityReplay: false });
		const result = await applyMailMigrations(bridge);
		expect(result.via).toBe('migrateStore');
		expect(await detectMailSchemaVersion(bridge)).toEqual({ version: 2, needsLegacyEligibilityReplay: false });
	});

	it('migrations NEVER send DDL through transactionBatch (frozen N66 batch contract)', async () => {
		// Astra finding: the fallback composed CREATE/ALTER through
		// transactionBatch, whose frozen contract prohibits DDL — a conforming
		// batch-only bridge would reject initialization.
		const bridge = createContractBridge();
		const batchOnly = Object.create(bridge) as typeof bridge;
		Object.defineProperty(batchOnly, 'execSchemaInit', { value: undefined });
		Object.defineProperty(batchOnly, 'migrateStore', { value: undefined });
		await batchOnly.open('mail');
		await expect(applyMailMigrations(batchOnly)).rejects.toThrow(/frozen contract prohibits DDL|authorized/);
		// No batch call was attempted at all: DDL never reached the batch entry.
		expect(bridge.log.filter((entry) => entry.entry === 'transactionBatch')).toHaveLength(0);
	});

	it('digest comparison distinguishes any manifest mutation', () => {
		const mutated = JSON.parse(JSON.stringify(MAIL_MIGRATION_MANIFEST)) as typeof MAIL_MIGRATION_MANIFEST;
		mutated.steps[1].statements = [...mutated.steps[1].statements, 'CREATE TABLE extra (x)'];
		expect(migrationManifestDigest(mutated)).not.toBe(BUNDLED_MANIFEST_DIGEST);
	});
});
