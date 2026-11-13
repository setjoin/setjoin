/**
 * E4-I versioned TS-owned mail store migrations.
 *
 * Replaces the single best-effort `MAIL_SCHEMA` block with a finite, versioned,
 * bundled migration manifest inside the existing SQLCipher-encrypted native
 * `mail` store. Authority: the native transaction freeze
 * (retired-docs:verification/2026-09-08-connectivity-native-transaction-freeze.md) and
 * the connectivity plan's E4-I unit.
 *
 * Registered migrations, not caller registration: this manifest is a trusted
 * bundled constant compiled into the application artifact. Ordinary job
 * callers cannot register/replace migrations, supply migration SQL or grant
 * themselves DDL rights — there is no runtime `register` entry, and the only
 * execution paths are the native `migrateStore` manifest loader (which loads
 * its own verified bundled copy through the installer/application-update trust
 * path) or the pre-existing authorized one-shot `execSchemaInit` seam.
 *
 * Schema history (versioned from the first release that carries version rows):
 * - v1: the shipped base schema (identical statement text to the historical
 *   `MAIL_SCHEMA`, including the `recovery_artifacts.eligibility` column).
 * - v2: the connectivity optional-work tables (`optional_jobs` and
 *   `attachment_transfers`). Content-minimal: no bearer token, subject,
 *   sender, filename, body or network-location history, per plan §4.
 *
 * Pre-versioning dev stores (created before `schema_version` existed) are
 * detected by their `sqlite_master` DDL exactly as the historical U6 probe
 * did; they replay the eligibility upgrade inside the same authorized batch.
 */

import type { NativeDbAppKey, OfflineDbBridge } from '$lib/native/types';

/** Version of the manifest envelope itself (not the schema version). */
export const MAIL_MANIFEST_VERSION = 1 as const;
/** Current mail schema version produced by this manifest. */
export const MAIL_SCHEMA_VERSION = 2 as const;

export interface MailMigrationStep {
	/** Stable step identity used in audits and refusal causes. */
	id: string;
	/** Schema version AFTER this step commits. Ordered, no gaps. */
	targetVersion: number;
	/** Statements executed in ONE atomic native transaction with the version row. */
	statements: readonly string[];
}

export interface MailMigrationManifest {
	appKey: NativeDbAppKey;
	manifestVersion: typeof MAIL_MANIFEST_VERSION;
	schemaVersion: typeof MAIL_SCHEMA_VERSION;
	steps: readonly MailMigrationStep[];
}

/** The bundled trusted manifest. Never accepted from callers at runtime. */
export const MAIL_MIGRATION_MANIFEST: MailMigrationManifest = {
	appKey: 'mail',
	manifestVersion: MAIL_MANIFEST_VERSION,
	schemaVersion: MAIL_SCHEMA_VERSION,
	steps: [
		{
			id: 'mail-v1-base',
			targetVersion: 1,
			statements: [
				`CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  thread_id TEXT NOT NULL DEFAULT '',
  received_at INTEGER NOT NULL DEFAULT 0,
  flags TEXT NOT NULL DEFAULT '[]',
  has_attachment INTEGER NOT NULL DEFAULT 0,
  cache_state TEXT NOT NULL DEFAULT 'meta',
  synced_at INTEGER NOT NULL DEFAULT 0,
  from_ TEXT NOT NULL DEFAULT '',
  to_ TEXT NOT NULL DEFAULT '',
  cc TEXT NOT NULL DEFAULT '',
  bcc TEXT NOT NULL DEFAULT '',
  subject TEXT NOT NULL DEFAULT '',
  preview TEXT NOT NULL DEFAULT '',
  version INTEGER NOT NULL DEFAULT 0,
  dirty_fields TEXT NOT NULL DEFAULT '[]'
)`,
				`CREATE INDEX IF NOT EXISTS idx_messages_received ON messages(received_at DESC)`,
				`CREATE INDEX IF NOT EXISTS idx_messages_thread ON messages(thread_id)`,
				`CREATE TABLE IF NOT EXISTS message_tags (
  message_id TEXT NOT NULL,
  tag_id TEXT NOT NULL,
  received_at INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (message_id, tag_id)
)`,
				`CREATE INDEX IF NOT EXISTS idx_message_tags_tag ON message_tags(tag_id, received_at DESC)`,
				`CREATE TABLE IF NOT EXISTS bodies (
  id TEXT PRIMARY KEY,
  html_body TEXT NOT NULL DEFAULT '',
  text_body TEXT NOT NULL DEFAULT '',
  inline_refs TEXT NOT NULL DEFAULT '[]'
)`,
				`CREATE TABLE IF NOT EXISTS mailboxes (
  id TEXT PRIMARY KEY,
  role TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL DEFAULT '',
  counts TEXT NOT NULL DEFAULT '{}'
)`,
				`CREATE TABLE IF NOT EXISTS sync_issues (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  action_type TEXT NOT NULL,
  payload TEXT NOT NULL DEFAULT '{}',
  error TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL DEFAULT 0
)`,
				`CREATE TABLE IF NOT EXISTS meta_mail (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL DEFAULT ''
)`,
				`CREATE TABLE IF NOT EXISTS action_queue (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL,
  payload TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL DEFAULT 0
)`,
				`CREATE INDEX IF NOT EXISTS idx_action_queue_status ON action_queue(status, created_at)`,
				`CREATE TABLE IF NOT EXISTS recovery_artifacts (
  artifact_identity TEXT PRIMARY KEY,
  message_id TEXT NOT NULL,
  account_id TEXT NOT NULL,
  mailbox_id TEXT NOT NULL,
  installation_id TEXT NOT NULL,
  raw_sha256 TEXT NOT NULL,
  raw_size INTEGER NOT NULL,
  received_at INTEGER NOT NULL,
  timeline_generation TEXT NOT NULL,
  boot_epoch TEXT NOT NULL,
  state_watermark TEXT NOT NULL,
  receipt TEXT NOT NULL,
  eligibility TEXT NOT NULL DEFAULT 'received',
  verified_at INTEGER NOT NULL,
  retained_until INTEGER,
  status TEXT NOT NULL DEFAULT 'covered'
)`,
				`CREATE UNIQUE INDEX IF NOT EXISTS idx_recovery_artifacts_message ON recovery_artifacts(account_id, message_id, raw_sha256)`,
				`CREATE INDEX IF NOT EXISTS idx_recovery_artifacts_received ON recovery_artifacts(received_at DESC)`,
				`CREATE TABLE IF NOT EXISTS recovery_artifact_items (
  artifact_identity TEXT NOT NULL,
  item_id TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  role TEXT NOT NULL,
  PRIMARY KEY (artifact_identity, item_id),
  FOREIGN KEY (artifact_identity) REFERENCES recovery_artifacts(artifact_identity) ON DELETE CASCADE
)`,
				`CREATE TABLE IF NOT EXISTS recovery_uploads (
  artifact_identity TEXT NOT NULL,
  incident_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  device_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (artifact_identity, incident_id),
  UNIQUE (session_id),
  FOREIGN KEY (artifact_identity) REFERENCES recovery_artifacts(artifact_identity) ON DELETE CASCADE
)`,
				`CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
  id UNINDEXED, subject, body, addrs, tokenize = 'unicode61'
)`,
			],
		},
		{
			id: 'mail-v2-optional-work',
			targetVersion: 2,
			statements: [
				`CREATE TABLE IF NOT EXISTS optional_jobs (
  job_id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  work_class TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'queued',
  trigger_generation INTEGER NOT NULL DEFAULT 0,
  coalescing_key TEXT NOT NULL UNIQUE,
  attempts INTEGER NOT NULL DEFAULT 0,
  deadline_utc TEXT NOT NULL,
  queued_at_utc_ms INTEGER NOT NULL DEFAULT 0,
  retry_at_utc_ms INTEGER,
  step_kind TEXT NOT NULL DEFAULT 'delta',
  checkpoint_version INTEGER,
  checkpoint_cursor TEXT,
  lease_owner TEXT,
  lease_expires_at_ms INTEGER,
  result_state TEXT,
  result_json TEXT
)`,
				`CREATE INDEX IF NOT EXISTS idx_optional_jobs_due ON optional_jobs(state, retry_at_utc_ms)`,
				`CREATE INDEX IF NOT EXISTS idx_optional_jobs_account ON optional_jobs(account_id, state)`,
				`CREATE TABLE IF NOT EXISTS attachment_transfers (
  job_id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  blob_sha256 TEXT NOT NULL,
  etag TEXT NOT NULL,
  expected_size INTEGER NOT NULL,
  expected_sha256 TEXT NOT NULL,
  committed_bytes INTEGER NOT NULL DEFAULT 0,
  state TEXT NOT NULL DEFAULT 'queued',
  deadline_utc TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  checkpoint_version INTEGER NOT NULL DEFAULT 1
)`,
				`CREATE INDEX IF NOT EXISTS idx_attachment_transfers_account ON attachment_transfers(account_id, state)`,
			],
		},
	],
};

/** The pre-versioning dev-store eligibility upgrade (historical U6 replay). */
export const MAIL_U6_ELIGIBILITY_REPLAY =
	"ALTER TABLE recovery_artifacts ADD COLUMN eligibility TEXT NOT NULL DEFAULT 'received';";

/** Stable, deterministic JSON for digest binding (sorted keys, no whitespace). */
export function stableManifestJson(value: unknown): string {
	return JSON.stringify(value, (_key, val) => {
		if (val !== null && typeof val === 'object' && !Array.isArray(val)) {
			const out: Record<string, unknown> = {};
			for (const k of Object.keys(val).sort()) out[k] = (val as Record<string, unknown>)[k];
			return out;
		}
		return val;
	});
}

/** FNV-1a 32-bit over the stable JSON — a binding/comparison digest only.
 *  Cryptographic signature/digest validation stays on the native trust path. */
export function migrationManifestDigest(manifest: MailMigrationManifest): string {
	const text = stableManifestJson(manifest);
	let hash = 0x811c9dc5;
	for (let i = 0; i < text.length; i += 1) {
		hash ^= text.charCodeAt(i);
		hash = Math.imul(hash, 0x01000193) >>> 0;
	}
	return hash.toString(16).padStart(8, '0');
}

export const BUNDLED_MANIFEST_DIGEST = migrationManifestDigest(MAIL_MIGRATION_MANIFEST);

/** Detection of the current on-disk schema generation. */
export interface DetectedSchema {
	version: number;
	/** True for pre-versioning dev stores whose DDL lacks `eligibility`. */
	needsLegacyEligibilityReplay: boolean;
}

export type MigrationRefusalReason =
	| 'unknown-version'
	| 'ahead-version'
	| 'downgrade'
	| 'digest-mismatch'
	| 'foreign-app';

export type MigrationPlan =
	| { kind: 'ok'; steps: readonly MailMigrationStep[]; legacyReplays: readonly string[] }
	| { kind: 'refused'; reason: MigrationRefusalReason };

/**
 * Pure admission planner. Refuses unknown, ahead and downgrade targets,
 * caller-supplied manifests whose digest does not match the bundled manifest
 * (forged registration), and manifests naming another app's namespace —
 * before any statement is produced.
 */
export function planMigration(
	current: DetectedSchema,
	targetVersion: number,
	manifest: MailMigrationManifest = MAIL_MIGRATION_MANIFEST,
	requestedAppKey: NativeDbAppKey = 'mail',
): MigrationPlan {
	if (manifest.appKey !== requestedAppKey) return { kind: 'refused', reason: 'foreign-app' };
	if (manifest !== MAIL_MIGRATION_MANIFEST) {
		// Only the bundled manifest is trusted; a caller-supplied copy must at
		// least bind to the bundled digest, otherwise it is forged registration.
		if (migrationManifestDigest(manifest) !== BUNDLED_MANIFEST_DIGEST) {
			return { kind: 'refused', reason: 'digest-mismatch' };
		}
	}
	if (!Number.isSafeInteger(targetVersion)) return { kind: 'refused', reason: 'unknown-version' };
	if (targetVersion > manifest.schemaVersion) return { kind: 'refused', reason: 'ahead-version' };
	if (targetVersion < current.version) return { kind: 'refused', reason: 'downgrade' };
	if (targetVersion > MAIL_SCHEMA_VERSION) return { kind: 'refused', reason: 'unknown-version' };

	const steps: MailMigrationStep[] = [];
	if (current.version < 1) {
		const v1 = manifest.steps.find((step) => step.targetVersion === 1);
		if (!v1) return { kind: 'refused', reason: 'unknown-version' };
		steps.push(v1);
	}
	if (current.version < 2 && targetVersion >= 2) {
		const v2 = manifest.steps.find((step) => step.targetVersion === 2);
		if (!v2) return { kind: 'refused', reason: 'unknown-version' };
		steps.push(v2);
	}
	// The replay rides whenever the store actually lacks the eligibility
	// column — including an interrupted legacy init that already created the
	// optional tables (E4-I Astra correction: the replay is composed after
	// both optional tables, so "at v2" never implies "replay done").
	const legacyReplays = current.needsLegacyEligibilityReplay
		? [MAIL_U6_ELIGIBILITY_REPLAY]
		: [];
	return { kind: 'ok', steps, legacyReplays };
}

/**
 * Detect the schema generation from the store's own `sqlite_master` DDL —
 * the same source the historical U6 probe used after PRAGMA reads were
 * rejected by shell gates. Fresh stores have no rows; versioned stores are
 * recognized by their newest migration's artifacts.
 *
 * E4-I Astra corrections: v2 is reported ONLY when BOTH optional-work tables
 * exist. Detecting v2 from either table alone hid partially-migrated stores
 * (an interrupted v2 step) from recovery — the migration then replays and
 * completes instead of missing a table forever. AND v2 is never reported as
 * fully current while `recovery_artifacts` still lacks its `eligibility`
 * column: the legacy eligibility replay is composed AFTER both optional
 * tables, so an interrupted legacy init can leave optional tables present
 * with the replay still missing — that store reports
 * `needsLegacyEligibilityReplay` and the replay is applied on open instead
 * of being mistaken for a current store.
 */
export async function detectMailSchemaVersion(db: OfflineDbBridge): Promise<DetectedSchema> {
	const rows = await db.query<{ name: string; sql: string | null }>(
		'mail',
		"SELECT name, sql FROM sqlite_master WHERE type IN ('table') AND name IN ('recovery_artifacts','optional_jobs','attachment_transfers')",
	);
	const names = new Set(rows.map((row) => row.name));
	const legacyEligibilityMissing = ((): boolean => {
		if (!names.has('recovery_artifacts')) return false;
		const ddl = rows.find((row) => row.name === 'recovery_artifacts')?.sql ?? '';
		return !/\beligibility\b/.test(ddl);
	})();
	if (names.has('optional_jobs') && names.has('attachment_transfers')) {
		return { version: MAIL_SCHEMA_VERSION, needsLegacyEligibilityReplay: legacyEligibilityMissing };
	}
	if (names.has('recovery_artifacts')) {
		if (legacyEligibilityMissing) {
			return { version: 0, needsLegacyEligibilityReplay: true };
		}
		// A store at v1 (or an interrupted v2 with one optional table) replays
		// the v2 step; every statement is idempotent IF NOT EXISTS.
		return { version: 1, needsLegacyEligibilityReplay: false };
	}
	return { version: 0, needsLegacyEligibilityReplay: false };
}

/**
 * Compose the one-shot authorized `execSchemaInit` SQL for shells without the
 * E4-I native entries. Idempotent statements make replays safe; a mid-batch
 * failure leaves earlier CREATEs applied and the gate unconsumed (retry stays
 * possible) exactly as the historical seam behaved.
 */
export function legacySchemaInitSql(detected: DetectedSchema): string {
	const plan = planMigration(detected, MAIL_SCHEMA_VERSION);
	if (plan.kind === 'refused') {
		throw new Error(`mail migrations: refused ${plan.reason} during legacy composition`);
	}
	const statements: string[] = [];
	for (const step of plan.steps) statements.push(...step.statements);
	statements.push(...plan.legacyReplays);
	return statements.map((statement) => `${statement};`).join('\n');
}

export interface MigrationApplyResult {
	version: number;
	via: 'migrateStore' | 'execSchemaInit' | 'current';
}

/** True only when the bridge exposes the E4-I native migration entry. */
export function nativeMigrationAvailable(db: OfflineDbBridge): boolean {
	return typeof db.migrateStore === 'function';
}

/**
 * Apply the mail migrations through an authorized path ONLY:
 * native `migrateStore` (bundled manifest, installer/application-update trust
 * path), else the pre-existing one-shot `execSchemaInit` seam. DDL never
 * travels through `transactionBatch` — the frozen N66 batch contract
 * prohibits DDL there, and a conforming batch-only bridge would reject
 * initialization. A store already at the current version re-opens without
 * consuming the one-shot seam (no empty batch is ever issued); shells
 * without any authorized seam fail closed before any statement is issued.
 */
export async function applyMailMigrations(db: OfflineDbBridge): Promise<MigrationApplyResult> {
	const detected = await detectMailSchemaVersion(db);
	if (typeof db.migrateStore === 'function') {
		const result = await db.migrateStore('mail', MAIL_SCHEMA_VERSION);
		return { version: result.version, via: 'migrateStore' };
	}
	if (detected.version >= MAIL_SCHEMA_VERSION && !detected.needsLegacyEligibilityReplay) {
		// E4-I Astra correction: an already-current store re-opens cleanly.
		// Issuing the empty composed batch consumed the one-shot seam (and is
		// rejected by the native entry), breaking every later reopen.
		return { version: detected.version, via: 'current' };
	}
	if (typeof db.execSchemaInit !== 'function') {
		throw new Error(
			'offline store init: this shell does not expose the authorized schema-init seam ' +
				'(db.execSchemaInit) nor the E4-I native migration entry (migrateStore); the ' +
				'versioned mail migrations cannot run through ordinary exec (refused by the ' +
				'sql guard) and never through transactionBatch, whose frozen contract ' +
				'prohibits DDL.',
		);
	}
	await db.execSchemaInit('mail', legacySchemaInitSql(detected));
	return { version: MAIL_SCHEMA_VERSION, via: 'execSchemaInit' };
}
