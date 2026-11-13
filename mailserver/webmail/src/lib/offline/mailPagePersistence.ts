/** Mail-owned composition over the existing generic native batch. No new native API. */
import type { NativeBatchStatement, OfflineDbBridge } from '$lib/native/types';
import type { OfflineStore, StoredMessage } from './store';
import type { CheckpointCommitOutcome, JobPersistence, LeaseFence, OptionalJobRecord } from './jobStore';
import type { SyncCheckpoint } from './work-contract';
import { admitBatch, DEFAULT_BATCH_BUDGET, executeBatch } from './nativeBatch';
import { createStagedStore, type StagedOp } from './stagedPage';
import { PageRollbackUnavailableError } from './storeErrors';

export interface MailPageIdentity {
	jobId: string;
	accountId: string;
	generation: number;
	fence: LeaseFence;
	/** Sample once before the batch; never use a clock expression per statement. */
	nowUtcMs: number;
}

export type CommitMailPage = (
	operations: readonly StagedOp[], identity: MailPageIdentity, checkpoint: SyncCheckpoint,
) => Promise<CheckpointCommitOutcome>;

/** A full prefix may yield. A record that cannot fit alone must fail finitely. */
export class MailPageCapacityError extends Error {
	readonly workCode = 'page-capacity';
	constructor(readonly canYield: boolean) {
		super(canYield ? 'mail page admission: commit the fitting prefix' :
			'mail page refused: one record or checkpoint exceeds the native batch capacity');
		this.name = 'MailPageCapacityError';
	}
}

const COLUMNS: Partial<Record<keyof StoredMessage, string>> = {
	threadId: 'thread_id', receivedAt: 'received_at', flags: 'flags', hasAttachment: 'has_attachment',
	cacheState: 'cache_state', syncedAt: 'synced_at', from: 'from_', to: 'to_', cc: 'cc', bcc: 'bcc',
	subject: 'subject', preview: 'preview',
};
const encode = (key: keyof StoredMessage, value: unknown) =>
	key === 'flags' ? JSON.stringify(value ?? []) : key === 'hasAttachment' ? (value ? 1 : 0) : value;

/** Every page write carries this SAME stable predicate. No page write changes its inputs. */
function jobPredicate(identity: MailPageIdentity) {
	return {
		sql: `EXISTS (SELECT 1 FROM optional_jobs WHERE job_id = ? AND account_id = ?
			AND trigger_generation = ? AND lease_owner = ? AND lease_expires_at_ms = ?
			AND lease_expires_at_ms > ? AND state = 'running')`,
		params: [identity.jobId, identity.accountId, identity.generation, identity.fence.owner,
			identity.fence.leaseExpiresAtMs, identity.nowUtcMs],
	};
}

/** SQL and serialized parameter bytes, including every repeated fence, are admitted together. */
export function mailPageStatements(
	operations: readonly StagedOp[], identity: MailPageIdentity, checkpoint: SyncCheckpoint,
): NativeBatchStatement[] {
	const fence = jobPredicate(identity);
	const statements: NativeBatchStatement[] = [];
	for (const op of operations) {
		const id = op.kind === 'upsert' ? op.message.id : op.id;
		// Match the existing F2 parsed-payload convention, including malformed payload refusal.
		const available = `${fence.sql} AND NOT EXISTS (SELECT 1 FROM action_queue
			WHERE status = 'pending' AND json_extract(CASE WHEN json_valid(payload) THEN payload ELSE '{}' END, '$.id') = ?)`;
		const availableParams = [...fence.params, id];
		if (op.kind === 'delete') {
			// An absent snapshot must not delete a row created meanwhile, even at watermark zero.
			const safe = `${available} AND NOT EXISTS (SELECT 1 FROM messages WHERE id = ?${
				op.expectedVersion == null ? '' : ` AND (dirty_fields != '[]' OR version > ?)`})`;
			const params = [...availableParams, id, ...(op.expectedVersion == null ? [] : [op.expectedVersion])];
			// The message predicate stays stable until the last delete. These four tables
			// have no schema triggers or foreign-key effects that can change the job fence.
			for (const [table, column] of [['message_tags', 'message_id'], ['bodies', 'id'], ['messages_fts', 'id'], ['messages', 'id']]) {
				statements.push({ sql: `DELETE FROM ${table} WHERE ${column} = ? AND ${safe}`, params: [id, ...params] });
			}
			continue;
		}
		if (op.kind === 'upsert') {
			const m = op.message;
			const keys = Object.keys(COLUMNS) as (keyof StoredMessage)[];
			const columns = keys.map((key) => COLUMNS[key]);
			const values = keys.map((key) => encode(key, m[key]));
			// A row created/edited after staging is merged at the native write seam, never replaced.
			const assignments = keys.map((key) => `${COLUMNS[key]} = CASE WHEN messages.dirty_fields NOT LIKE '%"${key}"%'
				THEN excluded.${COLUMNS[key]} ELSE messages.${COLUMNS[key]} END`);
			statements.push({
				sql: `INSERT INTO messages (id, ${columns.join(', ')}, version, dirty_fields)
					SELECT ${Array(values.length + 3).fill('?').join(', ')} WHERE ${available}
					ON CONFLICT(id) DO UPDATE SET ${assignments.join(', ')}, version = excluded.version
					WHERE excluded.version >= messages.version`,
				params: [id, ...values, m.version ?? 0, JSON.stringify(m.dirtyFields ?? []), ...availableParams],
			});
			const tagGuard = `${available} AND EXISTS (SELECT 1 FROM messages WHERE id = ?
				AND version <= ? AND dirty_fields NOT LIKE '%"tagIds"%')`;
			const tagParams = [...availableParams, id, m.version ?? 0];
			statements.push({ sql: `DELETE FROM message_tags WHERE message_id = ? AND ${tagGuard}`, params: [id, ...tagParams] });
			// Bound host parameters per statement independently of the aggregate byte budget.
			// No assumption about the number of tags per message; a huge record is refused finitely.
			const tags = [...new Set(m.tagIds)];
			for (let offset = 0; offset < tags.length; offset += 256) {
				const chunk = tags.slice(offset, offset + 256);
				statements.push({
					sql: `INSERT INTO message_tags (message_id, tag_id, received_at)
						SELECT ?, column1, (SELECT received_at FROM messages WHERE id = ?)
						FROM (VALUES ${chunk.map(() => '(?)').join(', ')}) WHERE ${tagGuard}`,
					params: [id, id, ...chunk, ...tagParams],
				});
			}
		} else {
			const keys = (Object.keys(op.changed) as (keyof StoredMessage)[]).filter((key) => COLUMNS[key]);
			const assignments = keys.map((key) => `${COLUMNS[key]} = CASE WHEN dirty_fields NOT LIKE '%"${key}"%'
				THEN ? ELSE ${COLUMNS[key]} END`);
			statements.push({
				sql: `UPDATE messages SET ${[...assignments, 'version = ?'].join(', ')}
					WHERE id = ? AND version <= ? AND ${available}`,
				params: [...keys.map((key) => encode(key, op.changed[key])), op.serverVersion, id, op.serverVersion, ...availableParams],
			});
		}
		// Rebuild from the committed row, including fields protected by a concurrent local edit.
		statements.push({ sql: `DELETE FROM messages_fts WHERE id = ? AND ${available}`, params: [id, ...availableParams] });
		statements.push({
			sql: `INSERT INTO messages_fts (id, subject, body, addrs)
				SELECT id, subject, preview, trim(from_ || ' ' || to_ || ' ' || cc) FROM messages
				WHERE id = ? AND ${available}`,
			params: [id, ...availableParams],
		});
	}
	// SQLite counts this matched UPDATE even when the value is unchanged. Therefore total
	// changed rows > 0 iff this checkpoint matched: every other write uses the same fence,
	// and no preceding statement changes optional_jobs. No preflight read authorizes writes.
	statements.push({
		sql: `UPDATE optional_jobs SET checkpoint_version = ?, checkpoint_cursor = ? WHERE job_id = ? AND ${fence.sql}`,
		params: [checkpoint.version, checkpoint.cursor, identity.jobId, ...fence.params],
	});
	return statements;
}

export function createNativeMailPageCommit(db: OfflineDbBridge): CommitMailPage {
	return async (operations, identity, checkpoint) => {
		if (!db.transactionBatch) throw new PageRollbackUnavailableError(operations.length);
		const changed = await executeBatch(db, 'mail', mailPageStatements(operations, identity, checkpoint));
		return { kind: changed > 0 ? 'committed' : 'stale-generation' };
	};
}

/** The coordinator owns scheduling; this module owns page/checkpoint composition. */
export function createMailPagePersistence(
	store: OfflineStore, jobs: JobPersistence, job: OptionalJobRecord, fence: LeaseFence,
	nowUtcMs: () => number,
) {
	let reserved: SyncCheckpoint = job.checkpoint ?? { version: 1, cursor: null };
	const identity = (): MailPageIdentity => ({ jobId: job.jobId, accountId: job.accountId,
		generation: job.triggerGeneration, fence, nowUtcMs: nowUtcMs() });
	const staged = createStagedStore(store, store.commitMailPage ? (operations) => {
		if (!store.hasAtomicRestore()) throw new PageRollbackUnavailableError(operations.length);
		const decision = admitBatch('mail', 'mail', DEFAULT_BATCH_BUDGET, mailPageStatements(operations, identity(), reserved));
		if (decision.kind === 'refused') throw new MailPageCapacityError(operations.length > 1);
	} : undefined);
	staged.reservePageCheckpoint = (checkpoint) => {
		reserved = checkpoint;
		if (store.commitMailPage && admitBatch('mail', 'mail', DEFAULT_BATCH_BUDGET,
			mailPageStatements([], identity(), checkpoint)).kind === 'refused') throw new MailPageCapacityError(false);
	};
	return {
		store: staged,
		discard: () => staged.discard(),
		async commit(checkpoint: SyncCheckpoint): Promise<CheckpointCommitOutcome> {
			if (store.commitMailPage) {
				const result = await store.commitMailPage(staged.stagedOperations, identity(), checkpoint);
				staged.discard();
				return result;
			}
			// Keep the model/legacy compensation path and its refusal/undo-retention tests.
			return jobs.commitCheckpoint(job.jobId, job.triggerGeneration, checkpoint, { fence, compose: {
				applyPage: () => staged.flushAllOrNothing(), rollbackPage: () => staged.rollbackAppliedPage(),
			} });
		},
	};
}
