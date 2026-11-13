import { describe, it, expect } from 'vitest';

import type { NativeBatchBudget } from '$lib/native/types';
import {
	admitBatch,
	admitBatchStatement,
	admitOrdinaryStatement,
	tokenizeStatement,
} from './nativeBatch';

const BUDGET: NativeBatchBudget = { maxStatements: 8, maxParamBytes: 1024 };
const STATEMENTS = [
	{ sql: 'INSERT INTO optional_jobs (job_id) VALUES (?)', params: ['job-1'] },
	{ sql: 'SELECT checkpoint_cursor FROM optional_jobs WHERE job_id = ?', params: ['job-1'] },
];

describe('E4-I native batch admission', () => {
	it('admits parameterized DML/read batches within budget', () => {
		const decision = admitBatch('mail', 'mail', BUDGET, STATEMENTS);
		expect(decision).toMatchObject({ kind: 'admitted', statementCount: 2 });
	});

	it('refuses cross-app handles before anything else', () => {
		expect(admitBatch('mail', 'drive', BUDGET, STATEMENTS)).toMatchObject({
			kind: 'refused',
			reason: 'foreign-app-handle',
		});
	});

	it('refuses empty batches and over-budget batches', () => {
		expect(admitBatch('mail', 'mail', BUDGET, [])).toMatchObject({ kind: 'refused', reason: 'empty-batch' });
		expect(admitBatch('mail', 'mail', { maxStatements: 1, maxParamBytes: 1024 }, STATEMENTS)).toMatchObject({
			kind: 'refused',
			reason: 'too-many-statements',
		});
		const huge: string[] = Array.from({ length: 4 }, (_, i) => `SELECT '${'x'.repeat(400)}${i}'`);
		expect(admitBatch('mail', 'mail', BUDGET, huge.map((sql) => ({ sql })))).toMatchObject({
			kind: 'refused',
			reason: 'budget-exceeded',
		});
	});

	it('refuses transaction control and its valid aliases (parsed, not prefix-matched)', () => {
		for (const sql of [
			'BEGIN', 'BEGIN IMMEDIATE', 'START TRANSACTION', 'COMMIT', 'END TRANSACTION',
			'ROLLBACK', 'ROLLBACK TO SAVEPOINT s', 'SAVEPOINT s', 'RELEASE s',
		]) {
			expect(admitBatchStatement(sql, []).kind === 'refused'
				&& (admitBatchStatement(sql, []) as { reason: string }).reason === 'transaction-control',
			).toBe(true);
		}
		// Keywords inside strings/comments/identifiers are not transaction control.
		expect(admitBatchStatement("SELECT 'BEGIN' AS k", [])).toMatchObject({ kind: 'ok' });
		expect(admitBatchStatement('SELECT 1 -- begins here', [])).toMatchObject({ kind: 'ok' });
		expect(admitBatchStatement('SELECT "begin" AS k', [])).toMatchObject({ kind: 'ok' });
		expect(admitBatchStatement('/* BEGIN */ SELECT 1', [])).toMatchObject({ kind: 'ok' });
	});

	it('refuses multi-statement smuggling, DDL, pragma and attach', () => {
		expect(admitBatchStatement('SELECT 1; DELETE FROM optional_jobs', [])).toMatchObject({ kind: 'refused', reason: 'multi-statement' });
		expect(admitBatchStatement('CREATE TABLE evil (x)', [])).toMatchObject({ kind: 'refused', reason: 'forbidden-keyword' });
		expect(admitBatchStatement('DROP TABLE optional_jobs', [])).toMatchObject({ kind: 'refused', reason: 'forbidden-keyword' });
		expect(admitBatchStatement('ALTER TABLE messages ADD COLUMN x', [])).toMatchObject({ kind: 'refused', reason: 'forbidden-keyword' });
		expect(admitBatchStatement('PRAGMA journal_mode = WAL', [])).toMatchObject({ kind: 'refused', reason: 'forbidden-keyword' });
		expect(admitBatchStatement('ATTACH DATABASE ? AS other', [])).toMatchObject({ kind: 'refused', reason: 'forbidden-keyword' });
		expect(admitBatchStatement('DETACH other', [])).toMatchObject({ kind: 'refused', reason: 'forbidden-keyword' });
		expect(admitBatchStatement('VACUUM', [])).toMatchObject({ kind: 'refused', reason: 'forbidden-keyword' });
		expect(admitBatchStatement("SELECT 'x", [])).toMatchObject({ kind: 'refused', reason: 'unterminated-literal' });
	});

	it('ordinary exec/query entry parity matches the batch rules', () => {
		expect(admitOrdinaryStatement('SELECT * FROM messages WHERE id = ?')).toEqual({ kind: 'ok' });
		expect(admitOrdinaryStatement('BEGIN')).toMatchObject({ kind: 'refused', reason: 'transaction-control' });
		expect(admitOrdinaryStatement('UPDATE messages; UPDATE messages')).toMatchObject({ kind: 'refused', reason: 'multi-statement' });
	});

	it('tokenizer reports statement separators outside literals only', () => {
		expect(tokenizeStatement('SELECT 1').hasStatementSeparator).toBe(false);
		expect(tokenizeStatement("SELECT ';'").hasStatementSeparator).toBe(false);
		expect(tokenizeStatement('SELECT 1;').hasStatementSeparator).toBe(true);
		expect(tokenizeStatement('SELECT [col;name] FROM t').hasStatementSeparator).toBe(false);
		expect(tokenizeStatement('SELECT `tick;s` FROM t').hasStatementSeparator).toBe(false);
	});
});
