/**
 * Native-batch admission edge branches (coverage round r2).
 *
 * Structural tokenizer behavior the main suites leave cold: escaped quote
 * doubling inside literals, unterminated bracket identifiers, unknown
 * leading keywords, comment-only statements, malformed batch entries, the
 * capability probe's false arm, and executeBatch's fail-closed refusal on a
 * shell that lacks the atomic batch entry.
 */

import { describe, it, expect } from 'vitest';

import {
	admitBatch,
	admitBatchStatement,
	admitOrdinaryStatement,
	executeBatch,
	nativeBatchAvailable,
	DEFAULT_BATCH_BUDGET,
} from './nativeBatch';
import type { OfflineDbBridge } from '$lib/native/types';

describe('tokenizer structural edges', () => {
	it('an escaped (doubled) quote inside a literal does not end the literal', () => {
		// SQLite escapes a quote by doubling it: 'it''s' is ONE literal.
		const decision = admitBatchStatement("UPDATE t SET c = 'it''s ok'", []);
		expect(decision.kind).toBe('ok');
		// A doubled quote does not leak the keyword scan into literal content.
		expect(admitOrdinaryStatement("SELECT 'begin''commit'")).toEqual({ kind: 'ok' });
	});

	it('an unterminated bracket identifier is an unterminated literal refusal', () => {
		expect(admitBatchStatement('SELECT [col FROM t', [])).toEqual({
			kind: 'refused',
			reason: 'unterminated-literal',
			detail: 'unterminated-literal',
		});
	});

	it('a leading keyword outside every known set is refused as forbidden', () => {
		expect(admitBatchStatement('EXPLAIN SELECT 1', [])).toEqual({
			kind: 'refused',
			reason: 'forbidden-keyword',
			detail: 'keyword=explain',
		});
	});

	it('a comment-only statement has no leading keyword and is refused', () => {
		expect(admitBatchStatement('-- nothing but a comment', [])).toEqual({
			kind: 'refused',
			reason: 'forbidden-keyword',
			detail: 'empty-statement',
		});
	});
});

describe('batch admission and execution edges', () => {
	it('refuses a batch holding a malformed entry before any statement runs', () => {
		const decision = admitBatch('mail', 'mail', DEFAULT_BATCH_BUDGET, [
			{ sql: 'SELECT 1' },
			null as never,
		]);
		expect(decision).toEqual({
			kind: 'refused',
			reason: 'forbidden-keyword',
			detail: 'statement=1 shape',
		});
	});

	it('nativeBatchAvailable is false on a shell without the atomic entry', () => {
		const bare = { query: async () => [] } as unknown as OfflineDbBridge;
		expect(nativeBatchAvailable(bare)).toBe(false);
	});

	it('executeBatch refuses a capable-admission batch on a shell without the entry', async () => {
		const bare = { query: async () => [] } as unknown as OfflineDbBridge;
		await expect(
			executeBatch(bare, 'mail', [{ sql: 'SELECT 1' }]),
		).rejects.toThrow(/unavailable-entry/);
	});
});
