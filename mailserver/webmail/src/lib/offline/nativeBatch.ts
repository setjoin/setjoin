/**
 * E4-I TS-side admission for the native atomic batch entry
 * (`OfflineDbBridge.transactionBatch`) and the ordinary exec/query statement
 * contract.
 *
 * Authority: retired-docs:verification/2026-09-08-connectivity-native-transaction-freeze.md.
 * Native owns the engine-level authorization; this module is the fail-closed
 * TS pre-admission that rejects before mutation, so a malformed or smuggled
 * payload never reaches the bridge and partial batch admission is not
 * permitted. Transaction control is detected by tokenizing statement text
 * (strings, quoted identifiers and comments stripped) and matching statement
 * keywords — never by naive string-prefix matching.
 */

import type { NativeBatchBudget, NativeBatchStatement, NativeDbAppKey, OfflineDbBridge } from '$lib/native/types';

/** Default bounded budget for one coordinator job batch. */
export const DEFAULT_BATCH_BUDGET: NativeBatchBudget = {
	maxStatements: 64,
	maxParamBytes: 1_048_576,
};

export type BatchRefusalReason =
	| 'foreign-app-handle'
	| 'empty-batch'
	| 'too-many-statements'
	| 'budget-exceeded'
	| 'multi-statement'
	| 'transaction-control'
	| 'forbidden-keyword'
	| 'unterminated-literal'
	| 'unavailable-entry';

export interface BatchRefusal {
	kind: 'refused';
	reason: BatchRefusalReason;
	/** Finite refusal identity — never raw input or content. */
	detail: string;
}

export interface BatchAdmitted {
	kind: 'admitted';
	statementCount: number;
	paramBytes: number;
}

export type BatchDecision = BatchAdmitted | BatchRefusal;

/** Parameterized read/DML keywords allowed inside a job batch. */
const ALLOWED_LEADING_KEYWORDS = new Set([
	'select',
	'insert',
	'update',
	'delete',
	'replace',
	'with',
	'values',
]);

/** Transaction-control leading keywords and their valid aliases (SQLite). */
const TRANSACTION_CONTROL_KEYWORDS = new Set([
	'begin',
	'commit',
	'end',
	'rollback',
	'savepoint',
	'release',
	'start',
	'abort',
]);

/** Everything else non-DML (DDL, pragmas, attach, vacuum, admin) is refused. */
const NAMED_CONTROL_KEYWORDS = new Set([
	'pragma',
	'attach',
	'detach',
	'vacuum',
	'analyze',
	'reindex',
	'create',
	'drop',
	'alter',
	'grant',
	'revoke',
]);

interface TokenizedStatement {
	leadingKeyword: string | null;
	hasStatementSeparator: boolean;
	unterminated: boolean;
}

/**
 * Strip string literals, quoted identifiers and comments, then report the
 * leading keyword and whether a statement separator or unterminated literal
 * remains. This is structural tokenization, not string-prefix matching.
 */
export function tokenizeStatement(sql: string): TokenizedStatement {
	let leadingKeyword: string | null = null;
	let seenContent = false;
	let hasStatementSeparator = false;
	let unterminated = false;
	let i = 0;
	const isIdentChar = (ch: string) => /[A-Za-z0-9_$]/.test(ch);
	while (i < sql.length) {
		const ch = sql[i];
		if (ch === "'" || ch === '"' || ch === '`') {
			const quote = ch;
			seenContent = true;
			i += 1;
			let closed = false;
			while (i < sql.length) {
				if (sql[i] === quote) {
					if (sql[i + 1] === quote) {
						i += 2;
						continue;
					}
					i += 1;
					closed = true;
					break;
				}
				i += 1;
			}
			if (!closed) unterminated = true;
			continue;
		}
		if (ch === '[') {
			seenContent = true;
			i += 1;
			let closed = false;
			while (i < sql.length) {
				if (sql[i] === ']') {
					i += 1;
					closed = true;
					break;
				}
				i += 1;
			}
			if (!closed) unterminated = true;
			continue;
		}
		if (ch === '-' && sql[i + 1] === '-') {
			while (i < sql.length && sql[i] !== '\n') i += 1;
			continue;
		}
		if (ch === '/' && sql[i + 1] === '*') {
			i += 2;
			while (i < sql.length && !(sql[i] === '*' && sql[i + 1] === '/')) i += 1;
			i += 2;
			continue;
		}
		if (ch === ';') {
			// Only a separator if it does not sit inside an identifier token.
			hasStatementSeparator = true;
			i += 1;
			continue;
		}
		if (/\s/.test(ch)) {
			i += 1;
			continue;
		}
		if (isIdentChar(ch)) {
			let j = i;
			while (j < sql.length && isIdentChar(sql[j])) j += 1;
			if (!seenContent) {
				leadingKeyword = sql.slice(i, j).toLowerCase();
				seenContent = true;
			}
			i = j;
			continue;
		}
		seenContent = true;
		i += 1;
	}
	return { leadingKeyword, hasStatementSeparator, unterminated };
}

function utf8ByteLength(value: unknown): number {
	if (value === null || value === undefined) return 0;
	if (typeof value === 'string') {
		return new TextEncoder().encode(value).length;
	}
	return new TextEncoder().encode(JSON.stringify(value)).length;
}

function classifyLeadingKeyword(keyword: string): BatchRefusalReason | null {
	if (ALLOWED_LEADING_KEYWORDS.has(keyword)) return null;
	if (TRANSACTION_CONTROL_KEYWORDS.has(keyword)) return 'transaction-control';
	if (NAMED_CONTROL_KEYWORDS.has(keyword)) return 'forbidden-keyword';
	return 'forbidden-keyword';
}

/** Validate one statement against the job-batch admission contract. */
export function admitBatchStatement(
	sql: string,
	params: readonly unknown[] | undefined,
): BatchRefusal | { kind: 'ok'; bytes: number } {
	const tokenized = tokenizeStatement(sql);
	if (tokenized.unterminated) {
		return { kind: 'refused', reason: 'unterminated-literal', detail: 'unterminated-literal' };
	}
	if (tokenized.hasStatementSeparator) {
		return { kind: 'refused', reason: 'multi-statement', detail: 'statement-separator' };
	}
	if (tokenized.leadingKeyword === null) {
		return { kind: 'refused', reason: 'forbidden-keyword', detail: 'empty-statement' };
	}
	const refusal = classifyLeadingKeyword(tokenized.leadingKeyword);
	if (refusal !== null) {
		return { kind: 'refused', reason: refusal, detail: `keyword=${tokenized.leadingKeyword}` };
	}
	return { kind: 'ok', bytes: utf8ByteLength(sql) + utf8ByteLength(params ?? []) };
}

/** Validate a whole batch against the admission contract. */
export function admitBatch(
	authorizedAppKey: NativeDbAppKey,
	appKey: NativeDbAppKey,
	budget: NativeBatchBudget,
	statements: readonly NativeBatchStatement[],
): BatchDecision {
	if (appKey !== authorizedAppKey) {
		return { kind: 'refused', reason: 'foreign-app-handle', detail: `appKey=${appKey}` };
	}
	if (!Array.isArray(statements) || statements.length === 0) {
		return { kind: 'refused', reason: 'empty-batch', detail: 'empty-batch' };
	}
	if (statements.length > budget.maxStatements) {
		return { kind: 'refused', reason: 'too-many-statements', detail: `count=${statements.length}` };
	}
	let totalBytes = 0;
	for (const [index, statement] of statements.entries()) {
		if (statement === null || typeof statement !== 'object' || typeof statement.sql !== 'string') {
			return { kind: 'refused', reason: 'forbidden-keyword', detail: `statement=${index} shape` };
		}
		const decision = admitBatchStatement(statement.sql, statement.params);
		if (decision.kind === 'refused') {
			return {
				kind: 'refused',
				reason: decision.reason,
				detail: `statement=${index} ${decision.detail}`,
			};
		}
		totalBytes += decision.bytes;
		if (totalBytes > budget.maxParamBytes) {
			return {
				kind: 'refused',
				reason: 'budget-exceeded',
				detail: `bytes=${totalBytes} statement=${index}`,
			};
		}
	}
	return { kind: 'admitted', statementCount: statements.length, paramBytes: totalBytes };
}

/** True when the bridge exposes the E4-I native atomic batch entry. */
export function nativeBatchAvailable(db: OfflineDbBridge): boolean {
	return typeof db.transactionBatch === 'function';
}

/**
 * Validate, then execute one bounded atomic batch. Rejection occurs before
 * mutation; the bridge either commits the entire batch or applies nothing.
 */
export async function executeBatch(
	db: OfflineDbBridge,
	authorizedAppKey: NativeDbAppKey,
	statements: readonly NativeBatchStatement[],
	budget: NativeBatchBudget = DEFAULT_BATCH_BUDGET,
): Promise<number> {
	const decision = admitBatch(authorizedAppKey, authorizedAppKey, budget, statements);
	if (decision.kind === 'refused') {
		throw new Error(`native batch refused: ${decision.reason} (${decision.detail})`);
	}
	if (typeof db.transactionBatch !== 'function') {
		throw new Error('native batch refused: unavailable-entry (shell lacks transactionBatch)');
	}
	return db.transactionBatch(authorizedAppKey, statements, budget);
}

/**
 * Ordinary exec/query statement parity check: the same tokenizer rejects
 * transaction control, multi-statement payloads and forbidden keywords for
 * single-statement entry points. Structural guarantee that a job caller
 * cannot reach transaction control through any TS-side statement assembly.
 */
export function admitOrdinaryStatement(sql: string): BatchRefusal | { kind: 'ok' } {
	const decision = admitBatchStatement(sql, []);
	if (decision.kind === 'refused') {
		return { kind: 'refused', reason: decision.reason, detail: decision.detail };
	}
	return { kind: 'ok' };
}
