import type { Mailbox } from '$lib/types/jmap';

export type SearchIntentFilter =
	| { kind: 'text'; value: string }
	| { kind: 'from' | 'to' | 'cc' | 'bcc' | 'subject'; value: string }
	| { kind: 'mailbox'; mailboxId: string; label: string }
	| { kind: 'keyword'; value: 'unread' | 'read' | 'starred' | 'draft' | 'answered' }
	| { kind: 'attachment'; value: true }
	| { kind: 'received'; op: 'before' | 'after'; value: string }
	| { kind: 'size'; op: 'larger' | 'smaller'; bytes: number };

export interface SearchIntent {
	version: 1;
	filters: SearchIntentFilter[];
	source: 'typed' | 'local-intent' | 'assist';
	confidence: 'exact' | 'review';
}

export interface SearchIntentPreview {
	intent: SearchIntent;
	raw: string;
	recognizedNaturalLanguage: boolean;
}

export class SearchIntentError extends Error {
	constructor(public readonly code: 'invalid' | 'unknown_mailbox' | 'impossible_range') {
		super(code);
	}
}

const MAX_QUERY_BYTES = 4096;
const MAX_FILTERS = 32;
const encoder = new TextEncoder();
const keywordValues = new Set(['unread', 'read', 'starred', 'draft', 'answered']);

function cleanValue(value: string): string {
	const cleaned = value.trim().replace(/^(["'])(.*)\1$/, '$2').trim();
	if (!cleaned || /[\u0000-\u001f\u007f]/.test(cleaned) || encoder.encode(cleaned).length > 512) {
		throw new SearchIntentError('invalid');
	}
	return cleaned;
}

function quoteValue(value: string, force = false): string {
	return force || /\s|["\\]/.test(value) ? JSON.stringify(value) : value;
}

function formatBytes(bytes: number): string {
	for (const [unit, size] of [['G', 1024 ** 3], ['M', 1024 ** 2], ['K', 1024]] as const) {
		if (bytes >= size && bytes % size === 0) return `${bytes / size}${unit}`;
	}
	return String(bytes);
}

function dedupe(filters: SearchIntentFilter[]): SearchIntentFilter[] {
	const keyed = new Map<string, SearchIntentFilter>();
	for (const filter of filters) {
		const key = filter.kind === 'received' || filter.kind === 'size'
			? `${filter.kind}:${filter.op}`
			: filter.kind;
		keyed.set(key, filter);
	}
	return [...keyed.values()];
}

export function compileSearchIntent(intent: SearchIntent, mailboxes: Mailbox[]): string {
	if (intent.version !== 1 || intent.filters.length > MAX_FILTERS) throw new SearchIntentError('invalid');
	const filters = dedupe(intent.filters);
	const before = filters.find((f): f is Extract<SearchIntentFilter, { kind: 'received' }> => f.kind === 'received' && f.op === 'before');
	const after = filters.find((f): f is Extract<SearchIntentFilter, { kind: 'received' }> => f.kind === 'received' && f.op === 'after');
	if (before && after && Date.parse(after.value) >= Date.parse(before.value)) {
		throw new SearchIntentError('impossible_range');
	}

	const parts = filters.map((filter) => {
		switch (filter.kind) {
			// Free text must re-enter the grammar as a literal, never as a
			// constraint (canonicalization/reparse invariant): a no-space token
			// like `older:7d` would otherwise serialize unquoted and re-parse as
			// an operator. Force-quoting keeps the canonical form narrowing-only.
			case 'text': {
				const value = cleanValue(filter.value);
				return quoteValue(value, /^[a-z_]+:/.test(value));
			}
			case 'from': case 'to': case 'cc': case 'bcc': case 'subject':
				return `${filter.kind}:${quoteValue(cleanValue(filter.value))}`;
			case 'mailbox': {
				const mailbox = mailboxes.find((candidate) => candidate.id === filter.mailboxId);
				if (!mailbox) throw new SearchIntentError('unknown_mailbox');
				return `in:${quoteValue(mailbox.name)}`;
			}
			case 'keyword':
				if (!keywordValues.has(filter.value)) throw new SearchIntentError('invalid');
				return `is:${filter.value}`;
			case 'attachment': return 'has:attachment';
			case 'received': {
				const value = cleanValue(filter.value);
				if (!Number.isFinite(Date.parse(value))) throw new SearchIntentError('invalid');
				return `${filter.op}:${quoteValue(value)}`;
			}
			case 'size':
				if (!Number.isSafeInteger(filter.bytes) || filter.bytes < 0 || filter.bytes > 1024 ** 4) {
					throw new SearchIntentError('invalid');
				}
				return `${filter.op}:${formatBytes(filter.bytes)}`;
			default:
				// Fail closed on unknown filter kinds — an unvalidated entry must be
				// rejected, never silently dropped into a broader (match-all) query.
				throw new SearchIntentError('invalid');
		}
	});
	const raw = parts.join(' ');
	if (encoder.encode(raw).length > MAX_QUERY_BYTES) throw new SearchIntentError('invalid');
	return raw;
}

function resolveMailbox(label: string, mailboxes: Mailbox[]): SearchIntentFilter {
	const cleaned = cleanValue(label);
	const mailbox = mailboxes.find((candidate) => candidate.name.localeCompare(cleaned, undefined, { sensitivity: 'accent' }) === 0);
	if (!mailbox) throw new SearchIntentError('unknown_mailbox');
	return { kind: 'mailbox', mailboxId: mailbox.id, label: mailbox.name };
}

function parseSize(value: string, unit: string | undefined): number {
	const number = Number(value);
	const multiplier = ({ k: 1024, kb: 1024, m: 1024 ** 2, mb: 1024 ** 2, g: 1024 ** 3, gb: 1024 ** 3 } as Record<string, number>)[unit?.toLowerCase() ?? ''] ?? 1;
	const bytes = Math.round(number * multiplier);
	if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > 1024 ** 4) throw new SearchIntentError('invalid');
	return bytes;
}

/** Tokenize raw operator syntax while preserving quoted values containing spaces. */
export function tokenizeSearch(raw: string): string[] {
	return raw.match(/(?:[^\s"']+|"(?:\\.|[^"\\])*"|'[^']*')+/g) ?? [];
}

export function intentFromTypedSearch(raw: string, mailboxes: Mailbox[]): SearchIntent {
	if (encoder.encode(raw).length > MAX_QUERY_BYTES || /[\u0000-\u001f\u007f]/.test(raw)) throw new SearchIntentError('invalid');
	const filters: SearchIntentFilter[] = [];
	const text: string[] = [];
	for (const token of tokenizeSearch(raw.trim())) {
		const match = token.match(/^([a-z_]+):(.*)$/i);
		if (!match) { text.push(cleanValue(token)); continue; }
		const key = match[1].toLowerCase();
		const value = cleanValue(match[2]);
		if (['from', 'to', 'cc', 'bcc', 'subject'].includes(key)) {
			filters.push({ kind: key as 'from' | 'to' | 'cc' | 'bcc' | 'subject', value });
		} else if (['tag', 'in', 'label'].includes(key)) {
			filters.push(resolveMailbox(value, mailboxes));
		} else if (key === 'has' && value.toLowerCase() === 'attachment') {
			filters.push({ kind: 'attachment', value: true });
		} else if (key === 'is' && keywordValues.has(value.toLowerCase())) {
			filters.push({ kind: 'keyword', value: value.toLowerCase() as Extract<SearchIntentFilter, { kind: 'keyword' }>['value'] });
		} else if (['before', 'after'].includes(key)) {
			filters.push({ kind: 'received', op: key as 'before' | 'after', value });
		} else if (['larger', 'smaller'].includes(key)) {
			const size = value.match(/^(\d+(?:\.\d+)?)([kmgt]?b?)$/i);
			if (!size) text.push(token); else filters.push({ kind: 'size', op: key as 'larger' | 'smaller', bytes: parseSize(size[1], size[2]) });
		} else {
			text.push(token);
		}
	}
	if (text.length) filters.push({ kind: 'text', value: text.join(' ') });
	return { version: 1, filters: dedupe(filters), source: 'typed', confidence: 'exact' };
}

type MatchHandler = (match: string[]) => SearchIntentFilter;

function consume(source: string, pattern: RegExp, handler: MatchHandler, filters: SearchIntentFilter[]): { source: string; matched: boolean } {
	let matched = false;
	const next = source.replace(pattern, (...args: unknown[]) => {
		const match = args.slice(0, -2) as string[];
		filters.push(handler(match));
		matched = true;
		return ' ';
	});
	return { source: next, matched };
}

/** Bounded, deterministic EN/ZH grammar. Unrecognized text is preserved verbatim. */
export function intentFromLocalLanguage(raw: string, mailboxes: Mailbox[], locale: string): SearchIntentPreview {
	if (encoder.encode(raw).length > MAX_QUERY_BYTES || /[\u0000-\u001f\u007f]/.test(raw)) throw new SearchIntentError('invalid');
	let source = raw.trim();
	const filters: SearchIntentFilter[] = [];
	let recognized = false;
	const apply = (pattern: RegExp, handler: MatchHandler) => {
		const result = consume(source, pattern, handler, filters);
		source = result.source;
		recognized ||= result.matched;
	};

	if (locale.toLowerCase().startsWith('zh')) {
		apply(/有附件/g, () => ({ kind: 'attachment', value: true }));
		apply(/(未读|已读|星标|草稿|已回复)/g, (m) => ({ kind: 'keyword', value: ({ 未读: 'unread', 已读: 'read', 星标: 'starred', 草稿: 'draft', 已回复: 'answered' } as const)[m[1] as '未读' | '已读' | '星标' | '草稿' | '已回复'] }));
		apply(/来自\s*([^\s，。]+)/g, (m) => ({ kind: 'from', value: cleanValue(m[1]) }));
		apply(/发给\s*([^\s，。]+)/g, (m) => ({ kind: 'to', value: cleanValue(m[1]) }));
		apply(/主题(?:是|为|:)\s*([^，。]+)/g, (m) => ({ kind: 'subject', value: cleanValue(m[1]) }));
		apply(/(?:在|位于)(?:邮箱|标签)?\s*([^\s，。]+)(?:里|中)?/g, (m) => resolveMailbox(m[1].replace(/[里中]$/, ''), mailboxes));
		apply(/(\d+(?:\.\d+)?)\s*(KB|MB|GB|K|M|G)?\s*(以上|更大|大于)/gi, (m) => ({ kind: 'size', op: 'larger', bytes: parseSize(m[1], m[2]) }));
		apply(/(\d+(?:\.\d+)?)\s*(KB|MB|GB|K|M|G)?\s*(以下|更小|小于)/gi, (m) => ({ kind: 'size', op: 'smaller', bytes: parseSize(m[1], m[2]) }));
		apply(/(\d{4}-\d{2}-\d{2})\s*之前/g, (m) => ({ kind: 'received', op: 'before', value: m[1] }));
		apply(/(\d{4}-\d{2}-\d{2})\s*之后/g, (m) => ({ kind: 'received', op: 'after', value: m[1] }));
	} else {
		apply(/\bwith attachments?\b/gi, () => ({ kind: 'attachment', value: true }));
		apply(/\b(unread|read|starred|draft|answered)\b/gi, (m) => ({ kind: 'keyword', value: m[1].toLowerCase() as Extract<SearchIntentFilter, { kind: 'keyword' }>['value'] }));
		apply(/\bfrom\s+("[^"]+"|'[^']+'|\S+)/gi, (m) => ({ kind: 'from', value: cleanValue(m[1]) }));
		apply(/\bto\s+("[^"]+"|'[^']+'|\S+)/gi, (m) => ({ kind: 'to', value: cleanValue(m[1]) }));
		apply(/\bsubject\s+("[^"]+"|'[^']+'|\S+)/gi, (m) => ({ kind: 'subject', value: cleanValue(m[1]) }));
		apply(/\b(?:in|under)\s+(?:mailbox\s+|label\s+)?("[^"]+"|'[^']+'|\S+)/gi, (m) => resolveMailbox(m[1], mailboxes));
		apply(/\b(?:larger|bigger) than\s+(\d+(?:\.\d+)?)\s*(KB|MB|GB|K|M|G)?\b/gi, (m) => ({ kind: 'size', op: 'larger', bytes: parseSize(m[1], m[2]) }));
		apply(/\bsmaller than\s+(\d+(?:\.\d+)?)\s*(KB|MB|GB|K|M|G)?\b/gi, (m) => ({ kind: 'size', op: 'smaller', bytes: parseSize(m[1], m[2]) }));
		apply(/\bbefore\s+(\d{4}-\d{2}-\d{2})\b/gi, (m) => ({ kind: 'received', op: 'before', value: m[1] }));
		apply(/\bafter\s+(\d{4}-\d{2}-\d{2})\b/gi, (m) => ({ kind: 'received', op: 'after', value: m[1] }));
	}

	const remainder = source.replace(/\s+/g, ' ').replace(/^[\s,，。]+|[\s,，。]+$/g, '');
	if (remainder) filters.push({ kind: 'text', value: remainder });
	const intent: SearchIntent = {
		version: 1,
		filters: dedupe(filters),
		source: recognized ? 'local-intent' : 'typed',
		confidence: recognized ? 'review' : 'exact',
	};
	return { intent, raw: compileSearchIntent(intent, mailboxes), recognizedNaturalLanguage: recognized };
}

export function buildSearchIntentPreview(raw: string, mailboxes: Mailbox[], locale: string): SearchIntentPreview {
	const explicit = tokenizeSearch(raw).some((token) => /^(from|to|cc|bcc|subject|tag|in|label|has|is|before|after|larger|smaller):/i.test(token));
	if (explicit) {
		const intent = intentFromTypedSearch(raw, mailboxes);
		return { intent, raw: compileSearchIntent(intent, mailboxes), recognizedNaturalLanguage: false };
	}
	return intentFromLocalLanguage(raw, mailboxes, locale);
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
	return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Closed per-entry validation for an Assist-declared filter (fail-closed):
 * each entry must match the declared `SearchIntentFilter` union exactly.
 * Unknown kinds, missing/mistyped fields, or out-of-domain values are rejected
 * with `SearchIntentError` — never coerced, silently dropped, or escaped as a
 * raw TypeError.
 */
function parseAssistFilter(entry: unknown): SearchIntentFilter {
	if (!isPlainObject(entry) || typeof entry.kind !== 'string') throw new SearchIntentError('invalid');
	const { kind, op, value, mailboxId, label, bytes } = entry;
	switch (kind) {
		case 'text':
		case 'from': case 'to': case 'cc': case 'bcc': case 'subject':
			if (typeof value !== 'string') throw new SearchIntentError('invalid');
			return { kind, value };
		case 'mailbox':
			if (typeof mailboxId !== 'string' || typeof label !== 'string') throw new SearchIntentError('invalid');
			return { kind, mailboxId, label };
		case 'keyword':
			if (typeof value !== 'string' || !keywordValues.has(value)) throw new SearchIntentError('invalid');
			return { kind, value: value as Extract<SearchIntentFilter, { kind: 'keyword' }>['value'] };
		case 'attachment':
			if (value !== true) throw new SearchIntentError('invalid');
			return { kind, value: true };
		case 'received':
			if ((op !== 'before' && op !== 'after') || typeof value !== 'string') throw new SearchIntentError('invalid');
			return { kind, op, value };
		case 'size': {
			if ((op !== 'larger' && op !== 'smaller') || !Number.isSafeInteger(bytes) || (bytes as number) < 0 || (bytes as number) > 1024 ** 4) {
				throw new SearchIntentError('invalid');
			}
			// Number.isSafeInteger narrows only at runtime — assert the number
			// the guard just proved.
			return { kind, op, bytes: bytes as number };
		}
		default:
			throw new SearchIntentError('invalid');
	}
}

/** Validate an optional Assist response locally before it can reach Email/query. */
export function validateAssistIntent(value: unknown, mailboxes: Mailbox[]): SearchIntent {
	if (!isPlainObject(value)) throw new SearchIntentError('invalid');
	const candidate = value as Partial<SearchIntent>;
	if (candidate.version !== 1 || candidate.source !== 'assist' || !Array.isArray(candidate.filters)) {
		throw new SearchIntentError('invalid');
	}
	const intent: SearchIntent = {
		version: 1,
		source: 'assist',
		confidence: 'review',
		filters: candidate.filters.map(parseAssistFilter),
	};
	const compiled = compileSearchIntent(intent, mailboxes);
	// Fail closed on garbage-only intents: an empty canonical query would be a
	// silent match-all, never an acceptable reading of an Assist response.
	if (!compiled.trim()) throw new SearchIntentError('invalid');
	return intent;
}
