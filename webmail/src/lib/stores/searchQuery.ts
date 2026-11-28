import type { Mailbox } from '$lib/types/jmap';
import { tokenizeSearch } from '$lib/search/searchIntent';

/**
 * JMAP Email/query filter conditions produced by the search-operator parser.
 * Keys mirror the JMAP Email/query filter properties the `jmap_email_query`
 * reducer already accepts (from/to/cc/bcc/subject substring, hasAttachment,
 * hasKeyword, before/after on receivedAt, minSize/maxSize bytes, inMailbox, text FTS).
 */
export interface SearchFilter {
	text?: string;
	from?: string;
	to?: string;
	cc?: string;
	bcc?: string;
	subject?: string;
	inMailbox?: string;
	hasAttachment?: boolean;
	hasKeyword?: string;
	before?: string;
	after?: string;
	minSize?: number;
	maxSize?: number;
}

/**
 * Sentinel mailbox id returned when a `tag:` operator refers to a tag that does
 * not exist. Using this id ensures the resulting JMAP query returns zero messages
 * rather than all messages (which would happen if `inMailbox` were omitted).
 */
export const NO_MATCH_SENTINEL = '__no_match__';

function unquote(value: string): string {
	if (value.startsWith('"') && value.endsWith('"')) {
		try { return JSON.parse(value) as string; } catch { return value.slice(1, -1); }
	}
	if (value.startsWith("'") && value.endsWith("'")) return value.slice(1, -1);
	return value;
}

// `is:<x>` → the reducer's hasKeyword value. Unknown values are ignored.
const KEYWORD_MAP: Record<string, string> = {
	unread: '$unseen',
	read: '$seen',
	starred: '$flagged',
	flagged: '$flagged',
	draft: '$draft',
	answered: '$answered',
};

// `key:value` operators whose value is copied straight through as a substring match.
const PASSTHROUGH = ['from', 'to', 'cc', 'bcc', 'subject'] as const;
type PassKey = (typeof PASSTHROUGH)[number];

// Parse an absolute date (`2026-01-01`, passed through — Postgres casts it to
// timestamptz) or a relative age (`7d`/`2w`/`3m`/`1y`) into an ISO instant N ago.
function parseDate(value: string): string | null {
	const rel = value.match(/^(\d+)([dwmy])$/i);
	if (rel) {
		const days = { d: 1, w: 7, m: 30, y: 365 }[rel[2].toLowerCase()] ?? 1;
		return new Date(Date.now() - parseInt(rel[1], 10) * days * 86400_000).toISOString();
	}
	return value || null;
}

// Parse a size like `5M`/`500K`/`2G` (optional leading `<`/`>`) into bytes.
// ponytail: 1024-based; flip to 1000 if we ever mirror Gmail's suffix convention exactly.
function parseSize(value: string): number | null {
	const m = value.replace(/^[<>]/, '').match(/^(\d+(?:\.\d+)?)([kmg])?b?$/i);
	if (!m) return null;
	const mult = { k: 1024, m: 1024 ** 2, g: 1024 ** 3 }[(m[2] || '').toLowerCase()] ?? 1;
	return Math.round(parseFloat(m[1]) * mult);
}

/**
 * Parse a raw search query string into a JMAP Email/query filter object.
 *
 * Grammar (whitespace-separated `key:value` operators; unmatched words are text):
 *   `tag:`/`in:`/`label:<name>` — resolve `<name>` (case-insensitive) to a mailbox
 *                    id → `inMailbox`, or `__no_match__` if unknown.
 *   `from:`/`to:`/`cc:`/`bcc:`/`subject:<v>` — substring match on that field.
 *   `has:attachment`               — `hasAttachment`.
 *   `is:unread|read|starred|flagged|draft|answered` — maps to `hasKeyword`.
 *   `before:`/`after:`/`older(_than):`/`newer(_than):<date|Nd>` — receivedAt bounds.
 *   `larger:`/`smaller:`/`size:<5M>` — `minSize`/`maxSize` in bytes.
 *   bare words + `"quoted phrase"` — joined as `text` (FTS; the reducer's
 *                    websearch_to_tsquery honours the quotes server-side).
 *
 * Later duplicate operators overwrite earlier ones (last wins). Empty → `{}`.
 * An unrecognised `key:value` token is treated as bare text (not silently dropped).
 */
export function parseSearch(raw: string, mailboxes: Mailbox[]): SearchFilter {
	const trimmed = raw.trim();
	if (!trimmed) return {};

	const tokens = tokenizeSearch(trimmed);
	const filter: SearchFilter = {};
	const bareWords: string[] = [];

	for (const token of tokens) {
		const op = token.match(/^([a-z_]+):(.+)$/i);
		if (!op) {
			bareWords.push(token);
			continue;
		}
		const key = op[1].toLowerCase();
		const value = unquote(op[2]);

		if (key === 'tag' || key === 'in' || key === 'label') {
			const resolved = mailboxes.find((m) => m.name.toLowerCase() === value.toLowerCase());
			filter.inMailbox = resolved ? resolved.id : NO_MATCH_SENTINEL;
		} else if ((PASSTHROUGH as readonly string[]).includes(key)) {
			filter[key as PassKey] = value;
		} else if (key === 'has') {
			if (value.toLowerCase() === 'attachment') filter.hasAttachment = true;
			else bareWords.push(token);
		} else if (key === 'is') {
			const kw = KEYWORD_MAP[value.toLowerCase()];
			if (kw) filter.hasKeyword = kw;
			else bareWords.push(token);
		} else if (key === 'before' || key === 'older' || key === 'older_than') {
			const d = parseDate(value);
			if (d) filter.before = d;
		} else if (key === 'after' || key === 'newer' || key === 'newer_than') {
			const d = parseDate(value);
			if (d) filter.after = d;
		} else if (key === 'larger' || key === 'size') {
			const b = parseSize(value);
			if (b !== null) filter.minSize = b;
		} else if (key === 'smaller') {
			const b = parseSize(value);
			if (b !== null) filter.maxSize = b;
		} else {
			// Unknown operator — keep the raw token as text rather than dropping it.
			bareWords.push(token);
		}
	}

	if (bareWords.length > 0) {
		filter.text = bareWords.join(' ');
	}

	return filter;
}
