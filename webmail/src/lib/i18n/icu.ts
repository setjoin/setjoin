// i18n/icu.ts — minimal ICU MessageFormat parser.
// Supports: {name}, {count, plural, …}, {gender, select, …}
// No external dependencies — relies on built-in Intl.

/**
 * Format an ICU MessageFormat pattern with the given values.
 *
 * Supported syntax:
 *   {name}                           — simple variable substitution
 *   {count, plural, =0{…} one{…} other{…}}  — plural forms
 *   {gender, select, male{…} female{…} other{…}} — select forms
 */
export function formatMessage(pattern: string, values: Record<string, unknown>): string {
	return parseICU(pattern, values);
}

function parseICU(pattern: string, values: Record<string, unknown>): string {
	let result = '';
	let i = 0;

	while (i < pattern.length) {
		// Handle escaped braces: {{ → {  and }} → }
		if (pattern[i] === '{' && i + 1 < pattern.length && pattern[i + 1] === '{') {
			result += '{';
			i += 2;
			continue;
		}
		if (pattern[i] === '}' && i + 1 < pattern.length && pattern[i + 1] === '}') {
			result += '}';
			i += 2;
			continue;
		}

		if (pattern[i] === '{') {
			const end = findMatchingBrace(pattern, i + 1);
			if (end === pattern.length) {
				// Unmatched brace — treat as literal
				result += pattern[i];
				i++;
			} else {
				const body = pattern.substring(i + 1, end);
				result += resolveICUBody(body, values);
				i = end + 1;
			}
		} else {
			result += pattern[i];
			i++;
		}
	}

	return result;
}

/** Find the matching closing brace accounting for nesting. */
function findMatchingBrace(pattern: string, start: number): number {
	let depth = 1;
	let i = start;
	while (i < pattern.length && depth > 0) {
		if (pattern[i] === '{') depth++;
		else if (pattern[i] === '}') depth--;
		if (depth === 0) return i;
		i++;
	}
	return pattern.length; // unmatched
}

/** Resolve the body of a single ICU argument: key, key+type, or key+type+selectors. */
function resolveICUBody(body: string, values: Record<string, unknown>): string {
	const firstComma = body.indexOf(',');
	if (firstComma === -1) {
		// Simple variable: {name}
		const key = body.trim();
		return values[key] !== undefined ? String(values[key]) : `{${body}}`;
	}

	const key = body.substring(0, firstComma).trim();
	const rest = body.substring(firstComma + 1).trim();

	// Find the second comma (separates type from selectors)
	const secondComma = findNextCommaOutsideBraces(rest);
	const type = secondComma === -1 ? rest : rest.substring(0, secondComma).trim();
	const optionsStr = secondComma === -1 ? '' : rest.substring(secondComma + 1).trim();

	if (type === 'plural') {
		const selectors = parseSelectors(optionsStr);
		const count = toNumber(values[key]);
		return resolvePlural(count, selectors, values);
	}

	if (type === 'select') {
		const selectors = parseSelectors(optionsStr);
		const choice = values[key] !== undefined ? String(values[key]) : 'other';
		const text = selectors[choice] ?? selectors['other'];
		if (text === undefined) return `{${body}}`;
		return parseICU(text, values);
	}

	return `{${body}}`;
}

/** Find a comma that is not inside nested braces. */
function findNextCommaOutsideBraces(str: string): number {
	let depth = 0;
	for (let i = 0; i < str.length; i++) {
		if (str[i] === '{') depth++;
		else if (str[i] === '}') depth--;
		else if (str[i] === ',' && depth === 0) return i;
	}
	return -1;
}

/** Parse plural/select selector→text pairs from options string. */
function parseSelectors(str: string): Record<string, string> {
	const result: Record<string, string> = {};
	let i = 0;

	while (i < str.length) {
		// Skip whitespace
		while (i < str.length && str[i] === ' ') i++;
		if (i >= str.length) break;

		// Parse selector key
		let selector = '';
		if (str[i] === '=') {
			i++; // skip =
			while (i < str.length && isDigit(str[i])) {
				selector += str[i];
				i++;
			}
			selector = '=' + selector;
		} else {
			while (i < str.length && isWordChar(str[i])) {
				selector += str[i];
				i++;
			}
		}

		// Skip whitespace
		while (i < str.length && str[i] === ' ') i++;

		// Parse braced value
		if (i < str.length && str[i] === '{') {
			const end = findMatchingBrace(str, i + 1);
			const text = str.substring(i + 1, end);
			result[selector] = text;
			i = end + 1;
		} else {
			break; // malformed
		}
	}

	return result;
}

/** Resolve a plural choice based on numeric value. */
function resolvePlural(
	count: number,
	selectors: Record<string, string>,
	values: Record<string, unknown>,
): string {
	// Exact match takes priority
	const exactKey = '=' + count;
	if (selectors[exactKey] !== undefined) {
		return parseICU(substituteHash(selectors[exactKey], count), values);
	}

	// CLDR plural categories (English-style: one vs other)
	// For simplicity, we use "one" for 1, "other" for everything else
	const category = count === 1 ? 'one' : 'other';
	const text = selectors[category] ?? selectors['other'];
	if (text === undefined) return `{count, plural, …}`; // fallback
	return parseICU(substituteHash(text, count), values);
}

// ICU plural clauses use bare `#` as shorthand for the formatted count (e.g.
// "{count, plural, one{# item} other{# items}}"). Substitute BEFORE the
// recursive parseICU pass so a literal `#` never collides with `{name}`-style
// placeholders elsewhere in the same clause.
function substituteHash(text: string, count: number): string {
	return text.replace(/#/g, String(count));
}

function toNumber(value: unknown): number {
	if (typeof value === 'number') return value;
	if (typeof value === 'string') {
		const n = Number(value);
		return Number.isNaN(n) ? 0 : n;
	}
	return 0;
}

function isDigit(c: string): boolean {
	return c >= '0' && c <= '9';
}

function isWordChar(c: string): boolean {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c === '_';
}
