const PATTERNS: Record<string, RegExp[]> = {
	en: [/\battach(ed|ing|ment|ments)?\b/i, /\bsee\s+(the\s+)?attached\b/i, /\benclosed\b/i],
	zh: [/附件/, /附上/, /夹带/],
	de: [/\banbei\b/i, /\banhang\b/i, /\bangeh(ä|ae)ngt\b/i, /\bbeigef(ü|ue)gt\b/i],
};

/** True when the subject/body mentions an attachment but (caller checks) none is attached. */
export function mentionsAttachment(subject: string, body: string, locale: string): boolean {
	// Strip URLs so "…/attachments/…" paths don't trigger a false positive.
	const text = `${subject}\n${body}`.replace(/https?:\/\/\S+/gi, ' ');
	const localized = PATTERNS[locale];
	const patterns = localized && localized !== PATTERNS.en
		? [...localized, ...PATTERNS.en]
		: PATTERNS.en;
	return patterns.some((re) => re.test(text));
}
