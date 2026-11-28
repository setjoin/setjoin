// ARCH-004 — render a directory/GAL person's FULL address set on their card.
//
// The directory/GAL reducers (gal_search / directory_members / directory_search)
// now return a person's whole address set under `addresses`: the union of
// `users.email` (primary), `aliases.email` (every alias on their mailboxes), and
// `users.ad_upn` (UPN), deduplicated case-insensitively with the primary first.
//
// These pure helpers shape that array for display so DirectoryMemberList and the
// GAL card render identically. No business logic — the server owns the set; this
// only orders/partitions it for the UI.
import type { DirectoryAddress } from '$lib/types/jmap';

export interface NormalizedAddresses {
	/** The person's primary address (falls back to the first entry, then ''). */
	primary: string;
	/** Every address except the primary, in server order (aliases then UPN). */
	secondary: DirectoryAddress[];
	/** True when the person has more than one address (so the card shows the set). */
	hasMultiple: boolean;
}

/**
 * Normalize a directory/GAL person's address set for the card.
 *
 * Deduplicates case-insensitively (the server already does, but a stray duplicate
 * — e.g. a primary that also appears as an alias — must never render twice),
 * keeps the primary first, and partitions the rest as `secondary`. A bare
 * `primaryFallback` (the legacy single `email` field) is used when `addresses`
 * is absent or empty, so GAL cards from older payloads still render.
 */
export function normalizeAddresses(
	addresses: DirectoryAddress[] | undefined,
	primaryFallback?: string | null
): NormalizedAddresses {
	const seen = new Set<string>();
	const deduped: DirectoryAddress[] = [];
	for (const a of addresses ?? []) {
		const email = (a?.email ?? '').trim();
		if (!email) continue;
		const key = email.toLowerCase();
		if (seen.has(key)) continue;
		seen.add(key);
		deduped.push({ email, type: a.type, isPrimary: a.isPrimary });
	}

	// Primary first: an explicit isPrimary wins; otherwise the first entry.
	const primaryIdx = deduped.findIndex((a) => a.isPrimary);
	let primary = '';
	let secondary: DirectoryAddress[] = [];
	if (deduped.length > 0) {
		const idx = primaryIdx >= 0 ? primaryIdx : 0;
		primary = deduped[idx].email;
		secondary = deduped.filter((_, i) => i !== idx);
	} else if (primaryFallback && primaryFallback.trim()) {
		primary = primaryFallback.trim();
	}

	return { primary, secondary, hasMultiple: secondary.length > 0 };
}

/** i18n label key for a secondary address kind (alias / UPN). */
export function addressKindKey(type: DirectoryAddress['type']): string {
	return type === 'upn' ? 'directory.address.upn' : 'directory.address.alias';
}
