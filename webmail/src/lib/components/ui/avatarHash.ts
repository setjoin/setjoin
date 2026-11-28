/**
 * Deterministic avatar hue + initials, ported 1:1 from the reference design
 * system. Same person must get the same color on every client (web, desktop,
 * mobile) — do not change this algorithm.
 */

/** The 8 avatar hues: the tag dot colors with --indigo-500 replacing gray. */
export const AVATAR_HUES = [
	'var(--tag-blue-dot)',
	'var(--tag-teal-dot)',
	'var(--tag-green-dot)',
	'var(--tag-amber-dot)',
	'var(--tag-orange-dot)',
	'var(--tag-rose-dot)',
	'var(--tag-purple-dot)',
	'var(--indigo-500)'
] as const;

/**
 * Java-style 31x string hash with signed 32-bit overflow, then absolute
 * value. The `| 0` is load-bearing: it truncates to 32-bit signed exactly
 * like the reference implementation, so hues match across clients.
 */
export function avatarHash(s: string): number {
	let h = 0;
	for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
	return Math.abs(h);
}

/** Deterministic background hue for a display name. */
export function avatarHue(name: string): string {
	return AVATAR_HUES[avatarHash(name) % AVATAR_HUES.length];
}

/**
 * Initials: first char of first word + first char of last word;
 * first two chars of a single word; "?" when empty.
 */
export function avatarInitials(name: string): string {
	const parts = name.trim().split(/\s+/).filter(Boolean);
	if (!parts.length) return '?';
	if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
	return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}
