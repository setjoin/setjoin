/**
 * Pure helper for RoleMembersPanel expiry badge logic.
 *
 * isExpiringSoon — returns true when a membership will expire within 7 days
 * from the given reference time (nowMs).
 *
 * @param expiresAt  ISO-8601 string or null/undefined (no expiry).
 * @param nowMs      Reference timestamp in milliseconds (injectable for testing).
 */
export function isExpiringSoon(
	expiresAt: string | null | undefined,
	nowMs: number
): boolean {
	if (!expiresAt) return false;
	const delta = new Date(expiresAt).getTime() - nowMs;
	return delta > 0 && delta < 7 * 24 * 60 * 60 * 1000;
}
