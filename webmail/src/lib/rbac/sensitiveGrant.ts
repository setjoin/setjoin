/**
 * Pure helper for SensitiveGrantConfirm gating logic.
 *
 * canConfirmGrant — returns true when the user is permitted to confirm the
 * sensitive-permission grant:
 *   - If requireType is false: always allowed (no typed confirmation needed).
 *   - If requireType is true: the user must have typed the role name exactly
 *     (after trimming whitespace from `typed`).
 */
export function canConfirmGrant(
	requireType: boolean,
	typed: string,
	roleName: string
): boolean {
	if (!requireType) return true;
	return typed.trim() === roleName;
}
