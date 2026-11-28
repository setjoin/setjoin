/**
 * Audit log types and helpers for the Logs & threats console.
 *
 * Mirrors admin-kit §4.6 (Audit columns: Time/Actor/Action/Target/Detail/Proto)
 * over the GET /admin/audit API, plus alert severity helpers for §5.2.
 */

import type { BadgeVariantName } from './threat';

/** Severity levels used by the alerts page (admin-kit §5.2). */
export type SeverityLevel = 'danger' | 'warning' | 'info';

/** One audit log entry from GET /admin/audit. Mirrors the Go item struct in admin_audit.go. */
export interface AuditEntry {
	id: number;
	occurredAt: string;
	userId?: number | null;
	userEmail: string;
	ip: string;
	action: string;
	targetType?: string | null;
	targetId?: number | null;
	beforeState?: unknown;
	afterState?: unknown;
	notes?: string;
}

/** Shape returned by GET /admin/audit. */
export interface AuditApiResponse {
	items: AuditEntry[];
	total: number;
}

/**
 * Return the M1 Badge variant for a given severity level string.
 * Maps directly — danger/warning/info are valid Badge variant names.
 */
export function severityBadgeVariant(level: string): BadgeVariantName {
	switch (level) {
		case 'danger': return 'danger';
		case 'warning': return 'warning';
		case 'info': return 'info';
		default: return 'neutral';
	}
}

/**
 * Derive an alert severity Badge variant from its state.
 * - suppressed → danger (needs attention)
 * - firing with >=3 consecutive → warning
 * - firing with 1-2 consecutive → info
 * - 0 consecutive → neutral (healthy)
 */
export function alertSeverity(consecutive: number, suppressed: boolean): BadgeVariantName {
	if (suppressed) return 'danger';
	if (consecutive >= 3) return 'warning';
	if (consecutive >= 1) return 'info';
	return 'neutral';
}

/**
 * Normalize an audit action string for code-chip display.
 * Returns the action unchanged; the code-chip styling is applied
 * in the template per admin-kit §3 code-chip pattern.
 */
export function auditActionChip(action: string): string {
	return action;
}

/**
 * Format an ISO 8601 / RFC3339 timestamp string to 24h HH:MM:SS.
 * Extracts the time portion directly from the ISO string to avoid
 * timezone conversion issues. Falls back to returning the input unchanged
 * if no time pattern is found.
 */
export function formatAuditTime(iso: string): string {
	if (!iso) return '';
	// If already looks like HH:MM:SS, return as-is
	if (/^\d{2}:\d{2}:\d{2}$/.test(iso)) return iso;
	// Extract time portion from ISO string: 2026-06-15T09:41:07Z → 09:41:07
	const m = iso.match(/T(\d{2}:\d{2}:\d{2})/);
	if (m) return m[1];
	// Try as a fallback with Date parsing (for non-ISO formats)
	try {
		const d = new Date(iso);
		if (!isNaN(d.getTime())) {
			const hh = String(d.getHours()).padStart(2, '0');
			const mm = String(d.getMinutes()).padStart(2, '0');
			const ss = String(d.getSeconds()).padStart(2, '0');
			return `${hh}:${mm}:${ss}`;
		}
	} catch { /* ignore */ }
	return iso;
}

/**
 * Format an audit target as "{type} #{id}" or just "{type}".
 */
export function formatAuditTarget(targetType: string | null | undefined, targetId: number | null | undefined): string {
	if (!targetType) return '';
	if (targetId != null) return `${targetType} #${targetId}`;
	return targetType;
}
