// auditSessions.ts — P6 Task 16: UI-side session grouping over per-access
// audit rows (spec §9.3: grouping is presentation-ONLY; the tamper-evident
// HMAC chain and drive_audit_query's response always stay per-operation —
// this module never mutates or drops a row, only buckets references to it).
import type { DriveAuditRow } from './api';

export type AuditRow = DriveAuditRow;

export interface AuditSession {
	userId: number | null;
	userEmail: string;
	start: string;
	end: string;
	count: number;
	actions: Record<string, number>;
	rows: AuditRow[];
}

const GAP_MS = 30 * 60 * 1000; // same user, event gap < 30 min => one session

/** Buckets rows into per-user sessions (gap < 30min), newest-first. Every
 *  input row survives into exactly one session's `rows` array — the raw
 *  per-access drill-down and the CSV export both read the ungrouped list. */
export function groupSessions(rows: AuditRow[]): AuditSession[] {
	const asc = [...rows].sort((a, b) => Date.parse(a.occurredAt) - Date.parse(b.occurredAt));
	const open = new Map<string, AuditSession>(); // key = userId|'system'
	const done: AuditSession[] = [];
	for (const r of asc) {
		const key = `${r.userId ?? 'system'}`;
		const cur = open.get(key);
		if (cur && Date.parse(r.occurredAt) - Date.parse(cur.end) < GAP_MS) {
			cur.end = r.occurredAt;
			cur.count += 1;
			cur.actions[r.action] = (cur.actions[r.action] ?? 0) + 1;
			cur.rows.push(r);
		} else {
			if (cur) done.push(cur);
			open.set(key, {
				userId: r.userId,
				userEmail: r.userEmail,
				start: r.occurredAt,
				end: r.occurredAt,
				count: 1,
				actions: { [r.action]: 1 },
				rows: [r],
			});
		}
	}
	done.push(...open.values());
	return done.sort((a, b) => Date.parse(b.end) - Date.parse(a.end)); // newest first
}
