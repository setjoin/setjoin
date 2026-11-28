<svelte:options runes={true} />

<script lang="ts">
	// AttendancePanel — Meet B2 Task 10, spec §9 (inherited (d)): host/cohost-
	// only, gated server-side by meeting_attendee_role (the caller only ever
	// hands this component a non-empty array when authorized — a plain
	// member's `attendance` is already `[]` from meeting_get, the anti-
	// oracle; this component renders nothing in that case, same shape as
	// EVERY other empty-vs-absent surface in this codebase). Duration is
	// computed CLIENT-side from the existing webhook-fed joined_at/left_at —
	// zero new schema (spec §9).
	import type { AttendanceRow } from '$lib/meet/api';
	import { Badge, Button } from '$lib/components/ui';
	import { formatDateTime, t } from '$lib/i18n';

	let { attendance }: { attendance: AttendanceRow[] } = $props();

	// B2 retro F9: localized instead of a hardcoded "Xh Ym" — de/zh get their
	// own unit words via the existing `t()` param-substitution path.
	function durationLabel(row: AttendanceRow): string {
		if (!row.joinedAt) return '—';
		const start = new Date(row.joinedAt).getTime();
		const end = row.leftAt ? new Date(row.leftAt).getTime() : Date.now();
		const ms = end - start;
		if (!(ms > 0)) return '—';
		const totalMinutes = Math.round(ms / 60000);
		const h = Math.floor(totalMinutes / 60);
		const m = totalMinutes % 60;
		return h > 0
			? t('meet.attendance.durationHm', { h: String(h), m: String(m) })
			: t('meet.attendance.durationM', { m: String(m) });
	}

	function csvField(value: string): string {
		return /[",\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
	}

	function exportCsv(): void {
		const header = 'name,role,guest,joined,left,duration';
		const lines = attendance.map((row) =>
			[
				row.displayName,
				row.role,
				row.isGuest ? 'true' : 'false',
				row.joinedAt ?? '',
				row.leftAt ?? '',
				durationLabel(row),
			]
				.map(csvField)
				.join(','),
		);
		const blob = new Blob([[header, ...lines].join('\n')], { type: 'text/csv' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = 'attendance.csv';
		a.click();
		URL.revokeObjectURL(url);
	}
</script>

{#if attendance.length > 0}
	<div class="attendance-panel">
		<div class="attendance-panel__head">
			<h3 class="attendance-panel__title">{t('meet.attendance.title')}</h3>
			<Button variant="secondary" size="sm" onclick={exportCsv}>{t('meet.attendance.exportCsv')}</Button>
		</div>
		<table class="attendance-panel__table">
			<thead>
				<tr>
					<th>{t('meet.attendance.name')}</th>
					<th>{t('meet.attendance.role')}</th>
					<th>{t('meet.attendance.joined')}</th>
					<th>{t('meet.attendance.left')}</th>
					<th>{t('meet.attendance.duration')}</th>
				</tr>
			</thead>
			<tbody>
				{#each attendance as row (row.identity)}
					<tr>
						<td class="attendance-panel__name">
							{row.displayName}
							{#if row.isGuest}<Badge variant="info" label={t('meet.attendance.guest')} />{/if}
						</td>
						<td>{t(`meet.role.${row.role}`)}</td>
						<td>{row.joinedAt ? formatDateTime(row.joinedAt) : '—'}</td>
						<td>{row.leftAt ? formatDateTime(row.leftAt) : '—'}</td>
						<td>{durationLabel(row)}</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}

<style>
	.attendance-panel {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.attendance-panel__head {
		display: flex;
		align-items: center;
		justify-content: space-between;
	}
	.attendance-panel__title {
		margin: 0;
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-primary);
	}
	.attendance-panel__table {
		width: 100%;
		border-collapse: collapse;
		font-size: var(--text-sm);
	}
	.attendance-panel__table th {
		text-align: left;
		font-weight: 600;
		color: var(--text-caption);
		padding: var(--space-1) var(--space-2);
		border-bottom: 1px solid var(--border-default);
	}
	.attendance-panel__table td {
		padding: var(--space-1) var(--space-2);
		border-bottom: 1px solid var(--border-subtle);
	}
	.attendance-panel__name {
		display: flex;
		align-items: center;
		gap: var(--space-1);
	}
</style>
