<svelte:options runes={true} />

<!--
	HrEvidence — detail-panel evidence renderer for hr.leave / hr.expense.
	payload is only populated for these two consumer types (see handler.go's
	scanApprovalItem doc comment) — every other consumer still withholds it.
-->

<script lang="ts">
	import { t } from '$lib/i18n';
	import type { ApprovalRequest } from '$lib/types/approvals';
	import type { HrLeaveForm, HrExpenseForm } from '$lib/types/approvals';

	interface Props {
		request: ApprovalRequest;
	}
	let { request }: Props = $props();

	let leave = $derived.by((): HrLeaveForm | null => {
		if (request.consumerType !== 'hr.leave' || !request.payload) return null;
		return request.payload as unknown as HrLeaveForm;
	});
	let expense = $derived.by((): HrExpenseForm | null => {
		if (request.consumerType !== 'hr.expense' || !request.payload) return null;
		return request.payload as unknown as HrExpenseForm;
	});

	function money(cents: number, currency: string): string {
		try {
			return new Intl.NumberFormat(undefined, { style: 'currency', currency }).format(cents / 100);
		} catch {
			return (cents / 100).toFixed(2) + ' ' + currency;
		}
	}
</script>

{#if leave}
	<div class="hre-field">
		<span class="hre-label">{t('approvals.detail.hr_leave_type')}</span>
		<span class="hre-value">{t(`approvals.hr.leave_type.${leave.leave_type}`)}</span>
	</div>
	<div class="hre-field">
		<span class="hre-label">{t('approvals.detail.hr_dates')}</span>
		<span class="hre-value">{leave.start_date} → {leave.end_date} ({t('approvals.hr.days_count', { count: String(leave.days) })})</span>
	</div>
	{#if leave.reason}
		<div class="hre-field">
			<span class="hre-label">{t('approvals.detail.hr_reason')}</span>
			<span class="hre-value hre-value--pre">{leave.reason}</span>
		</div>
	{/if}
{:else if expense}
	<div class="hre-field">
		<span class="hre-label">{t('approvals.detail.hr_currency')}</span>
		<span class="hre-value">{expense.currency}</span>
	</div>
	<div class="hre-table-wrap">
		<table class="hre-table">
			<thead>
				<tr>
					<th>{t('approvals.hr.description_label')}</th>
					<th>{t('approvals.hr.category_label')}</th>
					<th>{t('approvals.hr.amount_label')}</th>
					<th>{t('approvals.detail.hr_receipt')}</th>
				</tr>
			</thead>
			<tbody>
				{#each expense.line_items as item, i (i)}
					<tr>
						<td>{item.description}</td>
						<td>{t(`approvals.hr.category.${item.category}`)}</td>
						<td>{money(item.amount_cents, expense.currency)}</td>
						<td>
							{#if item.receipt_sha256}
								<a href={`/api/blobs/${item.receipt_sha256}`} download={item.receipt_filename ?? 'receipt'}>
									{t('approvals.detail.hr_receipt_download')}
								</a>
							{:else}
								—
							{/if}
						</td>
					</tr>
				{/each}
			</tbody>
			<tfoot>
				<tr>
					<td colspan="2">{t('approvals.hr.total_label')}</td>
					<td colspan="2">{money(expense.total_cents, expense.currency)}</td>
				</tr>
			</tfoot>
		</table>
	</div>
{/if}

<style>
	.hre-field {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.hre-label {
		font-size: var(--text-xs);
		font-weight: var(--weight-medium);
		color: var(--text-secondary);
	}
	.hre-value {
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	.hre-value--pre {
		white-space: pre-wrap;
	}
	.hre-table-wrap {
		overflow-x: auto;
	}
	.hre-table {
		width: 100%;
		border-collapse: collapse;
		font-size: var(--text-sm);
	}
	.hre-table th {
		text-align: left;
		padding: var(--space-1) var(--space-2);
		color: var(--text-secondary);
		font-weight: var(--weight-medium);
		border-bottom: 1px solid var(--border-default);
		white-space: nowrap;
	}
	.hre-table td {
		padding: var(--space-1) var(--space-2);
		border-bottom: 1px solid var(--border-subtle);
	}
	.hre-table tfoot td {
		font-weight: var(--weight-semibold);
		border-top: 1px solid var(--border-default);
		border-bottom: none;
	}
	.hre-table a {
		color: var(--accent);
	}
</style>
