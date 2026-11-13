<svelte:options runes={true} />

<!--
	NewHrRequestDialog — leave + expense submission forms (HR approval templates,
	4th+5th approval-engine consumers). POSTs /api/me/approvals/hr; a 400/422
	shows the reducer's field-level detail inline (RFC7807). Receipts ride the
	existing content-addressed blob PUT (jmap/client.ts uploadBlob) — no new
	upload surface.
-->

<script lang="ts">
	import { Dialog, Button, Select, Input, Textarea, Spinner } from '$lib/components/ui';
	import { t } from '$lib/i18n';
	import { typedFetch } from '$lib/http';
	import { problemDetail } from '$lib/errors';
	import { parseError } from '$lib/errors';
	import { uploadBlob } from '$lib/jmap/client';
	import type { LeaveType, ExpenseCategory, HrExpenseLineItem } from '$lib/types/approvals';

	interface Props {
		open: boolean;
		onClose: () => void;
		onSubmitted: () => void;
	}
	let { open, onClose, onSubmitted }: Props = $props();

	const LEAVE_TYPES: LeaveType[] = ['annual', 'sick', 'personal', 'marriage', 'maternity', 'paternity', 'bereavement', 'other'];
	const CATEGORIES: ExpenseCategory[] = ['travel', 'meals', 'lodging', 'supplies', 'other'];
	const CURRENCIES = ['CNY', 'EUR', 'USD'];

	let kind = $state<'hr.leave' | 'hr.expense'>('hr.leave');
	let submitting = $state(false);
	let error = $state('');

	// ── leave fields ──────────────────────────────────────────────────────────
	let leaveType = $state<LeaveType>('annual');
	let startDate = $state('');
	let endDate = $state('');
	let reason = $state('');
	let leaveDays = $derived.by(() => {
		if (!startDate || !endDate) return 0;
		const s = new Date(startDate + 'T00:00:00Z').getTime();
		const e = new Date(endDate + 'T00:00:00Z').getTime();
		if (isNaN(s) || isNaN(e) || e < s) return 0;
		return Math.round((e - s) / 86_400_000) + 1;
	});
	let leaveValid = $derived(!!startDate && !!endDate && leaveDays > 0 && reason.trim().length > 0);

	// ── expense fields ────────────────────────────────────────────────────────
	interface Row {
		description: string;
		amount: string; // major-unit decimal string, e.g. "80.00"
		category: ExpenseCategory;
		receiptFile: File | null;
		receiptSha256: string;
		uploadingReceipt: boolean;
	}
	function newRow(): Row {
		return { description: '', amount: '', category: 'other', receiptFile: null, receiptSha256: '', uploadingReceipt: false };
	}
	let currency = $state('CNY');
	let rows = $state<Row[]>([newRow()]);
	let totalCents = $derived(rows.reduce((sum, r) => sum + centsOf(r.amount), 0));
	let expenseValid = $derived(
		rows.length >= 1 &&
			rows.length <= 50 &&
			rows.every((r) => r.description.trim().length > 0 && centsOf(r.amount) > 0)
	);

	function centsOf(amount: string): number {
		const n = Number(amount);
		if (!isFinite(n) || n <= 0) return 0;
		return Math.round(n * 100);
	}

	function addRow() {
		if (rows.length < 50) rows = [...rows, newRow()];
	}
	function removeRow(i: number) {
		if (rows.length > 1) rows = rows.filter((_, idx) => idx !== i);
	}

	async function handleReceiptChange(i: number, file: File | null) {
		if (!file) return;
		rows[i].receiptFile = file;
		rows[i].uploadingReceipt = true;
		try {
			const { blobId } = await uploadBlob(file);
			rows[i].receiptSha256 = blobId;
		} catch (e) {
			error = parseError(e).message;
		} finally {
			rows[i].uploadingReceipt = false;
		}
	}

	function resetForm() {
		kind = 'hr.leave';
		leaveType = 'annual';
		startDate = '';
		endDate = '';
		reason = '';
		currency = 'CNY';
		rows = [newRow()];
		error = '';
	}

	function handleClose() {
		resetForm();
		onClose();
	}

	async function submit() {
		error = '';
		if (kind === 'hr.leave' && !leaveValid) return;
		if (kind === 'hr.expense' && !expenseValid) return;

		submitting = true;
		try {
			const form =
				kind === 'hr.leave'
					? { leave_type: leaveType, start_date: startDate, end_date: endDate, days: leaveDays, reason: reason.trim() }
					: {
							currency,
							total_cents: totalCents,
							line_items: rows.map(
								(r): HrExpenseLineItem => ({
									description: r.description.trim(),
									amount_cents: centsOf(r.amount),
									category: r.category,
									...(r.receiptSha256
										? { receipt_sha256: r.receiptSha256, receipt_filename: r.receiptFile?.name }
										: {}),
								})
							)
						};

			await typedFetch('/api/me/approvals/hr', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ kind, form }),
				onError: (r) => problemDetail(r, t('approvals.hr.submit_error'))
			});
			resetForm();
			onSubmitted();
		} catch (e) {
			error = parseError(e).message;
		} finally {
			submitting = false;
		}
	}
</script>

<Dialog {open} title={t('approvals.hr.new_request_title')} onClose={handleClose} wide>
	<form
		class="hr-form"
		onsubmit={(e) => {
			e.preventDefault();
			submit();
		}}
	>
		<Select
			label={t('approvals.hr.kind_label')}
			bind:value={kind}
			options={[
				{ value: 'hr.leave', label: t('approvals.hr.kind_leave') },
				{ value: 'hr.expense', label: t('approvals.hr.kind_expense') }
			]}
		/>

		{#if kind === 'hr.leave'}
			<Select label={t('approvals.hr.leave_type_label')} bind:value={leaveType} options={LEAVE_TYPES.map((lt) => ({ value: lt, label: t(`approvals.hr.leave_type.${lt}`) }))} />
			<div class="hr-form__row">
				<Input type="date" label={t('approvals.hr.start_date_label')} bind:value={startDate} required />
				<Input type="date" label={t('approvals.hr.end_date_label')} bind:value={endDate} required />
			</div>
			<p class="hr-form__days" aria-live="polite">
				{leaveDays > 0 ? t('approvals.hr.days_count', { count: String(leaveDays) }) : t('approvals.hr.days_pending')}
			</p>
			<Textarea label={t('approvals.hr.reason_label')} bind:value={reason} rows={3} required maxlength={2000} />
		{:else}
			<Select label={t('approvals.hr.currency_label')} bind:value={currency} options={CURRENCIES} />
			<div class="hr-form__items">
				<span class="hr-form__items-label">{t('approvals.hr.line_items_label')}</span>
				{#each rows as row, i (i)}
					<div class="hr-form__row hr-form__item-row">
						<Input label={t('approvals.hr.description_label')} bind:value={row.description} />
						<Select label={t('approvals.hr.category_label')} bind:value={row.category} options={CATEGORIES.map((c) => ({ value: c, label: t(`approvals.hr.category.${c}`) }))} />
						<Input type="number" step="0.01" min="0.01" label={t('approvals.hr.amount_label')} bind:value={row.amount} />
						<div class="hr-form__receipt">
							<label class="hr-form__receipt-label" for={`hr-receipt-${i}`}>{t('approvals.hr.receipt_label')}</label>
							<input
								id={`hr-receipt-${i}`}
								type="file"
								onchange={(e) => handleReceiptChange(i, (e.currentTarget as HTMLInputElement).files?.[0] ?? null)}
							/>
							{#if row.uploadingReceipt}<Spinner size={16} label={t('approvals.hr.receipt_uploading')} />{/if}
							{#if row.receiptSha256 && !row.uploadingReceipt}<span class="hr-form__receipt-ok">✓ {row.receiptFile?.name}</span>{/if}
						</div>
						<button
							type="button"
							class="hr-form__remove"
							aria-label={t('approvals.hr.remove_item', { description: row.description || t('approvals.hr.line_items_label') })}
							disabled={rows.length <= 1}
							onclick={() => removeRow(i)}
						>
							&times;
						</button>
					</div>
				{/each}
				<Button type="button" variant="ghost" size="sm" onclick={addRow} disabled={rows.length >= 50}>
					{t('approvals.hr.add_item')}
				</Button>
			</div>
			<p class="hr-form__total" aria-live="polite">
				{t('approvals.hr.total_label')}: {(totalCents / 100).toFixed(2)} {currency}
			</p>
		{/if}

		{#if error}
			<p class="hr-form__error" role="alert">{error}</p>
		{/if}

		<div class="hr-form__actions">
			<Button variant="ghost" type="button" onclick={handleClose}>{t('approvals.hr.cancel')}</Button>
			<Button
				variant="primary"
				type="submit"
				disabled={submitting || (kind === 'hr.leave' ? !leaveValid : !expenseValid)}
			>
				{#if submitting}<Spinner size={16} label="" />{/if}
				{t('approvals.hr.submit')}
			</Button>
		</div>
	</form>
</Dialog>

<style>
	.hr-form {
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
	}
	.hr-form__row {
		display: flex;
		gap: var(--space-3);
		flex-wrap: wrap;
	}
	.hr-form__row > :global(*) {
		flex: 1;
		min-width: 140px;
	}
	.hr-form__days {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.hr-form__items {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.hr-form__items-label {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
	}
	.hr-form__item-row {
		align-items: flex-end;
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-md);
		padding: var(--space-3);
	}
	.hr-form__receipt {
		display: flex;
		flex-direction: column;
		gap: 4px;
		font-size: var(--text-xs);
	}
	.hr-form__receipt-label {
		font-size: var(--text-xs);
		font-weight: var(--weight-medium);
		color: var(--text-secondary);
	}
	.hr-form__receipt-ok {
		color: var(--success-fg);
	}
	.hr-form__remove {
		min-width: 44px;
		min-height: 44px;
		border: none;
		background: transparent;
		color: var(--text-tertiary);
		font-size: var(--text-lg);
		cursor: pointer;
		border-radius: var(--radius-sm);
	}
	.hr-form__remove:hover:not(:disabled) {
		background: var(--surface-hover);
		color: var(--danger-fg);
	}
	.hr-form__remove:disabled {
		opacity: 0.35;
		cursor: default;
	}
	.hr-form__total {
		margin: 0;
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
	}
	.hr-form__error {
		font-size: var(--text-sm);
		color: var(--danger-fg);
		margin: 0;
	}
	.hr-form__actions {
		display: flex;
		justify-content: flex-end;
		gap: var(--space-2);
		padding-top: var(--space-2);
		border-top: 1px solid var(--border-default);
	}
</style>
