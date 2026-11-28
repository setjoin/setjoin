<svelte:options runes={true} />

<!--
	PolicyEditor — dialog panel for creating or editing an approval policy.
	Emits onsave with the policy payload or oncancel.
-->

<script lang="ts">
	import { Dialog, Button, Input, Switch } from '$lib/components/ui';
	import { t } from '$lib/i18n';
	import type { ApprovalPolicy, ApprovalConsumerType, ApproverSpec } from '$lib/admin/client';
	import ApproverSpecPicker from './ApproverSpecPicker.svelte';

	interface Props {
		open: boolean;
		/** null = create mode; defined = edit mode. */
		policy: ApprovalPolicy | null;
		consumerType: ApprovalConsumerType;
		onsave?: (data: Omit<ApprovalPolicy, 'id' | 'createdAt' | 'updatedAt'>) => void;
		oncancel?: () => void;
	}

	let { open, policy, consumerType, onsave, oncancel }: Props = $props();

	// Use $derived to react to prop changes (policy edit vs new)
	let name = $state('');
	let enabled = $state(true);
	let requiresApproval = $state(true);
	let conditionsStr = $state('{}');
	let approverSpec = $state<ApproverSpec>({ kind: 'default_admin' });
	let nameError = $state('');
	let conditionsError = $state('');

	$effect(() => {
		name = policy?.name ?? '';
		enabled = policy?.enabled ?? true;
		requiresApproval = policy?.requiresApproval ?? true;
		conditionsStr = policy?.conditions ? JSON.stringify(policy.conditions, null, 2) : '{}';
		approverSpec = policy?.approverSpec
			? (policy.approverSpec as unknown as ApproverSpec)
			: { kind: 'default_admin' };
		nameError = '';
		conditionsError = '';
	});

	function validate(): boolean {
		nameError = name.trim() === '' ? t('admin.approvals.editor.name_required') : '';
		try {
			const parsed = JSON.parse(conditionsStr);
			if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
				conditionsError = t('admin.approvals.editor.conditions_invalid');
				return false;
			}
			conditionsError = '';
		} catch {
			conditionsError = t('admin.approvals.editor.conditions_invalid');
			return false;
		}
		return nameError === '';
	}

	function submit() {
		if (!validate()) return;
		onsave?.({
			consumerType,
			name: name.trim(),
			enabled,
			priority: policy?.priority ?? 0,
			conditions: JSON.parse(conditionsStr),
			requiresApproval,
			approverSpec,
		});
	}
</script>

<Dialog {open} title={policy ? t('admin.approvals.editor.title_edit') : t('admin.approvals.editor.title_create')} onClose={oncancel}>
	<form
		class="pe-form"
		onsubmit={(e) => {
			e.preventDefault();
			submit();
		}}
	>
		<!-- Name -->
		<div class="pe-field">
			<Input label={t('admin.approvals.editor.name_label')} bind:value={name} required />
			{#if nameError}
				<p class="pe-error" role="alert">{nameError}</p>
			{/if}
		</div>

		<!-- Consumer (read-only label) -->
		<div class="pe-field">
			<span class="pe-label">{t('admin.approvals.editor.consumer_label')}</span>
			<span class="pe-readonly">{consumerType}</span>
		</div>

		<!-- Enabled -->
		<div class="pe-field pe-field--row">
			<span class="pe-label">{t('admin.approvals.editor.enabled_label')}</span>
			<Switch bind:checked={enabled} />
		</div>

		<!-- Requires approval -->
		<div class="pe-field pe-field--row">
			<span class="pe-label">{t('admin.approvals.editor.requires_approval_label')}</span>
			<Switch bind:checked={requiresApproval} />
		</div>

		<!-- Conditions JSON — Textarea doesn't expose id; use label prop -->
		<div class="pe-field">
			<span class="pe-label">{t('admin.approvals.editor.conditions_label')}</span>
			<textarea
				class="pe-textarea"
				rows={4}
				bind:value={conditionsStr}
			></textarea>
			<p class="pe-hint">{t('admin.approvals.editor.conditions_hint')}</p>
			{#if conditionsError}
				<p class="pe-error" role="alert">{conditionsError}</p>
			{/if}
		</div>

		<!-- Approver spec -->
		<div class="pe-field">
			<ApproverSpecPicker bind:value={approverSpec} />
		</div>

		<div class="pe-actions">
			<Button variant="ghost" type="button" onclick={oncancel}>{t('admin.approvals.editor.cancel')}</Button>
			<Button variant="primary" type="submit">{t('admin.approvals.editor.save')}</Button>
		</div>
	</form>
</Dialog>

<style>
	.pe-form {
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
		min-width: 380px;
	}
	.pe-field {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.pe-field--row {
		flex-direction: row;
		align-items: center;
		justify-content: space-between;
	}
	.pe-label {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-secondary);
	}
	.pe-readonly {
		font-size: var(--text-sm);
		color: var(--text-tertiary);
		font-family: var(--font-mono);
	}
	.pe-textarea {
		width: 100%;
		padding: var(--space-2);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		font-size: var(--text-sm);
		font-family: var(--font-mono);
		background: var(--surface-base);
		color: var(--text-primary);
		resize: vertical;
		box-sizing: border-box;
	}
	.pe-textarea:focus {
		outline: none;
		border-color: var(--accent);
		box-shadow: var(--focus-ring);
	}
	.pe-hint {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		margin: 0;
	}
	.pe-error {
		font-size: var(--text-xs);
		color: var(--text-danger);
		margin: 0;
	}
	.pe-actions {
		display: flex;
		justify-content: flex-end;
		gap: var(--space-2);
		padding-top: var(--space-2);
		border-top: 1px solid var(--border-default);
	}
</style>
