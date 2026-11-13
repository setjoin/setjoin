<svelte:options runes={true} />

<!--
	ApproverSpecPicker — builds an ApproverSpec object.
	Root kind selector: manager / named / role_group / default_admin / skip.
	Manager shows a fallback-chain builder.
-->

<script lang="ts">
	import { t } from '$lib/i18n';
	import type { ApproverSpec, ApproverFallbackStep, ApproverKind } from '$lib/admin/client';

	interface Props {
		value: ApproverSpec;
		onchange?: (spec: ApproverSpec) => void;
	}

	let { value = $bindable({ kind: 'default_admin' }), onchange }: Props = $props();

	const KINDS: { id: ApproverKind; label: string }[] = [
		{ id: 'manager', label: t('admin.approvals.spec.manager') },
		{ id: 'named', label: t('admin.approvals.spec.named') },
		{ id: 'role_group', label: t('admin.approvals.spec.role_group') },
		{ id: 'default_admin', label: t('admin.approvals.spec.default_admin') },
		{ id: 'skip', label: t('admin.approvals.spec.skip') },
	];

	const FALLBACK_KINDS: { id: ApproverFallbackStep['kind']; label: string }[] = [
		{ id: 'default_admin', label: t('admin.approvals.spec.default_admin') },
		{ id: 'named', label: t('admin.approvals.spec.named') },
		{ id: 'skip', label: t('admin.approvals.spec.skip') },
	];

	function emit(patch: Partial<ApproverSpec>) {
		const next = { ...value, ...patch };
		// ponytail: strip fields not relevant to the selected kind.
		if (next.kind !== 'named') delete next.userId;
		if (next.kind !== 'role_group') delete next.roleGroupId;
		if (next.kind !== 'manager') delete next.fallback;
		onchange?.(next);
	}

	function setKind(kind: ApproverKind) {
		const base: ApproverSpec = { kind };
		if (kind === 'manager') base.fallback = [{ kind: 'default_admin' }];
		onchange?.(base);
	}

	function addFallback() {
		const fb = [...(value.fallback ?? []), { kind: 'default_admin' as const }];
		emit({ fallback: fb });
	}

	function removeFallback(i: number) {
		const fb = (value.fallback ?? []).filter((_, idx) => idx !== i);
		emit({ fallback: fb });
	}

	function updateFallback(i: number, patch: Partial<ApproverFallbackStep>) {
		const fb = (value.fallback ?? []).map((step, idx) =>
			idx === i ? { ...step, ...patch } : step
		);
		emit({ fallback: fb });
	}
</script>

<fieldset class="spec-picker">
	<legend class="spec-picker__legend">{t('admin.approvals.editor.approver_label')}</legend>

	<div class="spec-picker__kinds">
		{#each KINDS as k (k.id)}
			<label class="spec-picker__kind">
				<input
					type="radio"
					name="approver-kind"
					value={k.id}
					checked={value.kind === k.id}
					onchange={() => setKind(k.id)}
				/>
				{k.label}
			</label>
		{/each}
	</div>

	{#if value.kind === 'named'}
		<div class="spec-picker__field">
			<label class="spec-picker__label" for="approver-user-id">
				{t('admin.approvals.spec.named')}
			</label>
			<input
				id="approver-user-id"
				type="number"
				min="1"
				class="spec-picker__input"
				value={value.userId ?? ''}
				oninput={(e) => emit({ userId: Number((e.target as HTMLInputElement).value) || undefined })}
			/>
		</div>
	{/if}

	{#if value.kind === 'role_group'}
		<div class="spec-picker__field">
			<label class="spec-picker__label" for="approver-role-group-id">
				{t('admin.approvals.spec.role_group')}
			</label>
			<input
				id="approver-role-group-id"
				type="number"
				min="1"
				class="spec-picker__input"
				value={value.roleGroupId ?? ''}
				oninput={(e) =>
					emit({ roleGroupId: Number((e.target as HTMLInputElement).value) || undefined })}
			/>
		</div>
	{/if}

	{#if value.kind === 'manager'}
		<fieldset class="spec-picker__fallback">
			<legend class="spec-picker__label">{t('admin.approvals.spec.fallback_label')}</legend>
			{#each value.fallback ?? [] as step, i (i)}
				<div class="spec-picker__fallback-row">
					<select
						class="spec-picker__select"
						value={step.kind}
						onchange={(e) =>
							updateFallback(i, {
								kind: (e.target as HTMLSelectElement).value as ApproverFallbackStep['kind']
							})}
					>
						{#each FALLBACK_KINDS as fk (fk.id)}
							<option value={fk.id}>{fk.label}</option>
						{/each}
					</select>
					{#if step.kind === 'named'}
						<input
							type="number"
							min="1"
							class="spec-picker__input spec-picker__input--sm"
							placeholder={t('admin.approvals.spec.named_ph')}
							value={step.userId ?? ''}
							oninput={(e) =>
								updateFallback(i, {
									userId: Number((e.target as HTMLInputElement).value) || undefined
								})}
						/>
					{/if}
					<button
						type="button"
						class="spec-picker__remove"
						aria-label={t('admin.approvals.spec.remove_fallback')}
						onclick={() => removeFallback(i)}
					>×</button>
				</div>
			{/each}
			<button type="button" class="spec-picker__add-fallback" onclick={addFallback}>
				+ {t('admin.approvals.spec.add_fallback')}
			</button>
		</fieldset>
	{/if}
</fieldset>

<style>
	.spec-picker {
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		padding: var(--space-3);
		margin: 0;
	}
	.spec-picker__legend {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-secondary);
		padding: 0 4px;
	}
	.spec-picker__kinds {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-2);
		margin-bottom: var(--space-2);
	}
	.spec-picker__kind {
		display: flex;
		align-items: center;
		gap: 6px;
		font-size: var(--text-sm);
		cursor: pointer;
	}
	.spec-picker__field {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		margin-top: var(--space-2);
	}
	.spec-picker__label {
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.spec-picker__input {
		height: 36px;
		padding: 0 var(--space-2);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		font-size: var(--text-sm);
		background: var(--surface-base);
		color: var(--text-primary);
	}
	.spec-picker__input--sm {
		width: 100px;
	}
	.spec-picker__select {
		height: 36px;
		padding: 0 var(--space-2);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		font-size: var(--text-sm);
		background: var(--surface-base);
		color: var(--text-primary);
	}
	.spec-picker__fallback {
		border: none;
		padding: 0;
		margin-top: var(--space-2);
	}
	.spec-picker__fallback-row {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		margin-top: var(--space-1);
	}
	.spec-picker__remove {
		background: transparent;
		border: none;
		cursor: pointer;
		color: var(--text-danger);
		font-size: var(--text-base);
		padding: 0 4px;
		line-height: 1;
	}
	.spec-picker__add-fallback {
		margin-top: var(--space-2);
		font-size: var(--text-sm);
		color: var(--text-accent);
		background: transparent;
		border: none;
		cursor: pointer;
		padding: 0;
	}
</style>
