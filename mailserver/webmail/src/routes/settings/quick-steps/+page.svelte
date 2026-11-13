<svelte:options runes={true} />
<script lang="ts">
	import { onMount } from 'svelte';
	import { Card, Button, Input, Select, showToast } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';
	import { listQuickSteps, saveQuickStep, deleteQuickStep } from '$lib/jmap/quicksteps';
	import type { QuickStep, QuickStepAction } from '$lib/types/jmap';

	type ActionType = QuickStepAction['type'];

	/** Action types that carry a single free-text value param. */
	const VALUE_PARAM: Record<ActionType, string | null> = {
		move_to: 'folder',
		categorize: 'category',
		forward_to: 'address',
		flag: null,
		mark_read: null,
	};

	const ACTION_TYPES: ActionType[] = ['move_to', 'categorize', 'flag', 'mark_read', 'forward_to'];
	const ICON_CHOICES = ['Zap', 'FileText', 'Archive', 'Flag', 'Forward', 'Folder', 'CheckSquare'];

	let steps = $state<QuickStep[]>([]);
	let loading = $state(true);
	let editing = $state<QuickStep | null>(null);
	let saving = $state(false);
	let formError = $state('');

	async function load() {
		loading = true;
		try {
			steps = await listQuickSteps();
		} catch {
			showToast(t('quickSteps.save_failed'));
		} finally {
			loading = false;
		}
	}
	onMount(load);

	function startNew() {
		formError = '';
		editing = { id: '', name: '', icon: 'Zap', position: 0, actions: [{ type: 'mark_read' }] };
	}
	function startEdit(s: QuickStep) {
		formError = '';
		// Deep clone so cancel discards in-progress edits.
		editing = { ...s, actions: s.actions.map((a) => ({ type: a.type, params: { ...(a.params ?? {}) } })) };
	}
	function cancel() {
		editing = null;
		formError = '';
	}

	function addAction() {
		if (!editing) return;
		editing.actions = [...editing.actions, { type: 'mark_read' }];
	}
	function removeAction(i: number) {
		if (!editing) return;
		editing.actions = editing.actions.filter((_, idx) => idx !== i);
	}
	function changeActionType(i: number, type: ActionType) {
		if (!editing) return;
		// Reset params on type change so a stale value param can't leak across types.
		editing.actions = editing.actions.map((a, idx) => (idx === i ? { type, params: {} } : a));
	}
	function changeActionValue(i: number, value: string) {
		if (!editing) return;
		editing.actions = editing.actions.map((a, idx) => {
			if (idx !== i) return a;
			const key = VALUE_PARAM[a.type];
			return key ? { type: a.type, params: { [key]: value } } : a;
		});
	}
	function actionValue(a: QuickStepAction): string {
		const key = VALUE_PARAM[a.type];
		return key ? (a.params?.[key] ?? '') : '';
	}

	async function save() {
		if (!editing) return;
		formError = '';
		const name = editing.name.trim();
		if (!name) {
			formError = t('quickSteps.name_required');
			return;
		}
		if (editing.actions.length === 0) {
			formError = t('quickSteps.action_required');
			return;
		}
		saving = true;
		try {
			await saveQuickStep({
				id: editing.id || undefined,
				name,
				icon: editing.icon || 'Zap',
				actions: editing.actions,
			});
			editing = null;
			await load();
			showToast(t('quickSteps.title'));
		} catch (e) {
			formError = e instanceof Error ? e.message : t('quickSteps.save_failed');
		} finally {
			saving = false;
		}
	}

	async function remove(s: QuickStep) {
		try {
			await deleteQuickStep(s.id);
			await load();
		} catch {
			showToast(t('quickSteps.save_failed'));
		}
	}

	function summary(s: QuickStep): string {
		return s.actions.map((a) => t(`quickSteps.action.${a.type}`)).join(' · ');
	}
</script>

<div class="sj-qs-page">
	<Card title={t('quickSteps.title')}>
		{#snippet actions()}
			<Button size="sm" variant="primary" data-testid="qs-new-btn" onclick={startNew}>
				<Icon name="Plus" size={14} />{t('quickSteps.new')}
			</Button>
		{/snippet}
		{#snippet children()}
			<p class="sj-qs-subtitle">{t('quickSteps.subtitle')}</p>

			{#if !loading}
				{#if steps.length === 0}
					<p class="sj-qs-empty">{t('quickSteps.empty')}</p>
				{:else}
					<ul class="sj-qs-list">
						{#each steps as s (s.id)}
							<li class="sj-qs-row">
								<Icon name={(s.icon || 'Zap') as never} size={16} strokeWidth={1.75} />
								<span class="sj-qs-name">{s.name}</span>
								<span class="sj-qs-summary">{summary(s)}</span>
								<Button size="sm" variant="ghost" onclick={() => startEdit(s)}>{t('quickSteps.edit')}</Button>
								<Button size="sm" variant="ghost" data-testid={`qs-delete-${s.id}`} onclick={() => remove(s)}>
									<Icon name="Trash2" size={14} />
								</Button>
							</li>
						{/each}
					</ul>
				{/if}
			{/if}

			{#if editing}
				<div class="sj-qs-editor">
					<Input label={t('quickSteps.name')} placeholder={t('quickSteps.name_placeholder')} bind:value={editing.name} />

					<Select
						label={t('quickSteps.icon')}
						bind:value={editing.icon}
						options={ICON_CHOICES}
					/>

					<div class="sj-qs-actions">
						<span class="sj-qs-actions-label">{t('quickSteps.actions')}</span>
						{#each editing.actions as a, i (i)}
							<div class="sj-qs-action-row">
								<Select
									value={a.type}
									onchange={(e) => changeActionType(i, (e.target as HTMLSelectElement).value as ActionType)}
									options={ACTION_TYPES.map((ty) => ({ value: ty, label: t(`quickSteps.action.${ty}`) }))}
								/>
								{#if VALUE_PARAM[a.type]}
									<Input
										placeholder={t('quickSteps.action_value')}
										value={actionValue(a)}
										oninput={(e) => changeActionValue(i, (e.target as HTMLInputElement).value)}
									/>
								{/if}
								<Button size="sm" variant="ghost" data-testid={`qs-remove-action-${i}`} onclick={() => removeAction(i)}>
									<Icon name="X" size={14} />
								</Button>
							</div>
						{/each}
						<Button size="sm" variant="ghost" data-testid="qs-add-action" onclick={addAction}>
							<Icon name="Plus" size={14} />{t('quickSteps.add_action')}
						</Button>
					</div>

					{#if formError}
						<p class="sj-qs-error" role="alert">{formError}</p>
					{/if}

					<div class="sj-qs-editor-actions">
						<Button size="sm" variant="ghost" onclick={cancel}>{t('quickSteps.cancel')}</Button>
						<Button size="sm" variant="primary" data-testid="qs-save-btn" disabled={saving} onclick={save}>
							{t('quickSteps.save')}
						</Button>
					</div>
				</div>
			{/if}
		{/snippet}
	</Card>
</div>

<style>
	.sj-qs-page { max-width: 720px; margin: 0 auto; padding: 24px clamp(12px, 3vw, 24px); }
	.sj-qs-subtitle { font-size: var(--text-sm); color: var(--text-secondary); margin: 0 0 16px; }
	.sj-qs-empty { font-size: var(--text-sm); color: var(--text-secondary); margin: 0; }
	.sj-qs-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 8px; }
	.sj-qs-row { display: flex; align-items: center; gap: 12px; padding: 10px 12px; border: 1px solid var(--border-subtle); border-radius: var(--radius-md); }
	.sj-qs-name { font-size: var(--text-sm); font-weight: var(--weight-medium); color: var(--text-primary); }
	.sj-qs-summary { flex: 1; min-width: 0; font-size: var(--text-xs); color: var(--text-tertiary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.sj-qs-editor { margin-top: 16px; display: flex; flex-direction: column; gap: 12px; border-top: 1px solid var(--border-subtle); padding-top: 16px; }
	.sj-qs-actions { display: flex; flex-direction: column; gap: 8px; }
	.sj-qs-actions-label { font-size: var(--text-xs); font-weight: var(--weight-semibold); letter-spacing: var(--tracking-caps); text-transform: uppercase; color: var(--text-tertiary); }
	.sj-qs-action-row { display: flex; align-items: flex-end; gap: 8px; }
	.sj-qs-action-row :global(.sj-select), .sj-qs-action-row :global(.sj-input) { flex: 1; }
	.sj-qs-error { font-size: var(--text-xs); color: var(--danger-solid); margin: 0; }
	.sj-qs-editor-actions { display: flex; gap: 8px; justify-content: flex-end; }
</style>
