<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { goto } from '$app/navigation';
	import { t } from '$lib/i18n';
	import { parseError } from '$lib/errors';
	import {
		listRules, createRule, updateRule, deleteRule,
		applyRuleRetro, getApplyStatus,
		type UserRule, type RuleInput, type RunOn, type RetroWindow
	} from '$lib/api/rules';
	import {
		Card, Button, IconButton, Input, Select, Switch, Checkbox,
		EmptyState, Spinner, showToast
	} from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';

	// ── Rule-engine vocab (mirrors eval_condition + apply_action in rule_engine.sql) ──
	const FIELDS = ['from_addr', 'subject', 'body', 'spam_score', 'size_bytes', 'has_attachments', 'sender_domain'] as const;
	const OPS = ['contains', 'not_contains', 'equals', 'not_equals', 'starts_with', 'gt', 'lt', 'gt_bytes', 'lt_bytes', 'is_true', 'matches_regex', 'in_list'] as const;
	const ACTIONS = ['move_to', 'flag', 'mark_read', 'categorize', 'delete', 'forward_to', 'add_header', 'bcc', 'append_footer', 'redirect'] as const;
	const RUN_ON: RunOn[] = ['server', 'client', 'both'];

	// action type → single param key (null = no parameter)
	function paramKeyFor(type: string): string | null {
		switch (type) {
			case 'move_to': return 'folder';
			case 'categorize': return 'category';
			case 'forward_to': return 'address';
			case 'add_header': return 'value';
			case 'bcc': return 'address';
			case 'redirect': return 'address';
			case 'append_footer': return 'text';
			default: return null;
		}
	}

	const fieldOptions = FIELDS.map((f) => ({ value: f, label: t(`rules.field.${f}`) }));
	const opOptions = OPS.map((o) => ({ value: o, label: t(`rules.op.${o}`) }));
	const actionOptions = ACTIONS.map((a) => ({ value: a, label: t(`rules.action.${a}`) }));
	const runOnOptions = RUN_ON.map((r) => ({ value: r, label: t(`rules.runOn.${r}`) }));

	// ── Form model (a single param string per action row; mapped to params on save) ──
	type CondRow = { field: string; op: string; value: string };
	type ActionRow = { type: string; param: string };
	type FormModel = {
		id: number | null;
		name: string;
		enabled: boolean;
		priority: string; // Input binds a string; parsed to number on save
		runOn: string; // Select binds a string; cast to RunOn on save
		stopProcessing: boolean;
		conditions: CondRow[];
		actions: ActionRow[];
	};

	let rules = $state<UserRule[]>([]);
	let loading = $state(true);
	let error = $state('');
	let form = $state<FormModel | null>(null);
	let saving = $state(false);

	onMount(async () => {
		await load();
		applyPrefill();
	});

	// "Create rule from message" (#4): seed a new draft from the sender/subject
	// passed as query params by the inbox reading pane, then strip them so a
	// refresh doesn't re-trigger the form.
	function applyPrefill() {
		const sp = $page.url.searchParams;
		const from = sp.get('prefillFrom') ?? '';
		const subject = sp.get('prefillSubject') ?? '';
		const domain = sp.get('prefillDomain') ?? '';
		if (!from && !subject && !domain) return;
		startNew();
		if (!form) return;
		const conds: CondRow[] = [];
		if (from) conds.push({ field: 'from_addr', op: 'contains', value: from });
		else if (domain) conds.push({ field: 'sender_domain', op: 'contains', value: domain });
		if (subject) conds.push({ field: 'subject', op: 'contains', value: subject });
		if (conds.length > 0) form.conditions = conds;
		goto('/settings/rules', { replaceState: true });
	}

	async function load() {
		loading = true;
		error = '';
		try {
			rules = await listRules();
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	function blankForm(): FormModel {
		return {
			id: null,
			name: '',
			enabled: true,
			priority: '0',
			runOn: 'server',
			stopProcessing: false,
			conditions: [{ field: 'subject', op: 'contains', value: '' }],
			actions: [{ type: 'move_to', param: '' }]
		};
	}

	function startNew() {
		form = blankForm();
		error = '';
	}

	function startEdit(r: UserRule) {
		form = {
			id: r.id,
			name: r.name,
			enabled: r.enabled,
			priority: String(r.priority),
			runOn: r.runOn,
			stopProcessing: r.stopProcessing,
			// Only flat simple conditions round-trip through the builder; grouped
			// conditions (created elsewhere) degrade to an empty condition list.
			conditions: (Array.isArray(r.conditions) ? r.conditions : [])
				.filter((c) => c && typeof c.field === 'string')
				.map((c) => ({ field: c.field, op: c.op, value: c.value ?? '' })),
			actions: (Array.isArray(r.actions) ? r.actions : []).map((a) => {
				const k = paramKeyFor(a.type);
				return { type: a.type, param: k ? (a.params?.[k] ?? '') : '' };
			})
		};
		error = '';
	}

	function cancel() {
		form = null;
		error = '';
	}

	function addCondition() {
		form?.conditions.push({ field: 'subject', op: 'contains', value: '' });
	}
	function removeCondition(i: number) {
		form?.conditions.splice(i, 1);
	}
	function addAction() {
		form?.actions.push({ type: 'move_to', param: '' });
	}
	function removeAction(i: number) {
		form?.actions.splice(i, 1);
	}

	function toInput(f: FormModel): RuleInput {
		return {
			name: f.name.trim(),
			enabled: f.enabled,
			priority: parseInt(f.priority, 10) || 0,
			runOn: f.runOn as RunOn,
			// Flat AND list of simple conditions (rule_engine handles this as implicit AND).
			conditions: f.conditions.map((c) => ({ field: c.field, op: c.op, value: c.value })),
			actions: f.actions.map((a) => {
				const k = paramKeyFor(a.type);
				return k ? { type: a.type, params: { [k]: a.param } } : { type: a.type };
			}),
			stopProcessing: f.stopProcessing
		};
	}

	async function save() {
		if (!form) return;
		if (!form.name.trim()) { error = t('rules.needName'); return; }
		if (form.actions.length === 0) { error = t('rules.needAction'); return; }
		saving = true;
		error = '';
		try {
			const input = toInput(form);
			if (form.id === null) {
				await createRule(input);
				showToast(t('rules.created'));
			} else {
				await updateRule(form.id, input);
				showToast(t('rules.updated'));
			}
			form = null;
			await load();
		} catch (e) {
			error = parseError(e).message;
		} finally {
			saving = false;
		}
	}

	async function toggle(r: UserRule) {
		try {
			await updateRule(r.id, {
				name: r.name,
				enabled: !r.enabled,
				priority: r.priority,
				runOn: r.runOn,
				conditions: r.conditions,
				actions: r.actions,
				stopProcessing: r.stopProcessing
			});
			await load();
		} catch (e) {
			error = parseError(e).message;
		}
	}

	async function remove(r: UserRule) {
		if (typeof window !== 'undefined' && !window.confirm(t('rules.deleteConfirm'))) return;
		try {
			await deleteRule(r.id);
			showToast(t('rules.deleted'));
			await load();
		} catch (e) {
			error = parseError(e).message;
		}
	}

	// ── Apply-to-existing-mail (retro sweep) ──
	const RETRO_WINDOWS: RetroWindow[] = ['90d', '1y', 'all'];
	let applyRuleId = $state<number | null>(null); // rule whose apply panel is open
	let applyWindow = $state<RetroWindow>('90d');
	let applyBusy = $state(false);
	let applyMsg = $state('');

	function openApply(r: UserRule) {
		applyRuleId = applyRuleId === r.id ? null : r.id;
		applyWindow = '90d';
		applyMsg = '';
	}

	async function runApply(r: UserRule) {
		applyBusy = true;
		applyMsg = t('rules.applyQueued');
		try {
			const { actionId } = await applyRuleRetro(r.id, applyWindow);
			// The dispatcher runs on a ~1-min cron tick; poll a bounded window.
			for (let i = 0; i < 48; i++) {
				await new Promise((res) => setTimeout(res, 2500));
				const st = await getApplyStatus(actionId);
				if (st.status === 'done') {
					const count = String(st.processed ?? 0);
					applyMsg = t('rules.applyDone', { count }) + (st.truncated ? t('rules.applyTruncated') : '');
					showToast(applyMsg);
					return;
				}
				if (st.status === 'failed') {
					applyMsg = t('rules.applyFailed');
					return;
				}
			}
			applyMsg = t('rules.applyStillRunning'); // still pending after the poll window
		} catch (e) {
			applyMsg = parseError(e).message;
		} finally {
			applyBusy = false;
		}
	}

	// Human-readable summary (rendered as TEXT — never {@html}).
	function summarize(r: UserRule): string {
		const conds = (Array.isArray(r.conditions) ? r.conditions : [])
			.filter((c) => c && typeof c.field === 'string')
			.map((c) => {
				const f = t(`rules.field.${c.field}`);
				const op = t(`rules.op.${c.op}`);
				return c.op === 'is_true' ? `${f} ${op}` : `${f} ${op} ${c.value}`;
			})
			.join(` ${t('rules.and')} `);
		const acts = (Array.isArray(r.actions) ? r.actions : [])
			.map((a) => {
				const label = t(`rules.action.${a.type}`);
				const k = paramKeyFor(a.type);
				const p = k ? a.params?.[k] : '';
				return p ? `${label} → ${p}` : label;
			})
			.join(', ');
		if (!conds) return acts;
		return `${conds} · ${acts}`;
	}
</script>

<div class="sj-rules-page">
	<div class="sj-rules-head">
		<div>
			<h1 class="sj-page-title">{t('rules.title')}</h1>
			<p class="sj-rules-subtitle">{t('rules.subtitle')}</p>
		</div>
		{#if !form}
			<Button variant="primary" size="sm" onclick={startNew}>
				<Icon name="Plus" size={14} strokeWidth={1.75} />
				{t('rules.new')}
			</Button>
		{/if}
	</div>

	{#if error}
		<p class="sj-rules-error" role="alert">{error}</p>
	{/if}

	{#if form}
		<Card title={form.id === null ? t('rules.new') : t('rules.edit')}>
			<div class="sj-rules-form">
				<Input label={t('rules.name')} placeholder={t('rules.namePlaceholder')} bind:value={form.name} />

				<div class="sj-rules-section">
					<span class="sj-rules-label">{t('rules.conditions')}</span>
					{#each form.conditions as cond, i (i)}
						<div class="sj-rules-row">
							<Select options={fieldOptions} bind:value={cond.field} />
							<Select options={opOptions} bind:value={cond.op} />
							{#if cond.op !== 'is_true'}
								<Input placeholder={t('rules.value')} bind:value={cond.value} />
							{/if}
							<IconButton label={t('rules.removeRow')} variant="ghost" size="sm" onclick={() => removeCondition(i)}>
								<Icon name="X" size={14} strokeWidth={1.75} />
							</IconButton>
						</div>
					{/each}
					<Button variant="ghost" size="sm" onclick={addCondition}>
						<Icon name="Plus" size={14} strokeWidth={1.75} />
						{t('rules.addCondition')}
					</Button>
				</div>

				<div class="sj-rules-section">
					<span class="sj-rules-label">{t('rules.actions')}</span>
					{#each form.actions as act, i (i)}
						{@const pk = paramKeyFor(act.type)}
						<div class="sj-rules-row">
							<Select options={actionOptions} bind:value={act.type} />
							{#if pk}
								<Input placeholder={t(`rules.actionParam.${act.type}`)} bind:value={act.param} />
							{/if}
							<IconButton label={t('rules.removeRow')} variant="ghost" size="sm" onclick={() => removeAction(i)}>
								<Icon name="X" size={14} strokeWidth={1.75} />
							</IconButton>
						</div>
					{/each}
					<Button variant="ghost" size="sm" onclick={addAction}>
						<Icon name="Plus" size={14} strokeWidth={1.75} />
						{t('rules.addAction')}
					</Button>
				</div>

				<div class="sj-rules-grid">
					<Input label={t('rules.priority')} type="number" bind:value={form.priority} />
					<Select label={t('rules.runOn')} options={runOnOptions} bind:value={form.runOn} />
				</div>

				<Switch label={t('rules.enabled')} checked={form.enabled} onchange={(e) => (form!.enabled = e.currentTarget.checked)} />
				<Checkbox label={t('rules.stopProcessing')} checked={form.stopProcessing} onchange={(e) => (form!.stopProcessing = e.currentTarget.checked)} />

				<div class="sj-rules-form-footer">
					<Button variant="ghost" size="sm" onclick={cancel}>{t('rules.cancel')}</Button>
					<Button variant="primary" size="sm" onclick={save} disabled={saving}>
						{saving ? t('rules.saving') : t('rules.save')}
					</Button>
				</div>
			</div>
		</Card>
	{:else if loading}
		<div class="sj-rules-loading"><Spinner size={20} label={t('rules.loading')} /></div>
	{:else if rules.length === 0}
		<EmptyState title={t('rules.empty')} />
	{:else}
		<div class="sj-rules-list">
			{#each rules as r (r.id)}
				<div class="sj-rules-entry">
					<div class="sj-rules-item">
						<Switch checked={r.enabled} onchange={() => toggle(r)} />
						<div class="sj-rules-item__body">
							<span class="sj-rules-item__name">{r.name}</span>
							<span class="sj-rules-item__summary">{summarize(r)}</span>
						</div>
						<IconButton label={t('rules.applyExisting')} variant="ghost" size="sm" onclick={() => openApply(r)}>
							<Icon name="RefreshCw" size={14} strokeWidth={1.75} />
						</IconButton>
						<IconButton label={t('rules.edit')} variant="ghost" size="sm" onclick={() => startEdit(r)}>
							<Icon name="Pencil" size={14} strokeWidth={1.75} />
						</IconButton>
						<IconButton label={t('rules.delete')} variant="ghost" size="sm" onclick={() => remove(r)}>
							<Icon name="Trash2" size={14} strokeWidth={1.75} />
						</IconButton>
					</div>

					{#if applyRuleId === r.id}
						<div class="sj-rules-apply">
							<span class="sj-rules-apply__title">{t('rules.applyExisting')}</span>
							<fieldset class="sj-rules-apply__windows">
								{#each RETRO_WINDOWS as win (win)}
									<label class="sj-rules-apply__opt">
										<input type="radio" name="apply-window-{r.id}" value={win} bind:group={applyWindow} disabled={applyBusy} />
										<span>{t(`rules.applyWindow.${win}`)}</span>
									</label>
								{/each}
							</fieldset>
							<div class="sj-rules-apply__actions">
								<Button variant="ghost" size="sm" onclick={() => (applyRuleId = null)} disabled={applyBusy}>
									{t('rules.cancel')}
								</Button>
								<Button variant="primary" size="sm" onclick={() => runApply(r)} disabled={applyBusy}>
									{applyBusy ? t('rules.applyRunning') : t('rules.applyRun')}
								</Button>
							</div>
							{#if applyMsg}
								<p class="sj-rules-apply__msg" role="status">{applyMsg}</p>
							{/if}
						</div>
					{/if}
				</div>
			{/each}
		</div>
	{/if}
</div>

<style>
	.sj-rules-page {
		max-width: 720px;
		margin: 0 auto;
		padding: clamp(16px, 4vw, 28px) clamp(12px, 4vw, 24px) 48px;
	}

	.sj-rules-head {
		display: flex;
		align-items: flex-start;
		justify-content: space-between;
		gap: 12px;
		margin-bottom: 16px;
	}

	.sj-page-title {
		font-size: clamp(20px, 16px + 1.2vw, 24px);
		font-weight: var(--weight-semibold);
		letter-spacing: var(--tracking-display);
		margin: 0;
		color: var(--text-primary);
	}

	.sj-rules-subtitle {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 4px 0 0;
	}

	.sj-rules-error {
		font-size: var(--text-sm);
		color: var(--danger-fg);
		background: var(--danger-bg);
		border-radius: var(--radius-sm);
		padding: 8px 12px;
		margin: 0 0 12px;
	}

	.sj-rules-loading {
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 3rem;
	}

	.sj-rules-form {
		display: flex;
		flex-direction: column;
		gap: 14px;
	}

	.sj-rules-section {
		display: flex;
		flex-direction: column;
		gap: 8px;
	}

	.sj-rules-label {
		font-size: var(--text-sm);
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
	}

	.sj-rules-row {
		display: flex;
		gap: 8px;
		align-items: center;
		flex-wrap: wrap;
	}

	.sj-rules-row :global(.sj-select-wrap),
	.sj-rules-row :global(.sj-field) {
		flex: 1 1 140px;
		min-width: 120px;
	}

	.sj-rules-grid {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 12px;
	}

	.sj-rules-form-footer {
		display: flex;
		justify-content: flex-end;
		gap: 8px;
		margin-top: 4px;
	}

	.sj-rules-list {
		display: flex;
		flex-direction: column;
		gap: 8px;
	}

	.sj-rules-item {
		display: flex;
		align-items: center;
		gap: 12px;
		padding: 12px 14px;
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
	}

	.sj-rules-item__body {
		display: flex;
		flex-direction: column;
		gap: 2px;
		flex: 1;
		min-width: 0;
	}

	.sj-rules-item__name {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
	}

	.sj-rules-item__summary {
		font-size: var(--text-xs);
		color: var(--text-caption);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.sj-rules-entry {
		display: flex;
		flex-direction: column;
	}

	.sj-rules-apply {
		display: flex;
		flex-direction: column;
		gap: 10px;
		margin-top: 6px;
		padding: 12px 14px;
		background: var(--surface-subtle, var(--surface-card));
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
	}

	.sj-rules-apply__title {
		font-size: var(--text-sm);
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
	}

	.sj-rules-apply__windows {
		display: flex;
		flex-wrap: wrap;
		gap: 14px;
		border: 0;
		margin: 0;
		padding: 0;
	}

	.sj-rules-apply__opt {
		display: flex;
		align-items: center;
		gap: 6px;
		font-size: var(--text-sm);
		color: var(--text-secondary);
		cursor: pointer;
	}

	.sj-rules-apply__actions {
		display: flex;
		justify-content: flex-end;
		gap: 8px;
	}

	.sj-rules-apply__msg {
		font-size: var(--text-xs);
		color: var(--text-secondary);
		margin: 0;
	}
</style>
