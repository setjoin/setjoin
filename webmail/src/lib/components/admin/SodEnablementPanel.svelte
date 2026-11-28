<svelte:options runes={true} />
<script lang="ts">
	import { onMount } from 'svelte';
	import { Dialog, Switch, Button, Badge, Spinner } from '$lib/components/ui';
	import { adminGetSodMode, adminSetSodMode, type SodModeStatus } from '$lib/admin/roles';
	import { adminPermissions, hasPermission } from '$lib/stores/auth';
	import { getAuditPolicy } from '$lib/admin/client';
	import ReasonPrompt from '$lib/components/admin/ReasonPrompt.svelte';
	import { parseError } from '$lib/errors';
	import { t } from '$lib/i18n';

	type PanelState = 'loading' | 'clean' | 'error' | 'violations' | 'enabled';

	let status = $state<SodModeStatus | null>(null);
	let panelState = $state<PanelState>('loading');
	let fetchError = $state('');
	let saving = $state(false);
	let saveError = $state('');

	// ── Audit policy: reason-required gate ──
	// ponytail: fetched once on mount; false = no prompt (default policy)
	let securityReasonRequired = $state(false);
	let sodReasonPromptOpen = $state(false);
	let pendingSodEnabled = $state<boolean | null>(null);

	let groupedViolations = $derived(groupByType(status?.violations ?? []));
	let totalViolations = $derived(status?.violations?.length ?? 0);

	function groupByType(violations: SodModeStatus['violations']) {
		const groups: Record<string, SodModeStatus['violations']> = {};
		for (const v of violations) {
			groups[v.violationType] ??= [];
			groups[v.violationType].push(v);
		}
		return groups;
	}

	const descId = `sod-panel-desc-${Math.random().toString(36).slice(2)}`;

	onMount(async () => {
		// ponytail: audit policy failure is non-fatal
		void getAuditPolicy().then((p) => {
			securityReasonRequired = p.reasonRequiredAreas.includes('security');
		}).catch(() => { /* non-fatal: default = no prompt */ });
		await load();
	});

	async function load() {
		panelState = 'loading';
		fetchError = '';
		try {
			status = await adminGetSodMode();
			if (status.enabled) {
				panelState = 'enabled';
			} else if (status.violations.length === 0) {
				panelState = 'clean';
			} else {
				panelState = 'violations';
			}
		} catch (e) {
			fetchError = parseError(e).message;
			panelState = 'error';
		}
	}

	async function doToggle(wantEnabled: boolean, reason?: string) {
		saving = true;
		saveError = '';
		try {
			await adminSetSodMode(wantEnabled, reason);
			await load();
		} catch (e) {
			saveError = parseError(e).message;
		} finally {
			saving = false;
		}
	}

	function toggle(wantEnabled: boolean) {
		if (wantEnabled && panelState !== 'clean') return;
		if (!wantEnabled && panelState !== 'enabled') return;
		if (securityReasonRequired) {
			pendingSodEnabled = wantEnabled;
			sodReasonPromptOpen = true;
		} else {
			void doToggle(wantEnabled);
		}
	}

	function onSodReasonSubmit(reason: string) {
		sodReasonPromptOpen = false;
		if (pendingSodEnabled !== null) {
			void doToggle(pendingSodEnabled, reason);
			pendingSodEnabled = null;
		}
	}

	function onSodReasonCancel() {
		sodReasonPromptOpen = false;
		pendingSodEnabled = null;
	}

	function resolveHref(v: { violationType: string }): string {
		if (v.violationType === 'legacy_admin_role') return '/admin/auth';
		return '/admin/roles';
	}

	function violationTypeLabel(type: string): string {
		const key = `admin.sod.violation_type_${type}` as Parameters<typeof t>[0];
		return t(key) || type;
	}
</script>

<div class="sod-panel">
	<div class="sod-panel__header">
		<div class="sod-panel__title-row">
			<h3 class="sod-panel__title">{t('admin.sod.panel_title')}</h3>
			{#if panelState === 'loading'}
				<Spinner size={16} label={t('common.loading')} />
			{:else if panelState === 'enabled'}
				<Badge variant="success" label={t('admin.sod.enabled_badge')} />
			{/if}
		</div>

		{#if panelState !== 'loading' && panelState !== 'error'}
			{@const isDisabled = panelState === 'violations' || saving || !hasPermission($adminPermissions, 'security.write')}
			{@const isChecked = panelState === 'enabled'}
			<div
				class="sod-panel__toggle-row"
				role="group"
				aria-disabled={isDisabled ? 'true' : undefined}
				aria-describedby={isDisabled && !isChecked ? descId : undefined}
			>
				<Switch
					checked={isChecked}
					disabled={isDisabled}
					label={t('admin.sod.toggle_label')}
					onchange={(e) => toggle((e.currentTarget as HTMLInputElement).checked)}
				/>
				{#if isDisabled && !isChecked}
					<span id={descId} class="sod-panel__caption" aria-live="polite">
						{t('admin.sod.resolve_to_enable', { count: String(totalViolations) })}
					</span>
				{/if}
			</div>
		{/if}
	</div>

	{#if panelState === 'loading'}
		<p class="sod-panel__checking">{t('admin.sod.checking')}</p>
	{:else if panelState === 'error'}
		<div class="sod-panel__error" role="alert">
			<p>{t('admin.sod.check_failed')}{fetchError}</p>
			<Button variant="ghost" size="sm" onclick={load}>{t('admin.sod.retry')}</Button>
		</div>
	{:else if panelState === 'clean'}
		<div class="sod-panel__clean" role="status">
			<p class="sod-panel__clean-msg">{t('admin.sod.no_conflicts')}</p>
		</div>
	{:else if panelState === 'violations'}
		{#if saveError}
			<div class="sod-panel__error" role="alert">{saveError}</div>
		{/if}
		<div class="sod-panel__violations">
			<p class="sod-panel__violations-count">
				{t('admin.sod.violations_count', { count: String(totalViolations) })}
			</p>
			<ul class="sod-panel__list" role="list" aria-label={t('admin.sod.violations_list_label')}>
				{#each Object.entries(groupedViolations) as [type, rows]}
					<li class="sod-panel__group">
						<span class="sod-panel__type-label">{violationTypeLabel(type)}</span>
						<ul class="sod-panel__type-rows" role="list">
							{#each rows as v}
								<li class="sod-panel__row" role="listitem">
									<span class="sod-panel__danger-dot" aria-hidden="true"></span>
									<code class="sod-panel__subject">{v.subject}</code>
									<span class="sod-panel__detail">{v.detail}</span>
									<a href={resolveHref(v)} class="sod-panel__action-link">
										{#if v.violationType === 'legacy_admin_role'}
											{t('admin.sod.fix_in_auth')}
										{:else}
											{t('admin.sod.resolve_link')}
										{/if}
									</a>
								</li>
							{/each}
						</ul>
					</li>
				{/each}
			</ul>
		</div>
	{:else if panelState === 'enabled'}
		<div class="sod-panel__enabled-actions">
			<Button variant="ghost" size="sm" onclick={() => toggle(false)} disabled={!hasPermission($adminPermissions, 'security.write')}>
				{t('admin.sod.disable')}
			</Button>
		</div>
	{/if}
</div>

{#if sodReasonPromptOpen}
	<!-- ponytail: reason prompt only when policy requires it for 'security' area -->
	<Dialog open={sodReasonPromptOpen} title={t('admin.audit.reason.dialog_title')} onClose={onSodReasonCancel}>
		{#snippet children()}
			<ReasonPrompt
				area="security"
				onSubmit={onSodReasonSubmit}
				onCancel={onSodReasonCancel}
				submitLabel={pendingSodEnabled ? t('admin.sod.toggle_label') : t('admin.sod.disable')}
			/>
		{/snippet}
	</Dialog>
{/if}

<style>
	.sod-panel {
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		padding: var(--space-4);
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
		background: var(--surface-card);
	}
	.sod-panel__header {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.sod-panel__title-row {
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}
	.sod-panel__title {
		font-size: var(--text-base);
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
		margin: 0;
	}
	.sod-panel__toggle-row {
		display: flex;
		align-items: center;
		gap: var(--space-3);
		flex-wrap: wrap;
	}
	.sod-panel__caption {
		color: var(--text-tertiary);
		font-size: var(--text-xs);
	}
	.sod-panel__checking {
		color: var(--text-secondary);
		font-size: var(--text-sm);
	}
	.sod-panel__error {
		background: var(--danger-bg);
		color: var(--danger-fg);
		border-radius: var(--radius-sm);
		padding: var(--space-3);
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}
	.sod-panel__clean {
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}
	.sod-panel__clean-msg {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.sod-panel__violations-count {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
		margin: 0;
	}
	.sod-panel__list {
		list-style: none;
		padding: 0;
		margin: var(--space-2) 0 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		max-height: 320px;
		overflow-y: auto;
	}
	.sod-panel__group {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.sod-panel__type-label {
		font-size: var(--text-xs);
		font-weight: var(--weight-semibold);
		color: var(--text-secondary);
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}
	.sod-panel__type-rows {
		list-style: none;
		padding: 0;
		margin: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.sod-panel__row {
		display: flex;
		align-items: baseline;
		gap: var(--space-2);
		padding: var(--space-1) var(--space-2);
		border-radius: var(--radius-sm);
		font-size: var(--text-sm);
	}
	.sod-panel__danger-dot {
		width: 7px;
		height: 7px;
		border-radius: var(--radius-full);
		background: var(--danger-solid);
		flex: none;
		margin-top: 4px;
	}
	.sod-panel__subject {
		font-family: var(--font-mono);
		font-size: var(--text-xs);
		color: var(--text-primary);
	}
	.sod-panel__detail {
		color: var(--text-tertiary);
		font-size: var(--text-xs);
		flex: 1;
	}
	.sod-panel__action-link {
		font-size: var(--text-xs);
		color: var(--link);
		text-decoration: none;
		white-space: nowrap;
		flex: none;
	}
	.sod-panel__action-link:hover {
		text-decoration: underline;
	}
	.sod-panel__enabled-actions {
		display: flex;
		gap: var(--space-2);
	}
</style>
