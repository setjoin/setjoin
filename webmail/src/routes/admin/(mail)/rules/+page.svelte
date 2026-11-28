<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import {
		adminRuleList,
		adminRuleDelete,
		adminRuleUpdate,
		adminFetch,
		type AdminRule
	} from '$lib/admin/client';
	import { parseError } from '$lib/errors';
	import { adminPermissions, hasPermission } from '$lib/stores/auth';
	import {
		Card, Table, Tabs, Badge, Button, IconButton, Switch, Input, Select,
		EmptyState, Spinner, showToast,
		type TableColumn, type TabItem,
	} from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';

	type BadgeVariant = 'neutral' | 'success' | 'warning' | 'danger' | 'info' | 'accent';

	let rules = $state<AdminRule[]>([]);
	let loading = $state(true);
	let error = $state('');
	let toggling = $state<Set<number>>(new Set());

	// DLP tab state
	let tab = $state<'rules' | 'dlp'>('rules');
	let dlpPatterns = $state<DLPPattern[]>([]);
	let dlpLoading = $state(false);
	let dlpError = $state('');
	let showDlpForm = $state(false);
	let dlpFormName = $state('');
	let dlpFormRegex = $state('');
	let dlpFormSeverity = $state('medium');
	let dlpFormEnabled = $state(true);
	let dlpTestText = $state('');
	let dlpTestResults = $state<string[]>([]);

	interface DLPPattern {
		name: string;
		regex: string;
		severity: string;
		enabled: boolean;
	}

	const TAB_ITEMS: TabItem[] = [
		{ id: 'rules', label: 'Mail rules' },
		{ id: 'dlp', label: 'DLP patterns' },
	];

	const RULE_COLUMNS: TableColumn[] = [
		{ key: 'name', label: 'Name', sortable: false },
		{ key: 'type', label: 'Type', sortable: false },
		{ key: 'runOn', label: 'Run on', sortable: false },
		{ key: 'priority', label: 'Priority', sortable: false },
		{ key: 'enabled', label: 'Enabled', sortable: false },
		{ key: 'conditions', label: 'Conditions', sortable: false, mono: true },
		{ key: 'actions', label: '', sortable: false },
	];

	const DLP_COLUMNS: TableColumn[] = [
		{ key: 'name', label: 'Name', sortable: false },
		{ key: 'regex', label: 'Regex', sortable: false, mono: true },
		{ key: 'severity', label: 'Severity', sortable: false },
		{ key: 'enabled', label: 'Enabled', sortable: false },
		{ key: 'actions', label: '', sortable: false },
	];

	const SEVERITY_OPTIONS = [
		{ value: 'critical', label: 'Critical — Block' },
		{ value: 'high', label: 'High — Quarantine' },
		{ value: 'medium', label: 'Medium — Notify admin' },
		{ value: 'low', label: 'Low — Warn' },
	];

	onMount(async () => {
		await refreshRules();
	});

	async function refreshRules() {
		loading = true;
		try {
			rules = await adminRuleList();
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	async function loadDLP() {
		dlpLoading = true;
		dlpError = '';
		try {
			const res = await adminFetch('/admin/dlp/patterns');
			dlpPatterns = await res.json();
		} catch (e) {
			dlpError = parseError(e).message;
		} finally {
			dlpLoading = false;
		}
	}

	async function saveDLP() {
		if (dlpLoading) return;
		dlpLoading = true;
		try {
			await adminFetch('/admin/dlp/patterns', {
				method: 'PUT',
				body: JSON.stringify(dlpPatterns)
			});
			await loadDLP();
		} catch (e) {
			dlpError = parseError(e).message;
		} finally {
			dlpLoading = false;
		}
	}

	function toggleDlpPattern(idx: number) {
		dlpPatterns[idx].enabled = !dlpPatterns[idx].enabled;
		saveDLP();
	}

	function removeDlpPattern(idx: number) {
		dlpPatterns.splice(idx, 1);
		saveDLP();
	}

	function addDlpPattern() {
		if (!dlpFormName.trim() || !dlpFormRegex.trim()) return;
		dlpPatterns = [...dlpPatterns, {
			name: dlpFormName.trim(),
			regex: dlpFormRegex.trim(),
			severity: dlpFormSeverity,
			enabled: dlpFormEnabled
		}];
		dlpFormName = '';
		dlpFormRegex = '';
		showDlpForm = false;
		saveDLP();
	}

	function testDlpPattern() {
		if (!dlpTestText.trim()) { dlpTestResults = []; return; }
		dlpTestResults = [];
		for (const p of dlpPatterns) {
			if (!p.enabled) continue;
			try {
				if (new RegExp(p.regex, 'i').test(dlpTestText)) {
					dlpTestResults = [...dlpTestResults, `${p.name} (${p.severity})`];
				}
			} catch { /* invalid regex */ }
		}
	}

	function severityVariant(s: string): BadgeVariant {
		switch (s) {
			case 'critical': return 'danger';
			case 'high': return 'warning';
			case 'medium': return 'warning';
			case 'low': return 'success';
			default: return 'neutral';
		}
	}

	$effect(() => { if (tab === 'dlp') loadDLP(); });

	async function toggleRule(r: AdminRule) {
		if (toggling.has(r.id)) return;
		toggling = new Set([...toggling, r.id]);
		try {
			await adminRuleUpdate(r.id, { enabled: !r.enabled });
			await refreshRules();
		} catch (e) {
			error = parseError(e).message;
		} finally {
			const next = new Set(toggling);
			next.delete(r.id);
			toggling = next;
		}
	}

	async function removeRule(id: number) {
		try {
			await adminRuleDelete(id);
			await refreshRules();
			showToast('Rule deleted');
		} catch (e) {
			error = parseError(e).message;
		}
	}

	function formatConditions(conds: unknown): string {
		if (!conds) return '-';
		try {
			return JSON.stringify(conds).slice(0, 60);
		} catch {
			return String(conds);
		}
	}

	let ruleRows = $derived(rules as unknown as Record<string, unknown>[]);
	let dlpRows = $derived(dlpPatterns as unknown as Record<string, unknown>[]);
</script>

<header class="page-header">
	<div class="page-header-left">
		<h1>Rules</h1>
		<p class="page-desc">Mailbox and transport rules, and data-loss-prevention patterns.</p>
	</div>
</header>

<h2 class="sr-only">{tab === 'rules' ? 'Mailbox and transport rules' : 'Data-loss-prevention patterns'}</h2>
<Tabs items={TAB_ITEMS} active={tab} onChange={(id: string) => (tab = id as 'rules' | 'dlp')} />

{#if error}
	<p class="rules-error" role="alert">{error}</p>
{/if}

{#if tab === 'rules'}
	{#if loading}
		<div class="rules-loading">
			<Spinner size={28} />
			<div>Loading rules…</div>
		</div>
	{:else if rules.length === 0}
		<EmptyState title="No rules configured." watermark={true} />
	{:else}
		<Card flush={true}>
			{#snippet children()}
				<Table columns={RULE_COLUMNS} rows={ruleRows}>
					{#snippet cell(row, col)}
						{@const r = row as unknown as AdminRule}
						{#if col.key === 'name'}
							{r.name}
						{:else if col.key === 'type'}
							<Badge variant={r.isTransportRule ? 'accent' : 'info'} label={r.isTransportRule ? 'Transport' : 'Mailbox'} />
						{:else if col.key === 'runOn'}
							<Badge variant={r.runOn === 'received' ? 'success' : 'warning'} label={r.runOn} />
						{:else if col.key === 'priority'}
							{r.priority}
						{:else if col.key === 'enabled'}
							<Switch checked={r.enabled} onchange={() => toggleRule(r)} disabled={toggling.has(r.id) || !hasPermission($adminPermissions, 'mail.pipeline')} />
						{:else if col.key === 'conditions'}
							<code class="cond-code">{formatConditions(r.conditions)}</code>
						{:else if col.key === 'actions'}
							<IconButton label="Delete rule" variant="ghost" size="sm" disabled={!hasPermission($adminPermissions, 'mail.pipeline')} onclick={() => removeRule(r.id)}>
								<Icon name="Trash2" size={14} strokeWidth={1.75} />
							</IconButton>
						{/if}
					{/snippet}
				</Table>
			{/snippet}
		</Card>
	{/if}
{:else}
	{#if dlpError}
		<p class="rules-error" role="alert">{dlpError}</p>
	{/if}

	<Card title="DLP patterns">
		{#snippet actions()}
			<Button variant="secondary" size="sm" disabled={!hasPermission($adminPermissions, 'mail.security')} onclick={() => (showDlpForm = !showDlpForm)}>
				<Icon name="Plus" size={14} strokeWidth={1.75} />
				Add pattern
			</Button>
		{/snippet}
		{#snippet children()}
			{#if showDlpForm}
				<div class="dlp-form">
					<div class="dlp-form-field"><Input type="text" placeholder="Pattern name" bind:value={dlpFormName} /></div>
					<div class="dlp-form-field"><Input type="text" placeholder="Regex pattern" mono={true} bind:value={dlpFormRegex} /></div>
					<div class="dlp-form-field"><Select options={SEVERITY_OPTIONS} bind:value={dlpFormSeverity} /></div>
					<Switch checked={dlpFormEnabled} label="Enabled" onchange={(e) => (dlpFormEnabled = (e.target as HTMLInputElement).checked)} />
					<Button variant="primary" size="sm" disabled={!hasPermission($adminPermissions, 'mail.security')} onclick={addDlpPattern}>Save</Button>
				</div>
			{/if}

			{#if dlpLoading}
				<div class="rules-loading">
					<Spinner size={28} />
					<div>Loading patterns…</div>
				</div>
			{:else if dlpPatterns.length === 0}
				<EmptyState title="No DLP patterns configured." />
			{:else}
				<Table columns={DLP_COLUMNS} rows={dlpRows}>
					{#snippet cell(row, col)}
						{@const p = row as unknown as DLPPattern}
						{@const idx = dlpPatterns.indexOf(p)}
						{#if col.key === 'name'}
							{p.name}
						{:else if col.key === 'regex'}
							<code class="cond-code">{p.regex.length > 50 ? p.regex.slice(0, 50) + '…' : p.regex}</code>
						{:else if col.key === 'severity'}
							<Badge variant={severityVariant(p.severity)} label={p.severity} />
						{:else if col.key === 'enabled'}
							<Switch checked={p.enabled} onchange={() => toggleDlpPattern(idx)} disabled={!hasPermission($adminPermissions, 'mail.security')} />
						{:else if col.key === 'actions'}
							<IconButton label="Remove pattern" variant="ghost" size="sm" disabled={!hasPermission($adminPermissions, 'mail.security')} onclick={() => removeDlpPattern(idx)}>
								<Icon name="Trash2" size={14} strokeWidth={1.75} />
							</IconButton>
						{/if}
					{/snippet}
				</Table>
			{/if}

			<div class="dlp-test-section">
				<h3 class="dlp-test-head">Test patterns</h3>
				<div class="dlp-test">
					<div class="dlp-test-field"><Input type="text" placeholder="Paste sample text to test…" bind:value={dlpTestText} /></div>
					<Button variant="secondary" size="md" onclick={testDlpPattern}>Check</Button>
				</div>
				{#if dlpTestResults.length > 0}
					<div class="dlp-results">
						<p class="dlp-results-count">Matches: {dlpTestResults.length}</p>
						{#each dlpTestResults as r}
							<Badge variant="warning" label={r} />
						{/each}
					</div>
				{/if}
			</div>
		{/snippet}
	</Card>
{/if}

<style>
	.page-header {
		margin-bottom: 16px;
	}

	.page-header h1 {
		font-family: var(--font-sans);
		font-size: var(--text-2xl);
		font-weight: var(--weight-semibold);
		letter-spacing: var(--tracking-heading);
		color: var(--text-primary);
		margin: 0 0 4px;
	}

	.page-desc {
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0;
		line-height: var(--leading-normal);
	}

	.rules-error {
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--danger-fg);
		background: var(--danger-bg);
		border-radius: var(--radius-sm);
		padding: 8px 12px;
		margin: 12px 0;
	}

	.rules-loading {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: 16px;
		padding: 48px 16px;
		color: var(--text-secondary);
		font-family: var(--font-sans);
		font-size: var(--text-sm);
	}

	.cond-code {
		font-family: var(--font-mono);
		font-size: var(--text-2xs);
		color: var(--text-tertiary);
	}

	.dlp-form {
		display: flex;
		flex-wrap: wrap;
		gap: 10px;
		align-items: center;
		padding-bottom: 14px;
		margin-bottom: 14px;
		border-bottom: 1px solid var(--border-subtle);
	}

	.dlp-form-field {
		flex: 1 1 180px;
		min-width: 140px;
	}

	.dlp-test-section {
		margin-top: 16px;
	}

	.dlp-test-head {
		margin: 0 0 8px;
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		font-weight: var(--weight-semibold);
		color: var(--text-primary);
	}

	.dlp-test {
		display: flex;
		gap: 8px;
		align-items: center;
	}

	.dlp-test-field {
		flex: 1;
		min-width: 0;
	}

	.dlp-results {
		margin-top: 8px;
		display: flex;
		flex-wrap: wrap;
		gap: 6px;
		align-items: center;
	}

	.dlp-results-count {
		font-family: var(--font-sans);
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		margin: 0;
		width: 100%;
	}
</style>
