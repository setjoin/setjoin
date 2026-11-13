<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { Card, Select, Switch, Button, Dialog, Spinner, showToast } from '$lib/components/ui';
	import {
		adminFeatureList,
		adminFeatureSet,
		adminGetJitDefaults,
		adminPutJitDefaults,
	} from '$lib/admin/client';
	import { DURATION_PRESETS, splitWindow } from '$lib/admin/jitStatus';
	import { parseError } from '$lib/errors';
	import { t } from '$lib/i18n';

	let loading = $state(true);
	let error = $state('');
	let jitEnabled = $state(false);
	let confirmEnable = $state(false);
	let savingDefaults = $state(false);

	let defaultMaxStr = $state('480');
	let defaultRequire = $state(false);

	function fmt(minutes: number): string {
		const w = splitWindow(minutes);
		return t(w.unit === 'hr' ? 'admin.jit.dur_hr' : 'admin.jit.dur_min', { n: String(w.n) });
	}

	let options = $derived(
		[...new Set<number>([...DURATION_PRESETS, Number(defaultMaxStr)])]
			.sort((a, b) => a - b)
			.map((m) => ({ value: String(m), label: fmt(m) }))
	);

	onMount(async () => {
		try {
			const [features, defaults] = await Promise.all([adminFeatureList(), adminGetJitDefaults()]);
			jitEnabled = features.find((f) => f.key === 'rbac.jit')?.enabled ?? false;
			defaultMaxStr = String(defaults.defaultMaxDurationMinutes);
			defaultRequire = defaults.defaultRequireJustification;
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	});

	// Turning ON dormants every eligible admin → confirm first. OFF is the strict no-op.
	function onToggle(e: Event & { currentTarget: EventTarget & HTMLInputElement }) {
		if (e.currentTarget.checked) {
			confirmEnable = true; // jitEnabled is already true (bound); apply only after confirm
		} else {
			void apply(false);
		}
	}

	async function apply(enabled: boolean) {
		const reason = prompt(`${enabled ? 'Enable' : 'Disable'} JIT activation — audit reason (required):`)?.trim();
		if (!reason) {
			jitEnabled = !enabled;
			return;
		}
		try {
			await adminFeatureSet('rbac.jit', enabled, reason);
			jitEnabled = enabled;
		} catch (e) {
			error = parseError(e).message;
			jitEnabled = !enabled; // revert the optimistic flip
		}
	}

	function doConfirmEnable() {
		confirmEnable = false;
		void apply(true);
	}

	function cancelEnable() {
		confirmEnable = false;
		jitEnabled = false; // revert the optimistic flip
	}

	async function saveDefaults() {
		savingDefaults = true;
		error = '';
		try {
			await adminPutJitDefaults({
				defaultMaxDurationMinutes: Number(defaultMaxStr),
				defaultRequireJustification: defaultRequire,
			});
			showToast(t('admin.jit.defaults_saved'));
		} catch (e) {
			error = parseError(e).message;
		} finally {
			savingDefaults = false;
		}
	}
</script>

{#if error}<div class="sj-alert-danger" role="alert">{error}</div>{/if}

{#if loading}
	<div class="jit-settings-loading"><Spinner size={20} label={t('common.loading')} /></div>
{:else}
	<Card>
		<div class="jit-settings">
			<Switch
				bind:checked={jitEnabled}
				label={t('admin.jit.toggle_label')}
				description={t('admin.jit.toggle_desc')}
				onchange={onToggle}
			/>
		</div>
	</Card>

	<Card>
		<div class="jit-settings">
			<div class="jit-settings-head">
				<strong>{t('admin.jit.defaults_title')}</strong>
				<span class="jit-settings-desc">{t('admin.jit.defaults_desc')}</span>
			</div>
			<Select label={t('admin.jit.policy_max_window')} {options} bind:value={defaultMaxStr} />
			<Switch
				checked={defaultRequire}
				label={t('admin.jit.policy_require_justif')}
				onchange={(e) => (defaultRequire = e.currentTarget.checked)}
			/>
			<div class="jit-settings-actions">
				<Button variant="primary" size="sm" onclick={saveDefaults} disabled={savingDefaults}>
					{savingDefaults ? t('common.loading') : t('admin.jit.defaults_save')}
				</Button>
			</div>
		</div>
	</Card>
{/if}

{#if confirmEnable}
	<Dialog open={true} title={t('admin.jit.toggle_confirm_title')} onClose={cancelEnable}>
		{#snippet children()}
			<p>{t('admin.jit.toggle_confirm_body')}</p>
		{/snippet}
		{#snippet footer()}
			<Button variant="ghost" onclick={cancelEnable}>{t('common.cancel')}</Button>
			<Button variant="primary" onclick={doConfirmEnable}>{t('admin.jit.toggle_confirm_cta')}</Button>
		{/snippet}
	</Dialog>
{/if}

<style>
	.jit-settings {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.jit-settings-head {
		display: flex;
		flex-direction: column;
		gap: 2px;
	}
	.jit-settings-head strong {
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	.jit-settings-desc {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}
	.jit-settings-actions {
		display: flex;
		justify-content: flex-end;
	}
	.jit-settings-loading {
		display: flex;
		justify-content: center;
		padding: var(--space-5);
	}
</style>
