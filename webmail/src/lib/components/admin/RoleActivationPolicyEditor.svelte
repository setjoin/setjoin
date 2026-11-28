<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { Select, Switch, Button, Spinner, showToast } from '$lib/components/ui';
	import {
		adminGetActivationPolicy,
		adminGetJitDefaults,
		adminPutActivationPolicy,
	} from '$lib/admin/client';
	import { DURATION_PRESETS, splitWindow } from '$lib/admin/jitStatus';
	import { parseError } from '$lib/errors';
	import { t } from '$lib/i18n';

	let { roleId }: { roleId: number } = $props();

	let loading = $state(true);
	let saving = $state(false);
	let error = $state('');
	let maxMinutes = $state(480);
	let requireJustification = $state(false);
	let defaultMax = $state(480);
	let defaultRequire = $state(false);

	function fmt(minutes: number): string {
		const w = splitWindow(minutes);
		return t(w.unit === 'hr' ? 'admin.jit.dur_hr' : 'admin.jit.dur_min', { n: String(w.n) });
	}

	onMount(async () => {
		try {
			const [policy, defaults] = await Promise.all([
				adminGetActivationPolicy(roleId),
				adminGetJitDefaults(),
			]);
			maxMinutes = policy.maxDurationMinutes;
			requireJustification = policy.requireJustification;
			defaultMax = defaults.defaultMaxDurationMinutes;
			defaultRequire = defaults.defaultRequireJustification;
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	});

	// Preset options, with the current value folded in if it isn't a standard preset.
	let options = $derived(
		[...new Set<number>([...DURATION_PRESETS, maxMinutes])]
			.sort((a, b) => a - b)
			.map((m) => ({ value: String(m), label: fmt(m) }))
	);
	let maxStr = $state('480');
	$effect(() => {
		maxStr = String(maxMinutes);
	});

	let inheritLine = $derived(
		t('admin.jit.policy_inherits', {
			window: fmt(defaultMax),
			justif: defaultRequire ? t('admin.jit.justif_required') : t('admin.jit.justif_optional'),
		})
	);

	async function save() {
		saving = true;
		error = '';
		try {
			await adminPutActivationPolicy(roleId, {
				maxDurationMinutes: Number(maxStr),
				requireJustification,
			});
			showToast(t('admin.jit.policy_saved'));
		} catch (e) {
			error = parseError(e).message;
		} finally {
			saving = false;
		}
	}
</script>

<div class="jit-policy">
	<div class="jit-policy-head">
		<strong>{t('admin.jit.policy_title')}</strong>
		<span class="jit-policy-inherit">{inheritLine}</span>
	</div>
	{#if error}<div class="sj-alert-danger" role="alert">{error}</div>{/if}
	{#if loading}
		<Spinner size={16} label={t('common.loading')} />
	{:else}
		<Select label={t('admin.jit.policy_max_window')} {options} bind:value={maxStr} />
		<Switch
			checked={requireJustification}
			label={t('admin.jit.policy_require_justif')}
			onchange={(e) => (requireJustification = e.currentTarget.checked)}
		/>
		<div class="jit-policy-actions">
			<Button variant="primary" size="sm" onclick={save} disabled={saving}>
				{saving ? t('common.loading') : t('admin.jit.policy_save')}
			</Button>
		</div>
	{/if}
</div>

<style>
	.jit-policy {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		padding: var(--space-3);
	}
	.jit-policy-head {
		display: flex;
		flex-direction: column;
		gap: 2px;
	}
	.jit-policy-head strong {
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	.jit-policy-inherit {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}
	.jit-policy-actions {
		display: flex;
		justify-content: flex-end;
	}
</style>
