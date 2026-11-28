<svelte:options runes={true} />

<script lang="ts">
	import { tick } from 'svelte';
	import type { FeatureToggle } from '$lib/admin/client';
	import {
		adminFeatureDeleteUnknown,
		adminFeatureList,
		adminFeatureRegistryModeSet,
		adminFeatureSet
	} from '$lib/admin/client';
	import { adminGetSodMode, adminSetSodMode } from '$lib/admin/roles';
	import { featureOperatorWarnings, groupLabel, sortFeatureToggles } from '$lib/admin/featureHelpers';
	import { t } from '$lib/i18n';
	import { adminPermissions, hasPermission } from '$lib/stores/auth';
	import {
		Badge,
		Button,
		Card,
		Dialog,
		EmptyState,
		Input,
		Spinner,
		Switch,
		showToast
	} from '$lib/components/ui';

	type RegistryMode = 'observe' | 'enforce';
	type ReconcilePhase = 'idle' | 'submitting' | 'reconciling' | 'still-present' | 'reconcile-failed';

	let toggles = $state<FeatureToggle[]>([]);
	let loading = $state(true);
	let error = $state('');
	let switchRevision = $state(0);
	let registryMode = $derived<RegistryMode>(toggles[0]?.registryMode ?? 'observe');
	let unknownCount = $derived(toggles.filter((toggle) => toggle.classification === 'unknown').length);
	let canConfigure = $derived(hasPermission($adminPermissions, 'system.config'));

	let toggleTarget = $state<FeatureToggle | null>(null);
	let toggleDesired = $state(false);
	let toggleReason = $state('');
	let toggleReasonError = $state('');
	let toggleError = $state('');
	let toggleBusy = $state(false);

	let presetTarget = $state('');
	let presetReason = $state('');
	let presetReasonError = $state('');
	let presetError = $state('');
	let presetBusy = $state(false);

	let removeTarget = $state<FeatureToggle | null>(null);
	let removeExactKey = $state('');
	let removeReason = $state('');
	let removeKeyError = $state('');
	let removeReasonError = $state('');
	let removeError = $state('');
	let removePhase = $state<ReconcilePhase>('idle');

	let modeTarget = $state<RegistryMode | null>(null);
	let modeReason = $state('');
	let modeReasonError = $state('');
	let modeError = $state('');
	let modePhase = $state<ReconcilePhase>('idle');

	let operationBusy = $derived(
		toggleBusy ||
		presetBusy ||
		removePhase === 'submitting' ||
		removePhase === 'reconciling' ||
		modePhase === 'submitting' ||
		modePhase === 'reconciling'
	);

	const PRESETS: Record<string, Record<string, boolean>> = {
		Minimal: {
			'feature.imap': false,
			'feature.ldap_gal': false,
			'feature.caldav': false,
			'feature.carddav': false,
			'feature.spf': false,
			'feature.dkim': false,
			'feature.dmarc': false,
			'feature.arc': false,
			'feature.dane': false,
			'feature.mta_sts': false,
			'feature.tls_rpt': false,
			'feature.greylisting': false,
			'feature.rbl': false,
			'feature.spam_scoring': false,
			'feature.clamav': false
		},
		Enterprise: {
			'feature.imap': true,
			'feature.smtp_inbound': true,
			'feature.smtp_submission': true,
			'feature.ldap_gal': true,
			'feature.caldav': true,
			'feature.carddav': true,
			'feature.spf': true,
			'feature.dkim': true,
			'feature.dmarc': true,
			'feature.arc': true,
			'feature.dane': true,
			'feature.mta_sts': true,
			'feature.tls_rpt': true,
			'feature.greylisting': true,
			'feature.rbl': true,
			'feature.spam_scoring': true,
			'feature.clamav': true,
			'feature.rules_engine': true,
			'feature.dlp': true,
			'feature.journaling': true,
			'feature.retention': true,
			'feature.dmarc_reporting': true,
			'feature.full_text_search': true
		},
		FullSecurity: {
			'feature.spf': true,
			'feature.dkim': true,
			'feature.dmarc': true,
			'feature.arc': true,
			'feature.dane': true,
			'feature.mta_sts': true,
			'feature.tls_rpt': true,
			'feature.greylisting': true,
			'feature.rbl': true,
			'feature.spam_scoring': true,
			'feature.clamav': true
		}
	};
	const SOD_MODE_KEY = 'dengbao.sod_mode';

	function message(e: unknown, fallback: string): string {
		return e instanceof Error ? e.message : fallback;
	}

	async function fetchToggles(): Promise<FeatureToggle[]> {
		return sortFeatureToggles(await adminFeatureList());
	}

	async function loadToggles() {
		loading = true;
		error = '';
		try {
			toggles = await fetchToggles();
			switchRevision += 1;
		} catch (e) {
			error = message(e, t('admin.features.load_failed'));
		} finally {
			loading = false;
		}
	}

	function openToggle(tg: FeatureToggle) {
		const current = tg.storedEnabled ?? tg.defaultEnabled;
		toggleTarget = tg;
		toggleDesired = !current;
		toggleReason = '';
		toggleReasonError = '';
		toggleError = '';
		// Switch is an immediate-control primitive. Remount it with authoritative
		// state while this confirmation dialog owns the pending mutation.
		switchRevision += 1;
	}

	function closeToggle() {
		if (toggleBusy) return;
		toggleTarget = null;
		switchRevision += 1;
	}

	async function confirmToggle() {
		if (!toggleTarget || toggleBusy) return;
		const reason = toggleReason.trim();
		if (!reason) {
			toggleReasonError = t('admin.features.audit_reason_required');
			return;
		}
		toggleReasonError = '';
		toggleError = '';
		toggleBusy = true;
		const target = toggleTarget;
		try {
			if (target.key === SOD_MODE_KEY) {
				// SoD owns a dedicated preflight that rejects conflicting role
				// assignments. The generic feature endpoint intentionally forbids
				// this key so the invariant cannot be bypassed.
				if (toggleDesired) {
					const status = await adminGetSodMode();
					if (status.violations.length > 0) {
						toggleError = t('admin.sod.violations_count', {
							count: String(status.violations.length)
						});
						return;
					}
				}
				await adminSetSodMode(toggleDesired, reason);
			} else {
				await adminFeatureSet(target.key, toggleDesired, reason);
			}
			const fresh = await fetchToggles();
			const applied = fresh.find((row) => row.key === target.key);
			if (!applied || (applied.storedEnabled ?? applied.defaultEnabled) !== toggleDesired) {
				toggleError = t('admin.features.update_verify_failed');
				return;
			}
			toggles = fresh;
			switchRevision += 1;
			toggleTarget = null;
			showToast(t('admin.features.update_success', {
				key: target.key,
				state: toggleDesired ? t('admin.features.state_on') : t('admin.features.state_off')
			}));
		} catch (e) {
			toggleError = message(e, t('admin.features.update_failed'));
		} finally {
			toggleBusy = false;
		}
	}

	function openPreset(name: string) {
		presetTarget = name;
		presetReason = '';
		presetReasonError = '';
		presetError = '';
	}

	function closePreset() {
		if (!presetBusy) presetTarget = '';
	}

	async function confirmPreset() {
		if (!presetTarget || presetBusy) return;
		const reason = presetReason.trim();
		if (!reason) {
			presetReasonError = t('admin.features.audit_reason_required');
			return;
		}
		presetReasonError = '';
		presetError = '';
		presetBusy = true;
		const name = presetTarget;
		const changed = Object.entries(PRESETS[name]).filter(([key, enabled]) => {
			const current = toggles.find((row) => row.key === key);
			return current && (current.storedEnabled ?? current.defaultEnabled) !== enabled;
		});
		try {
			const results = await Promise.allSettled(
				changed.map(([key, enabled]) => adminFeatureSet(key, enabled, reason))
			);
			const failed = changed.filter((_, index) => results[index].status === 'rejected').map(([key]) => key);
			toggles = await fetchToggles();
			switchRevision += 1;
			if (failed.length > 0) {
				presetError = t('admin.features.preset_partial', { name, keys: failed.join(', ') });
				return;
			}
			presetTarget = '';
			showToast(t('admin.features.preset_success', { name }));
		} catch (e) {
			presetError = message(e, t('admin.features.preset_failed'));
		} finally {
			presetBusy = false;
		}
	}

	async function openRemove(tg: FeatureToggle) {
		removeTarget = tg;
		removeExactKey = '';
		removeReason = '';
		removeKeyError = '';
		removeReasonError = '';
		removeError = '';
		removePhase = 'idle';
		await tick();
		document.getElementById('feature-remove-exact-key')?.focus();
	}

	function closeRemove() {
		if (!operationBusy) removeTarget = null;
	}

	async function reconcileRemoval(problem = '') {
		if (!removeTarget) return;
		const key = removeTarget.key;
		removePhase = 'reconciling';
		try {
			const fresh = await fetchToggles();
			toggles = fresh;
			switchRevision += 1;
			if (!fresh.some((row) => row.key === key)) {
				removeTarget = null;
				removePhase = 'idle';
				showToast(t('admin.features.remove_success', { key }));
				return;
			}
			removePhase = 'still-present';
			removeError = problem || t('admin.features.remove_failed');
		} catch {
			removePhase = 'reconcile-failed';
			removeError = t('admin.features.remove_verify_failed', { key });
		}
	}

	async function confirmRemove() {
		if (!removeTarget || operationBusy) return;
		removeKeyError = removeExactKey === removeTarget.key ? '' : t('admin.features.exact_key_mismatch');
		removeReasonError = removeReason.trim() ? '' : t('admin.features.audit_reason_required');
		if (removeKeyError || removeReasonError) return;
		removeError = '';
		removePhase = 'submitting';
		let problem = '';
		try {
			await adminFeatureDeleteUnknown(removeTarget.key, removeReason.trim());
		} catch (e) {
			// The response can be ambiguous after the server commits. Reconcile once
			// before claiming failure so a completed deletion is never retried blindly.
			problem = message(e, t('admin.features.remove_failed'));
		}
		await reconcileRemoval(problem);
	}

	function openMode(mode: RegistryMode) {
		if (mode === registryMode || (mode === 'enforce' && unknownCount > 0)) return;
		modeTarget = mode;
		modeReason = '';
		modeReasonError = '';
		modeError = '';
		modePhase = 'idle';
	}

	function closeMode() {
		if (!operationBusy) modeTarget = null;
	}

	async function confirmMode() {
		if (!modeTarget || operationBusy) return;
		const reason = modeReason.trim();
		if (!reason) {
			modeReasonError = t('admin.features.audit_reason_required');
			return;
		}
		modeReasonError = '';
		modeError = '';
		modePhase = 'submitting';
		const requested = modeTarget;
		try {
			await adminFeatureRegistryModeSet(requested, reason);
			modePhase = 'reconciling';
			const fresh = await fetchToggles();
			if ((fresh[0]?.registryMode ?? 'observe') !== requested) {
				modePhase = 'still-present';
				modeError = t('admin.features.mode_verify_failed');
				return;
			}
			toggles = fresh;
			switchRevision += 1;
			modeTarget = null;
			modePhase = 'idle';
			showToast(t('admin.features.mode_success', {
				mode: requested === 'enforce'
					? t('admin.features.registry_enforce')
					: t('admin.features.registry_observe')
			}));
		} catch (e) {
			modePhase = 'idle';
			modeError = message(e, t('admin.features.mode_failed'));
		}
	}

	function guardNavigation(event: BeforeUnloadEvent) {
		if (!operationBusy) return;
		event.preventDefault();
		event.returnValue = '';
	}

	function stateLabel(value: boolean): string {
		return value ? t('admin.features.state_on') : t('admin.features.state_off');
	}

	function switchLabel(tg: FeatureToggle): string {
		const enabled = tg.storedEnabled ?? tg.defaultEnabled;
		return t(enabled ? 'admin.features.switch_disable' : 'admin.features.switch_enable', {
			label: groupLabel(tg.key),
			key: tg.key
		});
	}

	$effect(() => {
		void loadToggles();
	});
</script>

<svelte:window onbeforeunload={guardNavigation} />

<div class="sj-page">
	<header class="sj-page-head">
		<div class="sj-page-head-left">
			<h1>{t('admin.features.title')}</h1>
			<p class="sj-page-desc">{t('admin.features.runtime_scope')}</p>
		</div>
		<div class="sj-registry-mode" aria-label={t('admin.features.registry_mode')}>
			<Badge
				variant={registryMode === 'enforce' ? 'accent' : 'neutral'}
				label={registryMode === 'enforce' ? t('admin.features.registry_enforce') : t('admin.features.registry_observe')}
			/>
			<Button
				size="sm"
				variant="secondary"
				onclick={() => openMode(registryMode === 'observe' ? 'enforce' : 'observe')}
				disabled={!canConfigure || (registryMode === 'observe' && unknownCount > 0)}
			>
				{registryMode === 'observe' ? t('admin.features.registry_enforce') : t('admin.features.registry_rollback')}
			</Button>
		</div>
	</header>

	{#if registryMode === 'observe' && unknownCount > 0}
		<p class="sj-mode-hint">{t('admin.features.registry_enforce_blocked')}</p>
	{/if}

	{#if error}
		<div class="alert alert-danger" role="alert">{error}</div>
	{/if}

	{#if unknownCount > 0}
		<div class="alert alert-warning" role="status">
			<Badge variant="warning" label={t('admin.features.unknown_badge')} dot={true} />
			<span>{t(registryMode === 'observe' ? 'admin.features.unknown_count_observe' : 'admin.features.unknown_count_enforce', { count: String(unknownCount) })}</span>
		</div>
	{/if}

	<div class="sj-presets" aria-label={t('admin.features.presets')}>
		{#each Object.keys(PRESETS) as preset}
			<Button variant="secondary" size="sm" onclick={() => openPreset(preset)} disabled={!canConfigure}>
				{preset}
			</Button>
		{/each}
	</div>

	{#if loading}
		<Spinner label={t('admin.features.loading')} />
	{:else if toggles.length === 0}
		<EmptyState title={t('admin.features.no_features')} />
	{:else}
		<Card flush={true}>
			{#each toggles as tg (tg.key)}
				<div class="sj-feature-row" class:sj-feature-row--unknown={tg.classification === 'unknown'}>
					<div class="sj-feature-info">
						<div class="sj-feature-heading">
							{#if tg.classification === 'unknown'}
								<Badge
									variant="warning"
									label={registryMode === 'observe' ? t('admin.features.unknown_observe') : t('admin.features.unknown_enforce')}
									dot={true}
								/>
							{:else}
								<span class="sj-feature-label">{groupLabel(tg.key)}</span>
							{/if}
						</div>
						{#if tg.description}<span class="sj-feature-desc">{tg.description}</span>{/if}
						<code class="sj-feature-key">{tg.key}</code>
						<span class="sj-feature-state">
							{t('admin.features.stored_state', {
								state: tg.storedEnabled === null
									? t('admin.features.state_default', { state: stateLabel(tg.defaultEnabled) })
									: stateLabel(tg.storedEnabled)
							})}
						</span>
						<span class="sj-feature-state">
							{t('admin.features.gateway_override', {
								state: `${stateLabel(tg.gatewayEffective)} (${tg.gatewaySource})`
							})}
						</span>
						<span class="sj-feature-state">{t('admin.features.auth_effective_unreported')}</span>
					</div>
					<div class="sj-feature-actions">
						{#if tg.classification === 'unknown'}
							<Button
								size="sm"
								variant="secondary"
								onclick={() => openRemove(tg)}
								disabled={!canConfigure}
								aria-label={t('admin.features.remove_unknown_named', { key: tg.key })}
							>
								{t('admin.features.remove_unknown')}
							</Button>
						{/if}
						{#if tg.classification === 'known' || registryMode === 'observe'}
							{#key `${tg.key}:${switchRevision}`}
								<Switch
									checked={tg.storedEnabled ?? tg.defaultEnabled}
									label={switchLabel(tg)}
									onchange={() => openToggle(tg)}
									disabled={!canConfigure}
								/>
							{/key}
						{/if}
					</div>
				</div>
			{/each}
		</Card>
	{/if}
</div>

<Dialog open={!!toggleTarget} title={t('admin.features.update_title')} onClose={toggleBusy ? undefined : closeToggle}>
	{#snippet children()}
		{#if toggleTarget}
			<p>{t('admin.features.update_body', {
				key: toggleTarget.key,
				state: toggleDesired ? t('admin.features.state_on') : t('admin.features.state_off')
			})}</p>
			{#each featureOperatorWarnings(toggleTarget, toggleDesired, toggles) as warning}
				{#if warning.kind === 'disconnect'}
					<div class="dialog-warning">{t('admin.features.listener_warning')}</div>
				{:else if warning.kind === 'drain'}
					<div class="dialog-warning">{t('admin.features.drain_warning')}</div>
				{:else if warning.kind === 'dependencies'}
					<div class="dialog-warning">{t('admin.features.dependencies_warning', { keys: warning.keys.join(', ') })}</div>
				{:else if warning.kind === 'confirmation'}
					<div class="dialog-warning">{t('admin.features.security_confirmation_warning')}</div>
				{/if}
			{/each}
			<Input
				label={t('admin.features.audit_reason')}
				bind:value={toggleReason}
				error={toggleReasonError}
				maxlength={1024}
				disabled={toggleBusy}
			/>
			{#if toggleError}<div class="dialog-error" role="alert">{toggleError}</div>{/if}
		{/if}
	{/snippet}
	{#snippet footer()}
		<Button variant="secondary" onclick={closeToggle} disabled={toggleBusy}>{t('common.cancel')}</Button>
		<Button onclick={confirmToggle} disabled={toggleBusy}>
			{#if toggleBusy}<Spinner size={16} label={t('admin.features.saving')} />{/if}
			{t('common.confirm')}
		</Button>
	{/snippet}
</Dialog>

<Dialog open={!!presetTarget} title={t('admin.features.preset_title', { name: presetTarget })} onClose={presetBusy ? undefined : closePreset}>
	{#snippet children()}
		<p>{t('admin.features.preset_body', { name: presetTarget })}</p>
		<Input
			label={t('admin.features.audit_reason')}
			bind:value={presetReason}
			error={presetReasonError}
			maxlength={1024}
			disabled={presetBusy}
		/>
		{#if presetError}<div class="dialog-error" role="alert">{presetError}</div>{/if}
	{/snippet}
	{#snippet footer()}
		<Button variant="secondary" onclick={closePreset} disabled={presetBusy}>{t('common.cancel')}</Button>
		<Button onclick={confirmPreset} disabled={presetBusy}>
			{#if presetBusy}<Spinner size={16} label={t('admin.features.saving')} />{/if}
			{t('admin.features.apply_preset')}
		</Button>
	{/snippet}
</Dialog>

<Dialog open={!!removeTarget} title={t('admin.features.remove_title')} onClose={operationBusy ? undefined : closeRemove}>
	{#snippet children()}
		{#if removeTarget}
			<p>{t('admin.features.remove_body', { key: removeTarget.key })}</p>
			<div class="dialog-fields">
				<Input
					id="feature-remove-exact-key"
					label={t('admin.features.exact_key_label', { key: removeTarget.key })}
					bind:value={removeExactKey}
					error={removeKeyError}
					mono={true}
					autocomplete="off"
					disabled={operationBusy}
				/>
				<Input
					label={t('admin.features.audit_reason')}
					bind:value={removeReason}
					error={removeReasonError}
					maxlength={1024}
					disabled={operationBusy}
				/>
			</div>
			{#if removeError}<div class="dialog-error" role="alert">{removeError}</div>{/if}
		{/if}
	{/snippet}
	{#snippet footer()}
		<Button variant="secondary" onclick={closeRemove} disabled={operationBusy}>{t('common.cancel')}</Button>
		{#if removePhase === 'reconcile-failed'}
			<Button variant="secondary" onclick={() => reconcileRemoval()}>{t('admin.features.retry_verify')}</Button>
		{/if}
		<Button variant="danger" onclick={confirmRemove} disabled={operationBusy}>
			{#if operationBusy}<Spinner size={16} label={t('admin.features.saving')} />{/if}
			{t('admin.features.remove_confirm')}
		</Button>
	{/snippet}
</Dialog>

<Dialog open={!!modeTarget} title={t('admin.features.registry_mode')} onClose={operationBusy ? undefined : closeMode}>
	{#snippet children()}
		{#if modeTarget}
			<p>{modeTarget === 'enforce' ? t('admin.features.mode_enforce_body') : t('admin.features.mode_observe_body')}</p>
			<Input
				label={t('admin.features.audit_reason')}
				bind:value={modeReason}
				error={modeReasonError}
				maxlength={1024}
				disabled={operationBusy}
			/>
			{#if modeError}<div class="dialog-error" role="alert">{modeError}</div>{/if}
		{/if}
	{/snippet}
	{#snippet footer()}
		<Button variant="secondary" onclick={closeMode} disabled={operationBusy}>{t('common.cancel')}</Button>
		<Button onclick={confirmMode} disabled={operationBusy}>
			{#if operationBusy}<Spinner size={16} label={t('admin.features.saving')} />{/if}
			{t('common.confirm')}
		</Button>
	{/snippet}
</Dialog>

<style>
	.sj-page {
		max-width: 980px;
	}
	.sj-page-head {
		display: flex;
		align-items: flex-start;
		gap: var(--space-3);
		margin-bottom: var(--space-4);
		flex-wrap: wrap;
	}
	.sj-page-head-left {
		flex: 1 1 260px;
		min-width: 0;
	}
	.sj-registry-mode {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		flex-wrap: wrap;
	}
	.sj-page-head-left h1 {
		margin: 0;
		font-size: clamp(20px, 16px + 1.2vw, 24px);
		font-weight: var(--weight-semibold);
		letter-spacing: var(--tracking-display);
		color: var(--text-primary);
	}
	.sj-page-desc,
	.sj-mode-hint {
		margin: var(--space-1) 0 0;
		font-size: var(--text-sm);
		color: var(--text-caption);
	}
	.sj-mode-hint {
		margin-block-end: var(--space-3);
	}
	.sj-presets {
		display: flex;
		gap: var(--space-2);
		margin-bottom: var(--space-3);
		flex-wrap: wrap;
	}
	.sj-feature-row {
		display: flex;
		align-items: center;
		gap: var(--space-3);
		padding: var(--space-3) var(--space-4);
		border-bottom: 1px solid var(--border-subtle);
	}
	.sj-feature-row--unknown {
		background: var(--warning-bg);
		align-items: stretch;
		flex-direction: column;
	}
	.sj-feature-row--unknown .sj-feature-actions {
		justify-content: flex-start;
		flex-wrap: wrap;
	}
	.sj-feature-row:last-child {
		border-bottom: none;
	}
	.sj-feature-info {
		flex: 1;
		min-width: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.sj-feature-heading {
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}
	.sj-feature-label {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
		text-transform: capitalize;
	}
	.sj-feature-desc,
	.sj-feature-state {
		font-size: var(--text-sm);
		color: var(--text-caption);
	}
	.sj-feature-key {
		font-family: var(--font-mono);
		font-size: var(--text-xs);
		color: var(--text-primary);
		overflow-wrap: anywhere;
	}
	.sj-feature-actions {
		display: flex;
		align-items: center;
		justify-content: flex-end;
		gap: var(--space-2);
		flex: 0 0 auto;
	}
	.alert,
	.dialog-warning,
	.dialog-error {
		padding: var(--space-2) var(--space-3);
		border-radius: var(--radius-sm);
		font-size: var(--text-sm);
	}
	.alert {
		margin-bottom: var(--space-3);
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}
	.alert-danger,
	.dialog-error {
		background: var(--danger-bg);
		color: var(--danger-fg);
		border: 1px solid var(--danger-fg);
	}
	.alert-warning,
	.dialog-warning {
		background: var(--warning-bg);
		color: var(--warning-fg);
		border: 1px solid var(--warning-fg);
	}
	.dialog-fields {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
		margin-top: var(--space-3);
	}
	.dialog-warning,
	.dialog-error {
		margin-top: var(--space-3);
	}

	@media (max-width: 640px) {
		.sj-feature-row {
			align-items: stretch;
			flex-direction: column;
		}
		.sj-feature-actions {
			align-items: stretch;
			flex-direction: column;
		}
		.sj-feature-actions :global(.sj-btn) {
			width: 100%;
		}
	}

	@media (prefers-reduced-motion: reduce) {
		.sj-feature-row {
			scroll-behavior: auto;
		}
	}
</style>
