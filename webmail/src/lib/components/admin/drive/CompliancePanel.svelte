<svelte:options runes={true} />

<script lang="ts">
	// P5 Task 10 — admin compliance panel: per-space classification upgrade to
	// gxp (with the compliance knobs), no-downgrade UI (the reducer refuses a
	// downgrade too — BZ142 is the real floor, this only avoids OFFERING one),
	// the worm-pending queue surface, and the audit-chain verify button
	// (AUTOPLAN correction #2 — GET /spaces/{id}/audit/verify has no other UI).
	import * as api from '$lib/drive/api';
	import { type DriveSpace, type AuditVerifyResult } from '$lib/drive/api';
	import { Badge, Button, Dialog, Input, Select } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';
	import { driveErrorMessage } from '$lib/drive/errors';

	let {
		space,
		wormPending,
		canManage,
		canView,
		onchanged,
	}: {
		space: DriveSpace;
		wormPending: number;
		canManage: boolean;
		canView: boolean;
		onchanged: () => void;
	} = $props();


	// ── classification upgrade (no-downgrade: only strictly higher ranks are
	// ever offered — the server's BZ142 trigger is the real floor) ───────────
	const RANK: Record<DriveSpace['classification'], number> = { regular: 0, secure: 1, gxp: 2 };
	let upgradeOptions = $derived(
		(['secure', 'gxp'] as const).filter((c) => RANK[c] > RANK[space.classification]),
	);
	let upgradeTarget = $state<'' | 'secure' | 'gxp'>('');
	let upgradeRetentionDays = $state('');
	let upgradeWormMode = $state<'governance' | 'compliance'>('governance');
	let showUpgradeConfirm = $state(false);
	let upgrading = $state(false);
	let upgradeError = $state('');

	// ── existing-gxp knobs (retention/worm may only ever strengthen — BZ142) ─
	let knobRetentionDays = $state('');
	let knobWormMode = $state<'governance' | 'compliance'>('governance');
	let savingKnobs = $state(false);
	let knobsError = $state('');
	let knobsSaved = $state(false);

	// ── verify-chain (drive.view) ────────────────────────────────────────────
	let verifyState = $state<'idle' | 'verifying' | 'clean' | 'broken' | 'error'>('idle');
	let verifyResult = $state<AuditVerifyResult | null>(null);

	// Reset all per-space local form state whenever a different space is
	// selected — otherwise a half-filled upgrade form from space A would leak
	// into space B's panel.
	$effect(() => {
		void space.id;
		upgradeTarget = '';
		upgradeRetentionDays = '';
		upgradeWormMode = 'governance';
		showUpgradeConfirm = false;
		upgradeError = '';
		knobRetentionDays = '';
		knobWormMode = 'governance';
		knobsError = '';
		knobsSaved = false;
		verifyState = 'idle';
		verifyResult = null;
	});

	let upgradeValid = $derived(
		upgradeTarget !== '' && (upgradeTarget !== 'gxp' || Number(upgradeRetentionDays) >= 1),
	);

	function openUpgradeConfirm() {
		if (!upgradeValid) return;
		upgradeError = '';
		showUpgradeConfirm = true;
	}

	async function confirmUpgrade() {
		upgrading = true;
		upgradeError = '';
		try {
			const fields: Record<string, unknown> = { classification: upgradeTarget };
			if (upgradeTarget === 'gxp') {
				fields.retentionDays = Number(upgradeRetentionDays);
				fields.wormMode = upgradeWormMode;
			}
			await api.patchSpace(space.id, fields);
			showUpgradeConfirm = false;
			onchanged();
		} catch (e) {
			upgradeError = driveErrorMessage(e);
		} finally {
			upgrading = false;
		}
	}

	async function saveKnobs() {
		const days = Number(knobRetentionDays);
		if (!(days >= 1)) return;
		savingKnobs = true;
		knobsError = '';
		knobsSaved = false;
		try {
			await api.patchSpace(space.id, {
				exportPolicy: {},
				retentionDays: days,
				wormMode: knobWormMode,
			});
			knobsSaved = true;
			onchanged();
		} catch (e) {
			knobsError = driveErrorMessage(e);
		} finally {
			savingKnobs = false;
		}
	}

	async function runVerifyChain() {
		verifyState = 'verifying';
		verifyResult = null;
		try {
			verifyResult = await api.verifyAuditChain(space.id);
			verifyState = verifyResult.broken.length > 0 ? 'broken' : 'clean';
		} catch {
			verifyState = 'error';
		}
	}

	const WORM_MODE_OPTIONS = [
		{ value: 'governance', label: t('drive.compliance.worm_mode.governance') },
		{ value: 'compliance', label: t('drive.compliance.worm_mode.compliance') },
	];
</script>

<section class="cp" aria-labelledby="cp-title-{space.id}">
	<h2 class="cp__title" id="cp-title-{space.id}">{t('drive.compliance.title')}</h2>

	{#if canManage && upgradeOptions.length > 0}
		<div class="cp__row">
			<Select
				label={t('drive.compliance.upgradeLabel')}
				bind:value={upgradeTarget}
				options={[
					{ value: '', label: t('drive.compliance.chooseLevel') },
					...upgradeOptions.map((c) => ({ value: c, label: t(`drive.space.classification.${c}`) })),
				]}
			/>
			{#if upgradeTarget === 'gxp'}
				<Input
					type="number"
					min="1"
					label={t('drive.compliance.retention_days')}
					bind:value={upgradeRetentionDays}
					required
				/>
				<Select label={t('drive.compliance.worm_mode')} bind:value={upgradeWormMode} options={WORM_MODE_OPTIONS} />
			{/if}
			<Button variant="secondary" size="sm" disabled={!upgradeValid} onclick={openUpgradeConfirm}>
				{t('drive.compliance.upgradeAction')}
			</Button>
		</div>
		{#if upgradeError}
			<p class="cp__error" role="alert">{upgradeError}</p>
		{/if}
	{:else if canManage}
		<p class="cp__hint">{t('drive.compliance.noUpgrade')}</p>
	{/if}

	{#if space.classification === 'gxp'}
		{#if canManage}
			<div class="cp__row">
				<h3 class="cp__subtitle">{t('drive.compliance.knobsTitle')}</h3>
			</div>
			<div class="cp__row">
				<Input
					type="number"
					min="1"
					label={t('drive.compliance.retention_days')}
					bind:value={knobRetentionDays}
				/>
				<Select label={t('drive.compliance.worm_mode')} bind:value={knobWormMode} options={WORM_MODE_OPTIONS} />
				<Button variant="secondary" size="sm" disabled={savingKnobs} onclick={saveKnobs}>
					{t('drive.compliance.knobsSave')}
				</Button>
			</div>
			<p class="cp__hint">{t('drive.space.noDowngradeWarning')}</p>
			{#if knobsError}
				<p class="cp__error" role="alert">{knobsError}</p>
			{/if}
			{#if knobsSaved}
				<p class="cp__success" role="status">{t('drive.compliance.knobsSaved')}</p>
			{/if}
		{/if}

		<div class="cp__worm" aria-live="polite">
			{#if wormPending > 0}
				<span class="cp__worm-badge">
					<Icon name="Lock" size={14} />
					<Badge variant="warning" label={String(wormPending)} />
					{t('drive.compliance.worm_pending')}
				</span>
				<p class="cp__hint">{t('drive.compliance.worm_pending_help')}</p>
				<p class="cp__hint">{t('drive.compliance.retry_state')}</p>
			{:else}
				<span class="cp__worm-badge">
					<Icon name="CheckCircle2" size={14} />
					{t('drive.compliance.worm_pending_none')}
				</span>
			{/if}
			<p class="cp__hint">{t('drive.compliance.worm_pending_backend_note')}</p>
		</div>
	{/if}

	{#if canView}
		<div class="cp__row">
			<Button variant="ghost" size="sm" disabled={verifyState === 'verifying'} onclick={runVerifyChain}>
				{verifyState === 'verifying' ? t('drive.compliance.verifyChainRunning') : t('drive.compliance.verifyChain')}
			</Button>
		</div>
		<div aria-live="polite">
			{#if verifyState === 'clean' && verifyResult}
				<p class="cp__success" role="status">
					{t('drive.compliance.verifyChainClean', { n: String(verifyResult.checked) })}
				</p>
			{:else if verifyState === 'broken' && verifyResult}
				<p class="cp__error" role="alert">
					{t('drive.compliance.verifyChainBroken', {
						n: String(verifyResult.checked),
						count: String(verifyResult.broken.length),
						ids: verifyResult.broken.join(', '),
					})}
				</p>
			{:else if verifyState === 'error'}
				<p class="cp__error" role="alert">{t('drive.compliance.verifyChainError')}</p>
			{/if}
		</div>
	{/if}

	{#if space.classification === 'gxp'}
		<p class="cp__part11">{t('drive.compliance.part11Capable')}</p>
	{/if}
</section>

<Dialog
	open={showUpgradeConfirm}
	title={t('drive.compliance.upgrade_confirm_title', {
		level: upgradeTarget ? t(`drive.space.classification.${upgradeTarget}`) : '',
	})}
	onClose={() => (showUpgradeConfirm = false)}
>
	<p>
		{upgradeTarget === 'gxp'
			? t('drive.compliance.upgrade_confirm_body_gxp')
			: t('drive.compliance.upgrade_confirm_body_secure')}
	</p>
	{#snippet footer()}
		<Button variant="primary" disabled={upgrading} onclick={confirmUpgrade}>
			{t('drive.compliance.upgrade_confirm_action')}
		</Button>
		<Button variant="secondary" disabled={upgrading} onclick={() => (showUpgradeConfirm = false)}>
			{t('common.cancel')}
		</Button>
	{/snippet}
</Dialog>

<style>
	.cp {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		padding: var(--space-3);
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-md);
		background: var(--surface-card);
	}
	.cp__title {
		margin: 0;
		font-size: var(--text-md);
		font-weight: 600;
	}
	.cp__subtitle {
		margin: 0;
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-secondary);
	}
	.cp__row {
		display: flex;
		flex-wrap: wrap;
		align-items: flex-end;
		gap: var(--space-2);
	}
	.cp__hint {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-caption);
	}
	.cp__error {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--danger-fg);
		background: var(--danger-bg);
		padding: var(--space-2);
		border-radius: var(--radius-sm);
	}
	.cp__success {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--success-fg);
		background: var(--success-bg);
		padding: var(--space-2);
		border-radius: var(--radius-sm);
	}
	.cp__worm {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.cp__worm-badge {
		display: inline-flex;
		align-items: center;
		gap: var(--space-1);
		font-size: var(--text-sm);
		font-weight: 600;
	}
	.cp__part11 {
		margin: 0;
		font-size: var(--text-xs);
		color: var(--text-caption);
		border-top: 1px solid var(--border-subtle);
		padding-top: var(--space-2);
	}
</style>
