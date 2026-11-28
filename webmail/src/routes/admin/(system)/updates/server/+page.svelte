<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import {
		adminUpgradeCancel, adminUpgradeChallenge, adminUpgradeCompleteChallenge,
		adminUpgradeConsole, adminUpgradeIntent, adminUpgradePreview, adminUpgradeRequest,
		type UpgradeConsoleModel, type UpgradeIntent, type UpgradePreview, type UpgradeRelease,
		type UpgradeState,
	} from '$lib/admin/client';
	import { Badge, Button, Card, Input, Progress, Spinner, showToast } from '$lib/components/ui';
	import { formatDateTime, t } from '$lib/i18n';
	import { resolveLocalSchedule, ScheduleTimeError } from './schedule';

	const orderedStates: UpgradeState[] = [
		'approved', 'claimed', 'preflight', 'recovery_point', 'staged', 'maintenance',
		'migrations', 'switched', 'readiness', 'committed', 'verified',
	];
	const terminalStates = new Set<UpgradeState>([
		'verified', 'rolled_back', 'failed', 'recovery_required', 'cancelled', 'expired',
	]);
	const cancellableStates = new Set<UpgradeState>([
		'awaiting_approval', 'approved', 'scheduled', 'claimed', 'preflight', 'recovery_point', 'staged',
	]);

	let model = $state<UpgradeConsoleModel | null>(null);
	let selectedReleaseId = $state('');
	let reason = $state(t('admin.updates.server.reasonDefault'));
	let scheduleLocal = $state('');
	let scheduleError = $state('');
	let preview = $state<UpgradePreview | null>(null);
	let loading = $state(true);
	let busy = $state(false);
	let error = $state('');
	let announcement = $state('');
	let lastAnnouncedState = $state<UpgradeState | ''>('');

	let selectedRelease = $derived(model?.releases.find((item) => item.releaseId === selectedReleaseId) ?? null);
	let activeIntent = $derived(model?.intent ?? null);
	let recoverySet = $derived(model?.recoverySet ?? null);
	let progressValue = $derived(progressFor(activeIntent));
	let canPreview = $derived(Boolean(
		model?.flags.catalog && model?.flags.execution && model?.recoverySet?.fresh &&
		selectedRelease?.status === 'available' && selectedRelease?.readiness?.status === 'ready' && reason.trim().length >= 8 && !scheduleError,
	));

	$effect(() => {
		const state = activeIntent?.state;
		if (state && state !== lastAnnouncedState) {
			// Reconnect/loading establishes a baseline silently. Only a state
			// transition observed while this page is mounted is announced.
			if (lastAnnouncedState) announcement = t('admin.updates.server.stateChanged', { state: stateLabel(state) });
			lastAnnouncedState = state;
		}
	});

	onMount(() => {
		void loadConsole();
		const poll = window.setInterval(() => {
			if (model?.intent && !terminalStates.has(model.intent.state)) void refreshIntent(model.intent.intentId);
		}, 2500);
		return () => window.clearInterval(poll);
	});

	async function loadConsole() {
		loading = true;
		try {
			model = await adminUpgradeConsole();
			if (!selectedReleaseId) selectedReleaseId = model.releases.find((item) => item.status === 'available')?.releaseId ?? '';
			error = '';
		} catch (cause) {
			error = readableError(cause);
		} finally {
			loading = false;
		}
	}

	async function refreshIntent(id: string) {
		try {
			const intent = await adminUpgradeIntent(id);
			if (model) model = { ...model, intent };
		} catch (cause) {
			error = readableError(cause);
		}
	}

	async function reviewRelease() {
		if (!canPreview) return;
		const scheduleAt = resolveLocalSchedule(scheduleLocal);
		busy = true;
		try {
			preview = await adminUpgradePreview(selectedReleaseId, reason.trim(), scheduleAt);
			error = '';
		} catch (cause) {
			error = readableError(cause);
		} finally {
			busy = false;
		}
	}

	async function authorizeAndStart() {
		if (!preview) return;
		const scheduleAt = resolveLocalSchedule(scheduleLocal);
		busy = true;
		try {
			const challengeKey = crypto.randomUUID();
			const challenge = await adminUpgradeChallenge(preview, reason.trim(), scheduleAt, challengeKey);
			const elevation = await adminUpgradeCompleteChallenge(challenge.challengeId);
			const accepted = await adminUpgradeRequest(preview, reason.trim(), scheduleAt, elevation.elevationId, crypto.randomUUID());
			preview = null;
			await loadConsole();
			if (model) model = { ...model, intent: await adminUpgradeIntent(accepted.intentId) };
			showToast(t('admin.updates.server.accepted'));
		} catch (cause) {
			error = readableError(cause);
		} finally {
			busy = false;
		}
	}

	function updateSchedule(event: Event) {
		scheduleLocal = (event.currentTarget as HTMLInputElement).value;
		preview = null;
		try {
			resolveLocalSchedule(scheduleLocal);
			scheduleError = '';
		} catch (cause) {
			scheduleError = scheduleErrorMessage(cause);
		}
	}

	function scheduleErrorMessage(cause: unknown): string {
		if (!(cause instanceof ScheduleTimeError)) return t('admin.updates.server.schedule.invalid');
		return t(`admin.updates.server.schedule.${cause.code}`);
	}

	async function cancelIntent(intent: UpgradeIntent) {
		busy = true;
		try {
			await adminUpgradeCancel(intent, 'Cancel this upgrade at the next safe boundary');
			await refreshIntent(intent.intentId);
			showToast(t('admin.updates.server.cancelled'));
		} catch (cause) {
			error = readableError(cause);
		} finally {
			busy = false;
		}
	}

	function progressFor(intent: UpgradeIntent | null): number {
		if (!intent) return 0;
		if (intent.state === 'verified') return 100;
		const index = orderedStates.indexOf(intent.state);
		return index < 0 ? 0 : Math.round((index / (orderedStates.length - 1)) * 100);
	}

	function stateLabel(state: UpgradeState): string {
		return t(`admin.updates.server.state.${state}`);
	}

	function tone(state: UpgradeState): 'neutral' | 'success' | 'warning' | 'danger' | 'info' {
		if (state === 'verified') return 'success';
		if (state === 'recovery_required' || state === 'failed') return 'danger';
		if (state === 'rolling_back' || state === 'rolled_back' || state === 'cancel_requested') return 'warning';
		return 'info';
	}

	function readinessLabel(release: UpgradeRelease): string {
		if (release.status === 'withdrawn') return t('admin.updates.server.withdrawn');
		if (!release.readiness) return t('admin.updates.server.notChecked');
		if (release.readiness.status === 'blocked') return t('admin.updates.server.blockers', { count: String(release.readiness.blockerCount) });
		return t(`admin.updates.server.readiness.${release.readiness.status}`);
	}

	function readableError(cause: unknown): string {
		if (!(cause instanceof Error)) return t('admin.updates.server.operationFailed');
		try {
			const parsed = JSON.parse(cause.message) as { detail?: string; remediation?: string };
			return [parsed.detail, parsed.remediation].filter(Boolean).join(' ');
		} catch {
			return cause.message || t('admin.updates.server.operationFailed');
		}
	}
</script>

<svelte:head>
	<title>{t('admin.updates.server.title')} — Setjoin Admin</title>
</svelte:head>

<div class="sj-page">
	<header class="sj-page-head">
		<div>
			<h1>{t('admin.updates.server.title')}</h1>
			<p>{t('admin.updates.server.subtitle')}</p>
		</div>
		<Button variant="secondary" size="sm" onclick={loadConsole} disabled={loading || busy}>{t('admin.updates.server.refresh')}</Button>
	</header>

	<p class="sr-only" aria-live="polite">{announcement}</p>

	{#if loading && !model}
		<div class="sj-loading" role="status"><Spinner label={t('admin.updates.server.loadingLabel')} /> {t('admin.updates.server.loading')}</div>
	{:else if error && !model}
		<div class="sj-banner danger" role="alert"><strong>{t('admin.updates.server.loadFailed')}</strong><span>{error}</span></div>
	{:else if model}
		{#if !model.flags.execution}
			<div class="sj-banner warning" role="status">
				<strong>{t('admin.updates.server.executionOff')}</strong>
				<span>{t('admin.updates.server.executionOffCopy')}</span>
			</div>
		{/if}
		{#if error}
			<div class="sj-banner danger" role="alert"><strong>{t('admin.updates.server.actionFailed')}</strong><span>{error}</span></div>
		{/if}

		<section aria-labelledby="release-heading">
			<h2 id="release-heading">1. {t('admin.updates.server.release')}</h2>
			<div class="release-grid">
				{#each model.releases as release (release.releaseId)}
					<button
						class:active={selectedReleaseId === release.releaseId}
						class="release-card"
						type="button"
						onclick={() => { selectedReleaseId = release.releaseId; preview = null; }}
						aria-pressed={selectedReleaseId === release.releaseId}
					>
						<span class="release-title"><strong>{release.version}</strong><Badge label={release.channel} variant={release.channel === 'enterprise' ? 'accent' : 'neutral'} /></span>
						<span>{readinessLabel(release)}</span>
						<code>{release.releaseId}</code>
					</button>
				{/each}
			</div>
			{#if model.releases.length === 0}<p class="sj-muted">{t('admin.updates.server.noRelease')}</p>{/if}
		</section>

		<section aria-labelledby="readiness-heading">
			<h2 id="readiness-heading">2. {t('admin.updates.server.readiness')}</h2>
			<div class="evidence-grid">
				<Card title={t('admin.updates.server.recoveryPoint')}>
					{#snippet children()}
						{#if recoverySet}
							<div class="evidence-line"><Badge label={recoverySet.fresh ? t('admin.updates.server.fresh') : t('admin.updates.server.stale')} variant={recoverySet.fresh ? 'success' : 'danger'} /><code>{recoverySet.recoverySetId}</code></div>
							<p>{t('admin.updates.server.expires', { date: formatDateTime(recoverySet.expiresAt) })}</p>
							<p>{t('admin.updates.server.restoreRehearsal')}: {recoverySet.restoreProof ? (recoverySet.restoreProof.staleWarning ? t('admin.updates.server.restoreOld') : t('admin.updates.server.restoreProven')) : t('admin.updates.server.restoreMissing')}</p>
						{:else}
							<p>{t('admin.updates.server.noRecoverySet')}</p>
						{/if}
					{/snippet}
				</Card>
				<Card title={t('admin.updates.server.selectedRelease')}>
					{#snippet children()}
						{#if selectedRelease}
							<div class="evidence-line"><Badge label={readinessLabel(selectedRelease)} variant={selectedRelease.readiness?.status === 'ready' ? 'success' : 'warning'} /><code>{selectedRelease.manifestDigest}</code></div>
							<p>{t('admin.updates.server.metadataExpires', { date: formatDateTime(selectedRelease.metadataExpiresAt) })}</p>
							{#if selectedRelease.channel === 'enterprise' && selectedRelease.entitlementGraceUntil}
								<p>{t('admin.updates.server.enterpriseGraceUntil', { date: formatDateTime(selectedRelease.entitlementGraceUntil) })}</p>
							{/if}
						{:else}<p>{t('admin.updates.server.selectRelease')}</p>{/if}
					{/snippet}
				</Card>
			</div>
		</section>

		<section aria-labelledby="confirm-heading">
			<h2 id="confirm-heading">3. {t('admin.updates.server.confirm')}</h2>
			{#if activeIntent && !terminalStates.has(activeIntent.state)}
				<p class="sj-muted">{t('admin.updates.server.activeIntent')}</p>
			{:else}
				<div class="confirm-row">
					<Input label={t('admin.updates.server.reason')} bind:value={reason} maxlength={1024} />
					<label class="schedule-field" for="upgrade-schedule">
						<span>{t('admin.updates.server.schedule.label')}</span>
						<input id="upgrade-schedule" type="datetime-local" aria-label={t('admin.updates.server.schedule.label')} value={scheduleLocal} oninput={updateSchedule} aria-describedby={scheduleError ? 'upgrade-schedule-error' : undefined} aria-invalid={scheduleError ? 'true' : undefined} />
						<small>{Intl.DateTimeFormat().resolvedOptions().timeZone || t('admin.updates.server.localTimezone')}</small>
						{#if scheduleError}<span id="upgrade-schedule-error" class="field-error" role="alert">{scheduleError}</span>{/if}
					</label>
					{#if preview}
						<div class="preview-box">
							<strong>{preview.preview.targetVersion}</strong>
							<span>{t('admin.updates.server.recoveryPointId', { id: preview.preview.recoverySetId })}</span>
							<span>{preview.preview.approvalRequired ? t('admin.updates.server.approvalRequired') : t('admin.updates.server.approvalNotRequired')}</span>
						</div>
						<Button variant="primary" onclick={authorizeAndStart} disabled={busy}>{busy ? t('admin.updates.server.authorizing') : t('admin.updates.server.authorize')}</Button>
					{:else}
						<Button variant="primary" onclick={reviewRelease} disabled={!canPreview || busy}>{busy ? t('admin.updates.server.checking') : t('admin.updates.server.review')}</Button>
					{/if}
				</div>
			{/if}
		</section>

		<section aria-labelledby="progress-heading">
			<h2 id="progress-heading">4. {t('admin.updates.server.progress')}</h2>
			{#if activeIntent}
				<div class:critical={activeIntent.state === 'recovery_required'} class="transaction" aria-live={activeIntent.state === 'recovery_required' ? 'assertive' : 'off'}>
					<div class="transaction-head"><Badge label={stateLabel(activeIntent.state)} variant={tone(activeIntent.state)} /><code>#{activeIntent.intentId}</code></div>
					<Progress value={progressValue} label={t('admin.updates.server.progressLabel')} />
					<ol class="timeline" aria-label="Upgrade transaction history">
						{#each activeIntent.events as event (`${event.generation}-${event.to}`)}
							<li><span>{stateLabel(event.to)}</span><time datetime={event.occurredAt}>{new Date(event.occurredAt).toLocaleString()}</time></li>
						{/each}
					</ol>
					{#if cancellableStates.has(activeIntent.state)}
						<Button variant="secondary" size="sm" onclick={() => cancelIntent(activeIntent)} disabled={busy}>{t('admin.updates.server.cancel')}</Button>
					{/if}
					{#if activeIntent.state === 'recovery_required'}
						<p><strong>{t('admin.updates.server.recoveryRequired')}</strong> {t('admin.updates.server.recoveryRequiredCopy')}</p>
					{/if}
				</div>
			{:else}
				<p class="sj-muted">{t('admin.updates.server.noIntent')}</p>
			{/if}
		</section>
	{/if}

	<a class="sj-link" href="/admin/updates">{t('admin.updates.server.back')}</a>
</div>

<style>
	.sj-page { max-width: 960px; display: grid; gap: var(--space-5); }
	.sj-page-head { display: flex; align-items: flex-start; justify-content: space-between; gap: var(--space-3); flex-wrap: wrap; }
	.sj-page-head h1 { margin: 0; font-size: var(--text-2xl); color: var(--text-primary); }
	.sj-page-head p, .sj-muted, .evidence-grid p { margin: var(--space-1) 0 0; color: var(--text-secondary); font-size: var(--text-sm); }
	h2 { margin: 0 0 var(--space-2); font-size: var(--text-lg); color: var(--text-primary); }
	.sj-loading { display: flex; gap: var(--space-2); align-items: center; color: var(--text-secondary); }
	.sj-banner { display: grid; gap: var(--space-1); padding: var(--space-3); border: 1px solid; border-radius: var(--radius-sm); font-size: var(--text-sm); }
	.sj-banner.warning { background: var(--warning-bg); border-color: var(--warning-fg); color: var(--warning-fg); }
	.sj-banner.danger { background: var(--danger-bg); border-color: var(--danger-fg); color: var(--danger-fg); }
	.release-grid, .evidence-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 260px), 1fr)); gap: var(--space-3); }
	.release-card { min-width: 0; display: grid; gap: var(--space-2); text-align: left; padding: var(--space-3); border: 1px solid var(--border-default); border-radius: var(--radius-sm); background: var(--surface-card); color: var(--text-secondary); cursor: pointer; }
	.release-card:hover { border-color: var(--border-strong); }
	.release-card:focus-visible { outline: none; box-shadow: var(--focus-ring); }
	.release-card.active { border-color: var(--accent); box-shadow: var(--focus-ring); }
	.release-title, .evidence-line, .transaction-head { display: flex; gap: var(--space-2); align-items: center; justify-content: space-between; min-width: 0; }
	code { min-width: 0; overflow-wrap: anywhere; font: var(--text-xs) var(--font-mono); color: var(--text-secondary); }
	.confirm-row { display: grid; gap: var(--space-3); align-items: end; }
	.schedule-field { display: grid; gap: var(--space-1); color: var(--text-primary); font-size: var(--text-sm); }
	.schedule-field input { min-height: 40px; padding: 0 var(--space-2); border: 1px solid var(--border-default); border-radius: var(--radius-sm); background: var(--surface-card); color: var(--text-primary); font: inherit; }
	.schedule-field input:focus-visible { outline: none; box-shadow: var(--focus-ring); }
	.schedule-field small { color: var(--text-secondary); }
	.field-error { color: var(--danger-fg); }
	.preview-box { display: grid; gap: var(--space-1); padding: var(--space-3); border: 1px solid var(--border-default); border-radius: var(--radius-sm); background: var(--surface-sunken); font-size: var(--text-sm); }
	.transaction { display: grid; gap: var(--space-3); padding: var(--space-3); border: 1px solid var(--border-default); border-radius: var(--radius-sm); background: var(--surface-card); }
	.transaction.critical { border-color: var(--danger-fg); background: var(--danger-bg); }
	.timeline { display: grid; gap: var(--space-2); margin: 0; padding-left: var(--space-5); }
	.timeline li { display: flex; justify-content: space-between; gap: var(--space-3); font-size: var(--text-sm); }
	.timeline time { color: var(--text-secondary); white-space: nowrap; }
	.sj-link { color: var(--text-accent); font-size: var(--text-sm); font-weight: 500; }
	.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip-path: inset(50%); white-space: nowrap; border: 0; }

	@media (max-width: 480px) {
		.sj-page { gap: var(--space-4); }
		.sj-page-head :global(.sj-btn), .confirm-row :global(.sj-btn) { width: 100%; }
		.timeline li { display: grid; gap: var(--space-1); }
		.timeline time { white-space: normal; }
	}
</style>
