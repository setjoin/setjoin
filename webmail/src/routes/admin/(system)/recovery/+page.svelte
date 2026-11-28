<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import {
		adminMailRecoveryAccept,
		adminMailRecoveryArtifacts,
		adminMailRecoveryIncidentAction,
		adminMailRecoveryIncidents,
		adminMailRecoveryOpen,
		adminMailRecoveryStatus,
		type MailRecoveryArtifact,
		type MailRecoveryIncident,
		type MailRecoverySignal,
		type MailRecoveryStatus,
	} from '$lib/admin/client';
	import { Badge, Button, Card, EmptyState, Input, Spinner, Switch } from '$lib/components/ui';
	import { parseError } from '$lib/errors';
	import { t } from '$lib/i18n';

	let loading = $state(true);
	let busy = $state(false);
	let error = $state('');
	let status = $state<MailRecoveryStatus | null>(null);
	let incidents = $state<MailRecoveryIncident[]>([]);
	let artifacts = $state<MailRecoveryArtifact[]>([]);
	let selectedIncident = $state<string | null>(null);
	let selected = $state<Record<string, boolean>>({});
	let reason = $state(t('admin.recovery.default_reason'));
	let approvalRequired = $state(true);
	let expiresHours = $state('24');
	let actionReason = $state(t('admin.recovery.default_action_reason'));

	const selectedSignals = $derived((status?.signals ?? []).filter((signal) => selected[signal.mailboxId]));
	const canOpen = $derived(selectedSignals.length > 0 && reason.trim().length >= 8 && !busy);

	function timelineBounds(signals: MailRecoverySignal[]): { minimum: string; maximum: string } {
		const values = signals.map((signal) => BigInt(signal.timelineGeneration));
		return {
			minimum: String(values.reduce((left, right) => left < right ? left : right)),
			maximum: String(values.reduce((left, right) => left > right ? left : right)),
		};
	}

	async function load() {
		loading = true;
		error = '';
		try {
			[status, incidents] = await Promise.all([
				adminMailRecoveryStatus(),
				adminMailRecoveryIncidents(),
			]);
		} catch (caught) {
			error = parseError(caught).message;
		} finally {
			loading = false;
		}
	}

	onMount(load);

	async function openIncident() {
		if (!canOpen) return;
		busy = true;
		error = '';
		try {
			const bounds = timelineBounds(selectedSignals);
			const hours = Math.max(1, Math.min(168, Number.parseInt(expiresHours, 10) || 24));
			await adminMailRecoveryOpen({
				mailboxIds: selectedSignals.map((signal) => signal.mailboxId),
				evidence: Object.fromEntries(selectedSignals.map((signal) => [signal.mailboxId, signal.tokenSha256])),
				minimumTimeline: bounds.minimum,
				maximumTimeline: bounds.maximum,
				expiresAt: new Date(Date.now() + hours * 60 * 60 * 1000).toISOString(),
				reason: reason.trim(),
				approvalRequired,
			});
			selected = {};
			await load();
		} catch (caught) {
			error = `${parseError(caught).message} ${t('admin.recovery.step_up_help')}`;
		} finally {
			busy = false;
		}
	}

	async function incidentAction(incident: MailRecoveryIncident, action: 'approve' | 'close') {
		if (actionReason.trim().length < 8) return;
		busy = true;
		error = '';
		try {
			await adminMailRecoveryIncidentAction(incident.id, action, actionReason.trim());
			await load();
		} catch (caught) {
			error = parseError(caught).message;
		} finally {
			busy = false;
		}
	}

	async function showArtifacts(incidentId: string) {
		busy = true;
		error = '';
		try {
			artifacts = await adminMailRecoveryArtifacts(incidentId);
			selectedIncident = incidentId;
		} catch (caught) {
			error = parseError(caught).message;
		} finally {
			busy = false;
		}
	}

	async function accept(artifact: MailRecoveryArtifact) {
		if (actionReason.trim().length < 8) return;
		busy = true;
		error = '';
		try {
			await adminMailRecoveryAccept(
				artifact.id,
				artifact.status === 'fork_conflict' ? 'accept_fork' : 'accept',
				actionReason.trim(),
			);
			const incidentId = selectedIncident;
			await load();
			if (incidentId) await showArtifacts(incidentId);
		} catch (caught) {
			error = parseError(caught).message;
		} finally {
			busy = false;
		}
	}

	function variant(value: string): 'success' | 'warning' | 'danger' | 'neutral' | 'info' {
		if (value === 'accepted' || value === 'open' || value === 'clean') return 'success';
		if (value === 'quarantined' || value === 'fork_conflict') return 'warning';
		if (value === 'rejected' || value === 'tampered' || value === 'infected') return 'danger';
		return 'neutral';
	}

	function statusLabel(value: string): string {
		const translated = t(`admin.recovery.status.${value}`);
		return translated === `admin.recovery.status.${value}` ? value : translated;
	}
</script>

<svelte:head><title>{t('admin.recovery.title')} — Admin</title></svelte:head>

<div class="recovery-page">
	<header class="page-head">
		<div>
			<h1>{t('admin.recovery.title')}</h1>
			<p>{t('admin.recovery.subtitle')}</p>
		</div>
		<Button variant="secondary" onclick={load} disabled={loading || busy}>{t('admin.recovery.refresh')}</Button>
	</header>

	{#if error}<div class="error" role="alert">{error}</div>{/if}
	{#if loading}
		<Spinner label={t('admin.recovery.loading')} />
	{:else if status}
		<div class="grid">
			<Card title={t('admin.recovery.evidence_title')}>
				<p class="muted">{t('admin.recovery.local_timeline')} <strong>{status.localTimelineGeneration}</strong> · {t('admin.recovery.installation')} <code>{status.installationId}</code></p>
				{#if status.signals.length === 0}
					<EmptyState title={t('admin.recovery.no_newer_timeline')} />
					<p class="muted">{t('admin.recovery.clock_not_enough')}</p>
				{:else}
					<div class="signal-list">
						{#each status.signals as signal (signal.mailboxId + signal.tokenSha256)}
							<label class="signal-row">
								<input type="checkbox" checked={!!selected[signal.mailboxId]} onchange={(event) => selected = { ...selected, [signal.mailboxId]: event.currentTarget.checked }} />
								<span><strong>{signal.email}</strong><small>{t('admin.recovery.signal_detail', { mailbox: signal.mailboxId, timeline: signal.timelineGeneration, observed: new Date(signal.observedAt).toLocaleString() })}</small></span>
							</label>
						{/each}
					</div>
					<div class="form-grid">
						<Input label={t('admin.recovery.audit_reason')} bind:value={reason} maxlength={1024} />
						<Input label={t('admin.recovery.expiry_hours')} type="number" min="1" max="168" bind:value={expiresHours} />
						<Switch label={t('admin.recovery.require_second_admin')} checked={approvalRequired} onchange={(event) => approvalRequired = event.currentTarget.checked} />
					</div>
					<Button variant="primary" onclick={openIncident} disabled={!canOpen}>{t('admin.recovery.open_incident')}</Button>
				{/if}
			</Card>

			<Card title={t('admin.recovery.incident_history')}>
				<Input label={t('admin.recovery.action_reason')} bind:value={actionReason} maxlength={1024} />
				{#if incidents.length === 0}
					<EmptyState title={t('admin.recovery.no_incidents')} />
					<p class="muted">{t('admin.recovery.no_incidents_help')}</p>
				{:else}
					<div class="incident-list">
						{#each incidents as incident (incident.id)}
							<article class="incident-row">
								<div class="row-head"><code>{incident.id}</code><Badge label={statusLabel(incident.status)} variant={variant(incident.status)} /></div>
								<p>{incident.reason}</p>
								<small>{t('admin.recovery.incident_detail', { mailboxes: String(incident.mailboxCount), quarantined: String(incident.counts.quarantined), accepted: String(incident.counts.accepted), expires: new Date(incident.expiresAt).toLocaleString() })}</small>
								<div class="actions">
									<Button size="sm" variant="secondary" onclick={() => showArtifacts(incident.id)} disabled={busy}>{t('admin.recovery.review_artifacts')}</Button>
									{#if incident.status === 'open' && incident.approvalRequired && !incident.approvedBy}<Button size="sm" variant="primary" onclick={() => incidentAction(incident, 'approve')} disabled={busy || actionReason.trim().length < 8}>{t('admin.recovery.approve')}</Button>{/if}
									{#if incident.status === 'open'}<Button size="sm" variant="danger" onclick={() => incidentAction(incident, 'close')} disabled={busy || actionReason.trim().length < 8}>{t('admin.recovery.close')}</Button>{/if}
								</div>
							</article>
						{/each}
					</div>
				{/if}
			</Card>
		</div>

		{#if selectedIncident}
			<Card title={t('admin.recovery.quarantine_review')}>
				{#if artifacts.length === 0}
					<EmptyState title={t('admin.recovery.no_artifacts')} />
					<p class="muted">{t('admin.recovery.no_artifacts_help')}</p>
				{:else}
					<div class="artifact-list">
						{#each artifacts as artifact (artifact.id)}
							<article class="artifact-row">
								<div class="row-head"><strong>{artifact.headers.subject || t('admin.recovery.no_subject')}</strong><Badge label={statusLabel(artifact.status)} variant={variant(artifact.status)} /></div>
								<p>{artifact.headers.from || t('admin.recovery.unknown_sender')} · {t('admin.recovery.artifact_detail', { mailbox: artifact.mailboxId, bytes: artifact.rawMimeSize })}</p>
								<small>SHA-256 <code>{artifact.rawMimeSha256}</code> · {t('admin.recovery.artifact_provenance', { timeline: artifact.signedTimeline, malware: statusLabel(artifact.malwareStatus) })}</small>
								{#if artifact.rejectionReason}<p class="error">{artifact.rejectionReason}</p>{/if}
								{#if artifact.status === 'quarantined' || (artifact.status === 'fork_conflict' && artifact.forkConsented)}
									<Button size="sm" variant="primary" onclick={() => accept(artifact)} disabled={busy || actionReason.trim().length < 8}>{artifact.status === 'fork_conflict' ? t('admin.recovery.accept_fork') : t('admin.recovery.accept')}</Button>
								{/if}
							</article>
						{/each}
					</div>
				{/if}
			</Card>
		{/if}
	{/if}
</div>

<style>
	.recovery-page { padding: var(--space-6); display: grid; gap: var(--space-5); max-width: 90rem; margin: 0 auto; }
	.page-head, .row-head, .actions { display: flex; align-items: center; justify-content: space-between; gap: var(--space-3); flex-wrap: wrap; }
	.page-head h1, .page-head p, .incident-row p, .artifact-row p { margin: 0; }
	.page-head p, .muted, small { color: var(--text-secondary); }
	.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 28rem), 1fr)); gap: var(--space-5); }
	.signal-list, .incident-list, .artifact-list { display: grid; gap: var(--space-3); margin: var(--space-3) 0; }
	.signal-row, .incident-row, .artifact-row { border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: var(--space-3); display: grid; gap: var(--space-2); }
	.signal-row { grid-template-columns: auto 1fr; cursor: pointer; }
	.signal-row span { display: grid; gap: var(--space-1); min-width: 0; }
	.form-grid { display: grid; gap: var(--space-3); margin: var(--space-4) 0; }
	.actions { justify-content: flex-start; }
	.error { color: var(--text-danger); background: var(--surface-danger-subtle); padding: var(--space-3); border-radius: var(--radius-md); }
	code { overflow-wrap: anywhere; font-size: var(--text-xs); }

	@media (max-width: 40rem) { .recovery-page { padding: var(--space-4); } }
</style>
