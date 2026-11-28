<svelte:options runes={true} />

<script lang="ts">
	// RecordingsList — Meet B2 Task 10, spec §7/§9: the ended-meeting detail's
	// recordings panel. `ready`'s <video> hits the SAME-ORIGIN, cookie-authed
	// Drive content route (`contentUrl`) — zero CSP delta, `media-src 'self'`
	// already covers it (drive/content.go's existing Range-streaming route;
	// access is `driveMemberScopeSQL` → `drive_member_role`, which already
	// derives from meeting attendance for a chat/meeting-bound space).
	import type { MeetingRecording } from '$lib/meet/api';
	import { contentUrl } from '$lib/drive/api';
	import { Card, Badge, EmptyState } from '$lib/components/ui';
	import { t } from '$lib/i18n';

	let { recordings }: { recordings: MeetingRecording[] } = $props();

	// D-4: one chip covers the whole in-flight span (requested/active/
	// stopping) — the UI never distinguishes them; only the server-owned
	// controls do.
	function chipFor(state: MeetingRecording['state']): { variant: 'warning' | 'info' | 'success' | 'danger'; label: string } {
		switch (state) {
			case 'requested':
			case 'active':
			case 'stopping':
				return { variant: 'warning', label: t('meet.recording.inProgress') };
			case 'pending_ingest':
				return { variant: 'info', label: t('meet.recording.processing') };
			case 'ready':
				return { variant: 'success', label: t('meet.recording.ready') };
			case 'failed':
				return { variant: 'danger', label: t('meet.recording.failed') };
		}
	}

	// B2 retro F9: the worker (internal/meet/worker.go) writes a handful of
	// known machine-readable reasons into `error` — map those to localized
	// copy; anything else (an unrecognized/future reason) falls back to the
	// raw string rather than hiding it. The raw string always rides `title=`
	// regardless, for anyone who needs it verbatim.
	function errorLabel(raw: string): string {
		if (raw === 'egress_busy') return t('meet.recording.busy');
		if (raw.startsWith('stopping with no egress binding')) return t('meet.recording.errorUnbound');
		if (raw.startsWith('ingest failed after')) return t('meet.recording.errorIngestFailed');
		return raw;
	}
</script>

<div class="recordings-list">
	<h3 class="recordings-list__title">{t('meet.recording.recordingsTitle')}</h3>
	{#if recordings.length === 0}
		<EmptyState title={t('meet.recording.empty')} />
	{:else}
		<ul class="recordings-list__items" role="list">
			{#each recordings as r (r.recordingId)}
				{@const chip = chipFor(r.state)}
				<li class="recordings-list__row">
					<Card>
						<div class="recordings-list__row-head">
							<Badge variant={chip.variant} label={chip.label} />
						</div>
						{#if r.state === 'ready' && r.versionId != null}
							<!-- svelte-ignore a11y_media_has_caption -->
							<video controls preload="metadata" src={contentUrl(r.versionId)} class="recordings-list__video"></video>
						{:else if r.state === 'failed'}
							<p class="recordings-list__error" title={r.error ?? ''}>{errorLabel(r.error ?? '')}</p>
						{/if}
					</Card>
				</li>
			{/each}
		</ul>
	{/if}
</div>

<style>
	.recordings-list {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.recordings-list__title {
		margin: 0;
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-primary);
	}
	.recordings-list__items {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.recordings-list__row-head {
		display: flex;
		justify-content: flex-start;
	}
	.recordings-list__video {
		width: 100%;
		margin-top: var(--space-2);
		border-radius: var(--radius-sm);
	}
	.recordings-list__error {
		margin: var(--space-2) 0 0;
		color: var(--danger-fg);
		font-size: var(--text-sm);
	}
</style>
