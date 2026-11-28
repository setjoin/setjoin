<svelte:options runes={true} />

<!--
	Meet recordings admin console (whole-pipeline review UX #11). A MINIMAL
	read-only registry read over GET /admin/meet/recordings — no new backend
	work, consumes admin_meet_recordings.go's List handler as-is. Gated on
	the SAME drive.view permission the API enforces (Meet B2 Task 8 plan
	delta 3 — no new permission minted; recordings are Drive-governed
	content). Deliberately no feature.meet_recording toggle check on this
	page either (D10 — the registry is a findability surface, visible
	regardless of the toggle's state) and no filters/actions beyond the
	plain list — the Drive admin page (`/admin/drive`) precedent for
	drive.view gating + Table/Card/EmptyState usage.
-->
<script lang="ts">
	import { adminPermissions, hasPermission } from '$lib/stores/auth';
	import { adminListMeetRecordings, type AdminMeetRecordingRow } from '$lib/admin/client';
	import { Card, Table, Badge, EmptyState, Spinner } from '$lib/components/ui';
	import type { TableColumn } from '$lib/components/ui';
	import { t, formatDateTime } from '$lib/i18n';
	import { formatBytes } from '$lib/utils/display';
	import { parseError } from '$lib/errors';

	let canView = $derived(hasPermission($adminPermissions, 'drive.view'));

	let rows = $state<AdminMeetRecordingRow[]>([]);
	let loading = $state(false);
	let error = $state('');

	async function load() {
		loading = true;
		try {
			rows = await adminListMeetRecordings();
			error = '';
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	// $effect (not onMount): canView resolves from the session's admin
	// permission list, which can still be loading at first mount — the
	// Drive admin page's own established pattern for this exact race.
	$effect(() => {
		if (canView) void load();
	});

	const COLUMNS: TableColumn[] = [
		{ key: 'meeting', label: t('admin.meetRecordings.columns.meeting') },
		{ key: 'state', label: t('admin.meetRecordings.columns.state') },
		{ key: 'started', label: t('admin.meetRecordings.columns.started') },
		{ key: 'ended', label: t('admin.meetRecordings.columns.ended') },
		{ key: 'size', label: t('admin.meetRecordings.columns.size') },
	];

	// D-4 (RecordingsList.svelte precedent, duplicated here — a private
	// per-view mapping, not a shared export): the in-flight states
	// (requested/active/stopping) collapse into ONE chip; the UI never
	// distinguishes them, only the server-owned controls do.
	function chipFor(state: AdminMeetRecordingRow['state']): { variant: 'warning' | 'info' | 'success' | 'danger'; label: string } {
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
</script>

{#if !canView}
	<EmptyState title={t('admin.meetRecordings.noAccess')} />
{:else}
	<div class="meet-recordings-admin">
		<h1 class="meet-recordings-admin__title">{t('admin.meetRecordings.title')}</h1>

		{#if error}
			<p class="meet-recordings-admin__error" role="alert">{error}</p>
		{/if}

		<Card flush={true}>
			{#if loading}
				<div class="meet-recordings-admin__loading"><Spinner /></div>
			{:else if rows.length === 0}
				<EmptyState title={t('admin.meetRecordings.empty')} />
			{:else}
				{@const tableRows = rows as unknown as Record<string, unknown>[]}
				<Table columns={COLUMNS} rows={tableRows}>
					{#snippet cell(row, col)}
						{@const r = row as unknown as AdminMeetRecordingRow}
						{@const chip = chipFor(r.state)}
						{#if col.key === 'meeting'}
							{r.meetingTitle || t('meet.app.titlePlaceholder')} <span class="meet-recordings-admin__id">#{r.meetingId}</span>
						{:else if col.key === 'state'}
							<Badge variant={chip.variant} label={chip.label} />
						{:else if col.key === 'started'}
							{formatDateTime(r.startedAt)}
						{:else if col.key === 'ended'}
							{r.stoppedAt ? formatDateTime(r.stoppedAt) : '—'}
						{:else if col.key === 'size'}
							{r.sizeBytes != null ? formatBytes(r.sizeBytes) : '—'}
						{/if}
					{/snippet}
				</Table>
			{/if}
		</Card>
	</div>
{/if}

<style>
	.meet-recordings-admin {
		max-width: 900px;
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.meet-recordings-admin__title {
		font-size: var(--text-lg);
		font-weight: 600;
		margin: 0;
	}
	.meet-recordings-admin__id {
		color: var(--text-caption);
		font-size: var(--text-xs);
	}
	.meet-recordings-admin__error {
		font-size: var(--text-sm);
		color: var(--danger-fg);
		background: var(--danger-bg);
		padding: var(--space-2);
		border-radius: var(--radius-sm);
		margin: 0;
	}
	.meet-recordings-admin__loading {
		display: flex;
		justify-content: center;
		padding: var(--space-6);
	}
</style>
