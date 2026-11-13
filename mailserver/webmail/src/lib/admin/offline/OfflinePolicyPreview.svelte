<!--
  OfflinePolicyPreview — E5 gated server-resolved policy preview (R4).
  Renders ONLY when the connectivity-aware-sync program is active (observe or
  execute): the parent gates this component behind `e5ui.active`, so the
  default-OFF posture renders nothing here at all.

  Contract (R4 settings/admin amendments):
  - The preview is a SERVER authority read for a selected user/device; the
    client never recomputes precedence.
  - Every response binds the selected target AND the request generation: an
    old response can never replace a newer selection.
  - A failed refresh labels retained facts stale; unauthorized and unavailable
    are honest states.
  - Disabled winning policies stay visible.
  - A background refresh never steals focus or discards edits: this block only
    ever renders text; it calls no focus() and owns no form state.
-->
<svelte:options runes={true} />

<script lang="ts">
	import { t } from '$lib/i18n';
	import { Button, Badge, Spinner } from '$lib/components/ui';
	import {
		createAdminPreviewController,
		type E5PreviewPayload,
		type E5PreviewTarget,
	} from '$lib/offline/e5AdminPreview';

	interface Props {
		/** Resolve one preview request; throws { forbidden?: boolean } on failure. */
		load: (target: E5PreviewTarget) => Promise<unknown>;
		/** Test seam: start from a non-idle controller state. */
		__controller?: ReturnType<typeof createAdminPreviewController>;
	}

	let { load, __controller = undefined }: Props = $props();

	// The controller is created once per component instance; the __controller
	// prop is an init-only test seam (never reassigned afterwards).
	// svelte-ignore state_referenced_locally
	const controller = __controller ?? createAdminPreviewController();

	let targetUserId = $state('');
	let deviceId = $state('');
	let announcement = $state('');

	const status = $derived(controller.status());
	const busy = $derived(status.kind === 'loading');

	function selectedTarget(): E5PreviewTarget | null {
		const user = targetUserId.trim();
		const device = deviceId.trim();
		if (user.length === 0 || device.length === 0) return null;
		return { targetUserId: user, deviceId: device };
	}

	async function runPreview(): Promise<void> {
		const target = selectedTarget();
		if (target === null || busy) return;
		controller.selectTarget(target);
		const generation = controller.generation;
		announcement = t('offline.e5.admin.preview_loading');
		try {
			const payload = await load(target);
			const result = controller.loaded(generation, payload);
			announcement = result.kind === 'applied'
				? t('offline.e5.admin.preview_loaded')
				: t('offline.e5.admin.preview_unavailable');
		} catch (error) {
			const forbidden = (error as { forbidden?: boolean } | null)?.forbidden === true;
			controller.failed(generation, { forbidden });
			announcement = forbidden
				? t('offline.e5.admin.preview_unauthorized')
				: t('offline.e5.admin.preview_unavailable');
		}
	}

	function sourceBadgeLabel(source: { policyId?: string; scope?: string } | undefined): string {
		if (source === undefined || (source.policyId === undefined && source.scope === undefined)) {
			return t('offline.e5.admin.source_default');
		}
		const policy = source.policyId ?? '?';
		const scope = source.scope ?? t('offline.e5.admin.source_scope_unknown');
		return t('offline.e5.admin.source_policy', { policy, scope });
	}

	// Wire enums are stable machine values; the UI renders them translated.
	// Unknown values fail visible as the raw key (never silently mislabeled).
	function syncModeLabel(mode: string): string {
		return t(`offline.e5.admin.sync_mode.${mode}`);
	}
	function networkPrefLabel(value: string): string {
		return t(`offline.e5.settings.net.${value}`);
	}
	function attachmentPrefLabel(value: string): string {
		return t(`offline.e5.settings.att.${value}`);
	}
</script>

<div class="e5-preview" data-testid="e5-admin-preview">
	<h4 class="e5-preview__title">{t('offline.e5.admin.preview_title')}</h4>
	<p class="e5-preview__hint">{t('offline.e5.admin.preview_hint')}</p>

	<div class="e5-preview__target">
		<label class="e5-preview__field">
			<span>{t('offline.e5.admin.target_user')}</span>
			<input
				type="text"
				bind:value={targetUserId}
				data-testid="e5-preview-user"
				autocomplete="off"
				disabled={busy}
			/>
		</label>
		<label class="e5-preview__field">
			<span>{t('offline.e5.admin.target_device')}</span>
			<input
				type="text"
				bind:value={deviceId}
				data-testid="e5-preview-device"
				autocomplete="off"
				disabled={busy}
			/>
		</label>
		<Button
			variant="secondary"
			size="sm"
			onclick={runPreview}
			disabled={busy || selectedTarget() === null}
			data-testid="e5-preview-run"
		>
			{busy ? t('offline.e5.admin.preview_loading') : t('offline.e5.admin.preview_run')}
		</Button>
	</div>

	{#if status.kind === 'loading'}
		<p class="e5-preview__state" data-testid="e5-preview-loading">
			<Spinner size={16} label={t('offline.e5.admin.preview_loading')} />
			{t('offline.e5.admin.preview_loading')}
		</p>
	{:else if status.kind === 'unauthorized'}
		<p class="e5-preview__state e5-preview__state--warn" data-testid="e5-preview-unauthorized" role="alert">
			{t('offline.e5.admin.preview_unauthorized')}
			{#if status.stale}
				<span class="e5-preview__stale">{t('offline.e5.admin.retained_stale')}</span>
			{/if}
		</p>
	{:else if status.kind === 'unavailable'}
		<p class="e5-preview__state e5-preview__state--warn" data-testid="e5-preview-unavailable" role="alert">
			{t('offline.e5.admin.preview_unavailable')}
			{#if status.stale}
				<span class="e5-preview__stale">{t('offline.e5.admin.retained_stale')}</span>
			{/if}
		</p>
	{/if}

	{#if status.kind === 'current' || ((status.kind === 'unavailable' || status.kind === 'unauthorized') && status.retained !== null)}
		{@const payload = (status.kind === 'current' ? status.payload : status.retained) as E5PreviewPayload}
		{@const projection = payload.projection}
		<dl class="e5-preview__facts" data-testid="e5-preview-facts" aria-busy={status.kind !== 'current'}>
			{#if status.kind !== 'current'}
				<dt></dt>
				<dd class="e5-preview__stale">{t('offline.e5.admin.retained_stale')}</dd>
			{/if}
			<dt>{t('offline.e5.admin.winning_policy')}</dt>
			<dd>
				<span class="e5-preview__policy-id">{projection.sources.automaticNetwork?.policyId ?? t('offline.e5.admin.source_default')}</span>
				<Badge
					variant={projection.syncMode === 'off' ? 'neutral' : 'success'}
					label={syncModeLabel(projection.syncMode)}
				/>
			</dd>
			<dt>{t('offline.e5.admin.requested_refresh')}</dt>
			<dd data-testid="e5-preview-requested-refresh">{networkPrefLabel(projection.requested.automaticNetwork)}</dd>
			<dt>{t('offline.e5.admin.effective_refresh')}</dt>
			<dd data-testid="e5-preview-effective-refresh">{networkPrefLabel(projection.effective.automaticNetwork)}</dd>
			<dt>{t('offline.e5.admin.requested_attachments')}</dt>
			<dd data-testid="e5-preview-requested-attachments">{attachmentPrefLabel(projection.requested.attachmentPrefetch)}</dd>
			<dt>{t('offline.e5.admin.effective_attachments')}</dt>
			<dd data-testid="e5-preview-effective-attachments">{attachmentPrefLabel(projection.effective.attachmentPrefetch)}</dd>
			<dt>{t('offline.e5.admin.background_allowed')}</dt>
			<dd>{projection.backgroundAllowed ? t('offline.e5.admin.on') : t('offline.e5.admin.off')}</dd>
			<dt>{t('offline.e5.admin.source_refresh')}</dt>
			<dd>{sourceBadgeLabel(projection.sources.automaticNetwork)}</dd>
			<dt>{t('offline.e5.admin.source_attachments')}</dt>
			<dd>{sourceBadgeLabel(projection.sources.attachmentPrefetch)}</dd>
		</dl>
	{/if}

	<!-- ONE polite live region owns async outcomes; the visual block is not live. -->
	<span class="sr-only" aria-live="polite" data-testid="e5-preview-live">{announcement}</span>
</div>

<style>
	.e5-preview {
		margin-top: var(--space-4);
		padding-top: var(--space-4);
		border-top: 1px solid var(--border-subtle);
		display: grid;
		gap: var(--space-2);
	}
	.e5-preview__title {
		margin: 0;
		font-size: var(--text-sm);
		font-weight: var(--font-weight-semibold);
		color: var(--text-primary);
	}
	/* Must-read hint/stale text uses the AA-safe caption channel
	   (--text-tertiary is below AA for small text; see theme/colors.css). */
	.e5-preview__hint {
		margin: 0;
		font-size: var(--text-xs);
		color: var(--text-caption);
	}
	.e5-preview__target {
		display: flex;
		flex-wrap: wrap;
		align-items: end;
		gap: var(--space-2);
	}
	.e5-preview__field {
		display: grid;
		gap: var(--space-1);
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}
	.e5-preview__field input {
		min-height: 44px;
		padding: 0 var(--space-2);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		background: var(--surface-raised);
		color: var(--text-primary);
		font: inherit;
	}
	.e5-preview__field input:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.e5-preview__state {
		margin: 0;
		display: inline-flex;
		align-items: center;
		gap: var(--space-2);
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.e5-preview__state--warn { color: var(--warning-fg); }
	.e5-preview__stale {
		font-size: var(--text-xs);
		color: var(--text-caption);
		font-style: italic;
	}
	.e5-preview__facts {
		margin: 0;
		display: grid;
		grid-template-columns: minmax(10rem, max-content) 1fr;
		gap: var(--space-1) var(--space-3);
		font-size: var(--text-sm);
	}
	.e5-preview__facts dt {
		color: var(--text-secondary);
	}
	.e5-preview__facts dd {
		margin: 0;
		display: flex;
		align-items: center;
		gap: var(--space-2);
		color: var(--text-primary);
	}
	.e5-preview__policy-id { font-family: var(--font-mono); font-size: var(--text-xs); }
	.sr-only {
		position: absolute;
		width: 1px;
		height: 1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
	}
</style>
