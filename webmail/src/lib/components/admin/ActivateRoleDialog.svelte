<svelte:options runes={true} />

<script lang="ts">
	import { Dialog, Button, Spinner, Tooltip } from '$lib/components/ui';
	import { adminActivateRole, type MyRole, type ActivateResult } from '$lib/admin/client';
	import { refreshSession as realRefreshSession } from '$lib/stores/auth';
	import { DURATION_PRESETS, splitWindow } from '$lib/admin/jitStatus';
	import { parseError } from '$lib/errors';
	import { t } from '$lib/i18n';

	let {
		role,
		onClose,
		onActivated,
		// Injectable for the cold-start (D6) refresh; defaults to the real auth path.
		refreshSession = realRefreshSession,
	}: {
		role: MyRole;
		onClose: () => void;
		onActivated: (result: ActivateResult) => void;
		refreshSession?: () => Promise<void>;
	} = $props();

	let selectedMinutes = $state(0);
	let reason = $state('');
	let submitting = $state(false);
	let refreshing = $state(false);
	let inlineError = $state('');
	let reasonEl = $state<HTMLTextAreaElement | null>(null);

	const max = $derived(role.policy.maxDurationMinutes);
	const requireJustification = $derived(role.policy.requireJustification);

	// Format a duration in minutes via the localized unit keys.
	function fmt(minutes: number): string {
		const w = splitWindow(minutes);
		return t(w.unit === 'hr' ? 'admin.jit.dur_hr' : 'admin.jit.dur_min', { n: String(w.n) });
	}

	// Reset when (re)opened for a role: default to the largest allowed preset.
	$effect(() => {
		const allowed = DURATION_PRESETS.filter((p) => p <= role.policy.maxDurationMinutes);
		selectedMinutes = allowed.length ? allowed[allowed.length - 1] : role.policy.maxDurationMinutes;
		reason = '';
		inlineError = '';
	});

	function pick(minutes: number, overMax: boolean) {
		if (overMax) return; // structurally non-selectable — an over-max window can't be submitted
		selectedMinutes = minutes;
	}

	async function submit() {
		// Justification is validated on submit (not keystroke); focus stays on the field.
		if (requireJustification && reason.trim() === '') {
			inlineError = t('admin.jit.reason_missing');
			reasonEl?.focus();
			return;
		}
		submitting = true;
		inlineError = '';
		try {
			const result = await adminActivateRole(
				role.roleGroupId,
				selectedMinutes,
				reason.trim() || undefined
			);
			// D6 cold-start: re-mint the token before the console is treated as active.
			if (result.tokenRefreshRequired) {
				refreshing = true;
				await refreshSession();
			}
			onActivated(result);
		} catch (e) {
			// Rejection (over-max / SoD conflict / not eligible) → inline, focus kept, no close.
			inlineError = parseError(e).message;
		} finally {
			submitting = false;
			refreshing = false;
		}
	}

	const grantExpiry = $derived(
		role.expiresAt ? new Date(role.expiresAt).toLocaleDateString() : null
	);
</script>

<Dialog open={true} title={t('admin.jit.dialog_title', { name: role.name })} onClose={onClose}>
	{#snippet children()}
		<div class="jit-dlg">
			<div class="jit-field">
				<span class="jit-label" id="jit-window-label">{t('admin.jit.window_length')}</span>
				<div class="jit-seg" role="group" aria-labelledby="jit-window-label">
					{#each DURATION_PRESETS as minutes}
						{@const overMax = minutes > max}
						{#if overMax}
							<Tooltip text={t('admin.jit.over_max_reason', { max: fmt(max) })}>
								<button
									type="button"
									class="jit-seg-btn"
									aria-pressed={false}
									aria-disabled="true"
									onclick={() => pick(minutes, true)}
								>{fmt(minutes)}</button>
							</Tooltip>
						{:else}
							<button
								type="button"
								class="jit-seg-btn"
								class:jit-seg-btn--sel={selectedMinutes === minutes}
								aria-pressed={selectedMinutes === minutes}
								onclick={() => pick(minutes, false)}
							>{fmt(minutes)}</button>
						{/if}
					{/each}
				</div>
				<p class="jit-hint">{t('admin.jit.window_hint', { max: fmt(max) })}</p>
			</div>

			<div class="jit-field">
				<label class="jit-label" for="jit-reason">
					{t('admin.jit.reason_label')}
					{#if requireJustification}<span class="jit-req" aria-hidden="true">*</span>{/if}
					<span class="jit-note">
						{requireJustification ? t('admin.jit.reason_required_note') : t('admin.jit.reason_optional_note')}
					</span>
				</label>
				<textarea
					id="jit-reason"
					class="jit-textarea"
					bind:this={reasonEl}
					bind:value={reason}
					required={requireJustification}
					aria-required={requireJustification}
					aria-invalid={inlineError !== ''}
					aria-describedby={inlineError ? 'jit-error' : undefined}
					placeholder={t('admin.jit.reason_placeholder')}
				></textarea>
			</div>

			{#if grantExpiry}
				<p class="jit-hint">{t('admin.jit.expiry_cap_hint', { date: grantExpiry })}</p>
			{/if}

			<!-- Rejection + validation surface: announced politely, focus stays in the dialog. -->
			<div class="jit-error-region" id="jit-error" role="alert" aria-live="assertive">
				{#if inlineError}<span class="jit-error">{inlineError}</span>{/if}
			</div>
		</div>
	{/snippet}
	{#snippet footer()}
		<Button variant="ghost" onclick={onClose} disabled={submitting}>{t('common.cancel')}</Button>
		<Button variant="primary" onclick={submit} disabled={submitting}>
			{#if refreshing}
				<Spinner size={16} /> {t('admin.jit.refreshing')}
			{:else if submitting}
				<Spinner size={16} /> {t('admin.jit.activating')}
			{:else}
				{t('admin.jit.activate')}
			{/if}
		</Button>
	{/snippet}
</Dialog>

<style>
	.jit-dlg {
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
	}
	.jit-field {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.jit-label {
		display: block;
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
	}
	.jit-req {
		color: var(--danger-fg);
		font-weight: var(--weight-bold);
	}
	.jit-note {
		color: var(--text-tertiary);
		font-weight: var(--weight-regular);
		font-size: var(--text-xs);
	}
	.jit-seg {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-2);
	}
	.jit-seg-btn {
		font-family: inherit;
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		min-height: 44px;
		padding: 0 var(--space-3);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		background: var(--surface-card);
		color: var(--text-primary);
		cursor: pointer;
	}
	.jit-seg-btn:hover {
		border-color: var(--text-tertiary);
	}
	.jit-seg-btn:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.jit-seg-btn--sel {
		background: var(--accent-subtle);
		border-color: var(--accent);
		color: var(--accent);
	}
	.jit-seg-btn[aria-disabled='true'] {
		opacity: 0.45;
		cursor: not-allowed;
	}
	.jit-textarea {
		width: 100%;
		font-family: inherit;
		font-size: var(--text-sm);
		color: var(--text-primary);
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		padding: var(--space-2);
		resize: vertical;
		min-height: 64px;
	}
	.jit-textarea:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
	.jit-hint {
		margin: 0;
		font-size: var(--text-xs);
		color: var(--text-tertiary);
	}
	.jit-error-region:empty {
		display: none;
	}
	.jit-error {
		display: block;
		font-size: var(--text-sm);
		color: var(--danger-fg);
		background: var(--danger-bg);
		border-radius: var(--radius-sm);
		padding: var(--space-2) var(--space-3);
	}
</style>
