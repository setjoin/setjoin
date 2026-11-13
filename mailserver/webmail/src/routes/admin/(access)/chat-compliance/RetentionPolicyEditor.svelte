<svelte:options runes={true} />

<!--
	RetentionPolicyEditor — create/edit dialog for a chat_retention_policies
	row (Chat A4a Task 12). Shape follows approvals/PolicyEditor.svelte, with
	two additions the plan requires:
	  - N4 re-arm warning: a BEFORE-save banner when the edit can only GROW
	    the destroyed set (the server's exposesAnyChannel check is the
	    authoritative backstop; this is a cheap early-out so the admin isn't
	    surprised the grace re-armed).
	  - N7 purge-impact confirm: Save is disabled until "Preview impact" has
	    been fetched, and the final save goes through ConfirmDestructive
	    (typed DESTROY) stating the TOTAL backlog + the nightly-drain rate —
	    never implying the whole backlog goes in one night.
-->
<script lang="ts">
	import { Dialog, Button, Input, Select, Switch, ConfirmDestructive } from '$lib/components/ui';
	import { t } from '$lib/i18n';
	import { parseError } from '$lib/errors';
	import {
		adminCreateChatRetentionPolicy,
		adminUpdateChatRetentionPolicy,
		adminPreviewChatPurge,
		type ChatRetentionPolicy,
		type ChatAppliesTo,
	} from '$lib/admin/client';

	interface Props {
		open: boolean;
		/** null = create mode; defined = edit mode. */
		policy: ChatRetentionPolicy | null;
		onsaved: (effectiveAt: string) => void;
		oncancel: () => void;
	}

	let { open, policy, onsaved, oncancel }: Props = $props();

	const APPLIES_TO_OPTIONS: Array<{ value: ChatAppliesTo; label: string }> = [
		{ value: 'all', label: t('admin.chatCompliance.policy.appliesTo.all') },
		{ value: 'channel', label: t('admin.chatCompliance.policy.appliesTo.channel') },
		{ value: 'dm', label: t('admin.chatCompliance.policy.appliesTo.dm') },
		{ value: 'group_dm', label: t('admin.chatCompliance.policy.appliesTo.group_dm') },
	];

	let name = $state('');
	let appliesTo = $state<ChatAppliesTo>('all');
	let durationDaysStr = $state('30');
	let enabled = $state(true);
	let nameError = $state('');
	let saveError = $state('');
	let saving = $state(false);

	let previewFetched = $state(false);
	let previewMessages = $state(0);
	let previewChannels = $state(0);
	let previewLoading = $state(false);

	let confirmOpen = $state(false);

	$effect(() => {
		void open; // re-seed on every open, not only when the target policy changes
		name = policy?.name ?? '';
		appliesTo = policy?.appliesTo ?? 'all';
		durationDaysStr = String(policy?.durationDays ?? 30);
		enabled = policy?.enabled ?? true;
		nameError = '';
		saveError = '';
		previewFetched = false;
		previewMessages = 0;
		previewChannels = 0;
		confirmOpen = false;
	});

	let durationDays = $derived(Number(durationDaysStr) || 0);

	// N4/FIX 3's cheap per-policy early-out (the server's exposesAnyChannel
	// query, which also catches shielding-weakening edits, is the
	// authoritative backstop run at save time — this is only a
	// before-save warning).
	let willRearm = $derived(
		policy != null &&
			(durationDays < policy.durationDays ||
				(enabled && !policy.enabled) ||
				appliesTo !== policy.appliesTo)
	);

	async function loadPreview() {
		previewLoading = true;
		saveError = '';
		try {
			const preview = await adminPreviewChatPurge();
			previewMessages = preview.totalMessages;
			previewChannels = preview.totalChannels;
			previewFetched = true;
		} catch (e) {
			saveError = parseError(e).message;
		} finally {
			previewLoading = false;
		}
	}

	function openConfirm() {
		nameError = name.trim() === '' ? t('admin.chatCompliance.policy.name_required') : '';
		if (nameError || durationDays <= 0 || !previewFetched) return;
		confirmOpen = true;
	}

	async function doSave() {
		saving = true;
		saveError = '';
		try {
			const body = { name: name.trim(), appliesTo, durationDays, enabled };
			// The (possibly re-armed) effectiveAt comes back from the SAVE
			// response — the caller must re-render from it, never from what the
			// editor displayed pre-save (N4).
			const res = policy
				? await adminUpdateChatRetentionPolicy(policy.id, body)
				: await adminCreateChatRetentionPolicy(body);
			confirmOpen = false;
			onsaved(res.effectiveAt);
		} catch (e) {
			saveError = parseError(e).message;
		} finally {
			saving = false;
		}
	}
</script>

<Dialog
	{open}
	title={policy
		? t('admin.chatCompliance.policy.editor.title_edit')
		: t('admin.chatCompliance.policy.editor.title_create')}
	onClose={oncancel}
>
	{#snippet children()}
		<form
			class="rpe-form"
			onsubmit={(e) => {
				e.preventDefault();
				openConfirm();
			}}
		>
			<div class="rpe-field">
				<Input label={t('admin.chatCompliance.policy.name_label')} bind:value={name} required />
				{#if nameError}<p class="rpe-error" role="alert">{nameError}</p>{/if}
			</div>
			<div class="rpe-field">
				<Select
					label={t('admin.chatCompliance.policy.appliesTo_label')}
					bind:value={appliesTo}
					options={APPLIES_TO_OPTIONS}
				/>
			</div>
			<div class="rpe-field">
				<Input
					type="number"
					min="1"
					label={t('admin.chatCompliance.policy.durationDays_label')}
					bind:value={durationDaysStr}
				/>
			</div>
			<div class="rpe-field rpe-field--row">
				<span class="rpe-label">{t('admin.chatCompliance.policy.enabled_label')}</span>
				<Switch bind:checked={enabled} />
			</div>

			{#if policy}
				<p class="rpe-hint">
					{t('admin.chatCompliance.policy.effectiveOn', { date: policy.effectiveAt.slice(0, 10) })}
				</p>
			{/if}
			<p class="rpe-hint">{t('admin.chatCompliance.policy.graceHint')}</p>
			{#if willRearm}
				<p class="rpe-warning" role="alert">{t('admin.chatCompliance.policy.rearmWarning')}</p>
			{/if}

			<div class="rpe-preview">
				<Button
					type="button"
					variant="secondary"
					size="sm"
					onclick={loadPreview}
					disabled={previewLoading}
				>
					{t('admin.chatCompliance.policy.previewImpact')}
				</Button>
				{#if previewFetched}
					<span class="rpe-preview__result">
						{t('admin.chatCompliance.policy.previewNote', {
							messages: String(previewMessages),
							channels: String(previewChannels),
						})}
					</span>
				{/if}
			</div>
			{#if !previewFetched}
				<p class="rpe-hint">{t('admin.chatCompliance.policy.previewRequiredHint')}</p>
			{/if}

			{#if saveError}<p class="rpe-error" role="alert">{saveError}</p>{/if}

			<div class="rpe-actions">
				<Button type="button" variant="ghost" onclick={oncancel}>
					{t('admin.chatCompliance.policy.cancel')}
				</Button>
				<Button type="submit" variant="primary" disabled={!previewFetched}>
					{t('admin.chatCompliance.policy.save')}
				</Button>
			</div>
		</form>
	{/snippet}
</Dialog>

<ConfirmDestructive
	open={confirmOpen}
	title={t('admin.chatCompliance.purge.confirmTitle')}
	message={t('admin.chatCompliance.purge.confirmMessage', {
		messages: String(previewMessages),
		channels: String(previewChannels),
	})}
	confirmWord="DESTROY"
	confirmLabel={t('admin.chatCompliance.purge.confirmButton')}
	busy={saving}
	error={saveError}
	onConfirm={doSave}
	onCancel={() => (confirmOpen = false)}
/>

<style>
	.rpe-form {
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
		min-width: 380px;
	}
	.rpe-field {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.rpe-field--row {
		flex-direction: row;
		align-items: center;
		justify-content: space-between;
	}
	.rpe-label {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-secondary);
	}
	.rpe-hint {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		margin: 0;
	}
	.rpe-warning {
		font-size: var(--text-sm);
		color: var(--warning-fg, var(--text-danger));
		background: var(--warning-bg, transparent);
		border-radius: var(--radius-sm);
		padding: var(--space-2);
		margin: 0;
	}
	.rpe-error {
		font-size: var(--text-xs);
		color: var(--text-danger);
		margin: 0;
	}
	.rpe-preview {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		flex-wrap: wrap;
	}
	.rpe-preview__result {
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.rpe-actions {
		display: flex;
		justify-content: flex-end;
		gap: var(--space-2);
		padding-top: var(--space-2);
		border-top: 1px solid var(--border-default);
	}
</style>
