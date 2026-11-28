<svelte:options runes={true} />

<!--
	ConfirmDestructive — shared typed-confirm dialog for irreversible actions
	(Chat A4a Task 12, design review #6). States the exact consequences +
	affected count, and requires typing an exact word (a channel name, or the
	literal word DESTROY) before the danger button enables — the approvals
	console's plain overlay+Confirm shape is not enough friction for a
	one-click irreversible gxp upgrade or purge.

	Mirrors the existing remote-wipe type-to-confirm dialog
	(admin/offline/DeviceApprovalQueue.svelte:544-589) as a reusable primitive
	instead of a fifth hand-rolled copy.
-->
<script lang="ts">
	import Dialog from './Dialog.svelte';
	import Button from './Button.svelte';
	import Input from './Input.svelte';
	import Spinner from './Spinner.svelte';
	import { t } from '$lib/i18n';

	interface Props {
		open: boolean;
		title: string;
		/** The consequences paragraph — plain text; caller does its own i18n interpolation. */
		message: string;
		/** The exact string that must be typed to enable the confirm button (a channel name, or the literal word "DESTROY"). */
		confirmWord: string;
		/** Danger-button label — e.g. "Upgrade to Records (WORM)" / "Destroy" / "Release hold". */
		confirmLabel: string;
		busy?: boolean;
		error?: string;
		onConfirm: () => void;
		onCancel: () => void;
	}

	let {
		open,
		title,
		message,
		confirmWord,
		confirmLabel,
		busy = false,
		error = '',
		onConfirm,
		onCancel,
	}: Props = $props();

	let typed = $state('');

	// Every re-open starts from a blank input — a typed word from a previous
	// (cancelled, or different-target) confirm must never carry over.
	$effect(() => {
		if (open) typed = '';
	});

	let matches = $derived(typed.length > 0 && typed === confirmWord);
</script>

<Dialog {open} {title} onClose={onCancel}>
	{#snippet children()}
		<p class="cd-message">{message}</p>
		<Input
			label={t('common.type_to_confirm', { value: confirmWord })}
			bind:value={typed}
			disabled={busy}
			autocomplete="off"
		/>
		{#if error}
			<p class="cd-error" role="alert">{error}</p>
		{/if}
	{/snippet}
	{#snippet footer()}
		<Button variant="secondary" onclick={onCancel} disabled={busy}>{t('common.cancel')}</Button>
		<Button
			variant="danger"
			onclick={onConfirm}
			disabled={busy || !matches}
			aria-disabled={matches ? 'false' : 'true'}
		>
			{#if busy}<Spinner size={16} />{/if}
			{confirmLabel}
		</Button>
	{/snippet}
</Dialog>

<style>
	.cd-message {
		font-size: var(--text-sm);
		color: var(--text-primary);
		white-space: pre-line;
		margin: 0 0 var(--space-3);
	}
	.cd-error {
		font-size: var(--text-xs);
		color: var(--text-danger);
		margin: var(--space-2) 0 0;
	}
</style>
