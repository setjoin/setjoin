<svelte:options runes={true} />

<script lang="ts">
	// P5 Task 11 — gxp change-control note. A gxp space requires a change note
	// on every save (spec §2.1's `note` column) before the upload proceeds.
	// Dialog gives focus-trap + Escape for free (ui/Dialog.svelte).
	import { Button, Dialog, Textarea } from '$lib/components/ui';
	import { t } from '$lib/i18n';

	let {
		open,
		onSubmit,
		onCancel,
	}: {
		open: boolean;
		onSubmit: (note: string) => void;
		onCancel: () => void;
	} = $props();

	let note = $state('');

	let valid = $derived(note.trim().length >= 1 && note.trim().length <= 2000);

	function submit() {
		if (!valid) return;
		const value = note.trim();
		note = '';
		onSubmit(value);
	}

	function cancel() {
		note = '';
		onCancel();
	}
</script>

<Dialog open={open} title={t('drive.version.changeNoteTitle')} onClose={cancel}>
	<Textarea
		label={t('drive.version.changeNotePrompt')}
		hint={t('drive.version.changeNoteHelp')}
		bind:value={note}
		required
		maxlength={2000}
		rows={4}
	/>
	{#snippet footer()}
		<Button variant="primary" disabled={!valid} onclick={submit}>{t('drive.version.changeNoteSave')}</Button>
		<Button variant="secondary" onclick={cancel}>{t('common.cancel')}</Button>
	{/snippet}
</Dialog>
