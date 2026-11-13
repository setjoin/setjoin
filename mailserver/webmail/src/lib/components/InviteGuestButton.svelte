<svelte:options runes={true} />
<script lang="ts">
	import { Button, Dialog, Input } from '$lib/components/ui';
	import { httpRequest } from '$lib/http';
	import { t } from '$lib/i18n';

	let { guestAccountsEnabled, guestInviteEnabled }: {
		guestAccountsEnabled: boolean;
		guestInviteEnabled: boolean;
	} = $props();

	let open = $state(false);
	let email = $state('');
	let message = $state('');
	let submitting = $state(false);
	let error = $state('');
	let success = $state('');
	let disabledReason = $derived(!guestAccountsEnabled
		? t('guestInvite.disabled.accounts')
		: !guestInviteEnabled ? t('guestInvite.disabled.approval') : '');

	async function submit(): Promise<void> {
		submitting = true;
		error = '';
		success = '';
		try {
			await httpRequest('/api/me/guest-invites', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ invitedEmail: email.trim(), message: message.trim() })
			});
			success = t('guestInvite.success');
			email = '';
			message = '';
		} catch (e) {
			error = e instanceof Error ? e.message : t('guestInvite.error');
		} finally {
			submitting = false;
		}
	}
</script>

<div class="guest-invite-entry">
	<Button variant="secondary" disabled={disabledReason !== ''} title={disabledReason || undefined}
		onclick={() => { open = true; error = ''; success = ''; }}>
		{t('guestInvite.action')}
	</Button>
	{#if disabledReason}<p class="guest-invite-entry__hint">{disabledReason}</p>{/if}
</div>

<Dialog {open} title={t('guestInvite.title')} onClose={() => (open = false)}>
	<div class="guest-invite-form">
		<Input label={t('guestInvite.email')} type="email" bind:value={email} />
		<Input label={t('guestInvite.message')} bind:value={message} />
		<div aria-live="polite">
			{#if success}<p class="guest-invite-form__success">{success}</p>{/if}
			{#if error}<p class="guest-invite-form__error">{error}</p>{/if}
		</div>
	</div>
	{#snippet footer()}
		<Button variant="primary" disabled={submitting || !email.trim()} onclick={() => void submit()}>
			{submitting ? t('common.loading') : t('guestInvite.submit')}
		</Button>
		<Button variant="secondary" onclick={() => (open = false)}>{t('common.cancel')}</Button>
	{/snippet}
</Dialog>

<style>
	.guest-invite-entry,.guest-invite-form { display:flex; flex-direction:column; gap:var(--space-2); align-items:flex-start; }
	.guest-invite-entry__hint { margin:0; color:var(--text-caption); font-size:var(--text-sm); }
	.guest-invite-form { align-items:stretch; }
	.guest-invite-form__success { color:var(--success-fg); margin:0; }
	.guest-invite-form__error { color:var(--danger-fg); margin:0; }
</style>
