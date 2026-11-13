<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { Button } from '$lib/components/ui';
	import { t } from '$lib/i18n';
	import { applySenderControl, readSenderControl, type SenderControlAction, type SenderControlState, type SenderControlTarget } from '$lib/mail/senderControl';

	let { target, onClose, onChanged }: { target: SenderControlTarget; onClose: () => void; onChanged?: () => void } = $props();
	let control = $state<SenderControlState | null>(null);
	let loading = $state(true);
	let pending = $state<SenderControlAction | null>(null);
	let error = $state('');
	let lastOperation = $state<string | null>(null);

	onMount(async () => {
		try { control = await readSenderControl(target); }
		catch { error = t('inbox.sender_control.error'); }
		finally { loading = false; }
	});

	async function apply(action: SenderControlAction) {
		if (!control || pending) return;
		pending = action; error = '';
		try {
			const next = await applySenderControl(target, action, control.generation, action === 'undo' ? lastOperation ?? undefined : undefined);
			if (action !== 'undo') lastOperation = next.operationId ?? null;
			else lastOperation = null;
			control = next;
			onChanged?.();
		} catch { error = t('inbox.sender_control.error'); }
		finally { pending = null; }
	}

	function toggleVip() { void apply(control?.vip ? 'not_vip' : 'vip'); }
</script>

<div class="sj-sender-control" role="dialog" aria-modal="false" aria-label={t('inbox.sender_control.title')}>
	<header><div><strong>{t('inbox.sender_control.title')}</strong>{#if control}<span>{control.sender}</span>{/if}</div><button type="button" onclick={onClose} aria-label={t('common.close')}>×</button></header>
	{#if loading}<p>{t('common.loading')}</p>
	{:else if control}
		<section aria-label={t('inbox.sender_control.focus')}>
			<h3>{t('inbox.sender_control.focus')}</h3>
			<Button size="sm" variant={control.alwaysFocus ? 'primary' : 'secondary'} disabled={!!pending} onclick={() => apply('always_focus')}>{t('inbox.sender_control.always_focus')}</Button>
			<Button size="sm" variant={control.neverFocus ? 'primary' : 'secondary'} disabled={!!pending} onclick={() => apply('never_focus')}>{t('inbox.sender_control.never_focus')}</Button>
			<Button size="sm" variant={control.vip ? 'primary' : 'secondary'} disabled={!!pending} onclick={toggleVip}>{control.vip ? t('inbox.sender_control.remove_vip') : t('inbox.sender_control.vip')}</Button>
		</section>
		<section aria-label={t('inbox.sender_control.safety')}>
			<h3>{t('inbox.sender_control.safety')}</h3>
			<Button size="sm" variant={control.safe ? 'primary' : 'secondary'} disabled={!!pending} onclick={() => apply('never_block')}>{t('inbox.sender_control.never_block')}</Button>
			<Button size="sm" variant={control.blocked ? 'danger' : 'secondary'} disabled={!!pending} onclick={() => apply('block')}>{t('inbox.sender_control.block')}</Button>
			<Button size="sm" variant="secondary" disabled={!!pending} onclick={() => apply('report_spam')}>{t('inbox.sender_control.report_spam')}</Button>
			<Button size="sm" variant="secondary" disabled={!!pending} onclick={() => apply('report_phishing')}>{t('inbox.sender_control.report_phishing')}</Button>
		</section>
		{#if lastOperation}<Button size="sm" variant="ghost" disabled={!!pending} onclick={() => apply('undo')}>{t('common.undo')}</Button>{/if}
	{/if}
	{#if error}<p class="error" role="alert">{error}</p>{/if}
</div>

<style>
	.sj-sender-control { position:absolute; z-index:var(--z-popover); top:calc(100% + var(--space-1)); right:var(--space-2); width:min(420px,calc(100vw - var(--space-4))); padding:var(--space-3); border:1px solid var(--border-default); border-radius:var(--radius-md); background:var(--surface-card); box-shadow:var(--shadow-lg); }
	header { display:flex; justify-content:space-between; gap:var(--space-2); margin-bottom:var(--space-3); }
	header div { display:flex; flex-direction:column; min-width:0; }
	header span { overflow:hidden; text-overflow:ellipsis; color:var(--text-secondary); font-size:var(--text-xs); }
	header button { min-width:32px; min-height:32px; border:0; background:transparent; color:var(--text-secondary); cursor:pointer; }
	section { display:flex; flex-wrap:wrap; gap:var(--space-2); padding:var(--space-2) 0; border-top:1px solid var(--border-subtle); }
	h3 { flex-basis:100%; margin:0; color:var(--text-secondary); font-size:var(--text-xs); text-transform:uppercase; letter-spacing:.04em; }
	p { margin:var(--space-2) 0; color:var(--text-secondary); }
	.error { color:var(--text-danger); }
</style>
