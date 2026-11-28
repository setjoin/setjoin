<svelte:options runes={true} />

<!--
	/book/confirm — the PUBLIC email-verification + cancel landing (feature #6).
	?token=<verify token> completes the double opt-in (creates the calendar
	event + sends the iTIP invite server-side). ?cancel=<cancel token> cancels
	an already-confirmed booking. Standalone: no app shell, no session/JMAP
	fetch. The raw cancel token is only ever seen here (from the confirm
	response) or via a link the booker saved — nothing else on this surface
	exposes it (see internal/booking/public.go's handleConfirm).
-->

<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import { Card, Button } from '$lib/components/ui';
	import { t } from '$lib/i18n';
	import { confirmBooking, cancelBooking, BookingTokenInvalidError } from '$lib/api/publicBooking';

	type Status = 'confirming' | 'confirmed' | 'cancelling' | 'cancelled' | 'invalid';
	let status = $state<Status>('confirming');
	let cancelToken = $state('');

	onMount(async () => {
		const verifyToken = page.url.searchParams.get('token');
		const cancelParam = page.url.searchParams.get('cancel');

		if (cancelParam) {
			status = 'cancelling';
			try {
				await cancelBooking(cancelParam);
				status = 'cancelled';
			} catch (e) {
				status = e instanceof BookingTokenInvalidError ? 'invalid' : 'invalid';
			}
			return;
		}

		if (!verifyToken) {
			status = 'invalid';
			return;
		}
		try {
			const result = await confirmBooking(verifyToken);
			cancelToken = result.cancelToken ?? '';
			status = 'confirmed';
		} catch {
			status = 'invalid';
		}
	});

	async function cancelNow() {
		if (!cancelToken) return;
		status = 'cancelling';
		try {
			await cancelBooking(cancelToken);
			status = 'cancelled';
		} catch {
			status = 'invalid';
		}
	}
</script>

<svelte:head><title>{t('booking.public.pickSlot')} · setjoin</title></svelte:head>

<div class="sj-confirm-page">
	<div class="sj-confirm-inner">
		<Card>
			<div role="status" aria-live="polite">
				{#if status === 'confirming' || status === 'cancelling'}
					<p>{t('booking.public.confirming')}</p>
				{:else if status === 'confirmed'}
					<p class="sj-confirm-ok">{t('booking.public.confirmed')}</p>
					{#if cancelToken}
						<Button variant="ghost" size="sm" onclick={cancelNow}>{t('booking.public.cancelBooking')}</Button>
					{/if}
				{:else if status === 'cancelled'}
					<p>{t('booking.public.cancelled')}</p>
				{:else}
					<p class="sj-confirm-error">{t('booking.public.tokenInvalid')}</p>
				{/if}
			</div>
		</Card>
	</div>
</div>

<style>
	.sj-confirm-page {
		min-height: 100vh;
		display: flex;
		align-items: center;
		justify-content: center;
		background: var(--surface-page);
	}
	.sj-confirm-inner {
		max-width: 420px;
		width: 100%;
		padding: 16px;
	}
	.sj-confirm-ok {
		color: var(--text-primary);
		font-weight: 500;
	}
	.sj-confirm-error {
		color: var(--danger-fg);
	}
</style>
