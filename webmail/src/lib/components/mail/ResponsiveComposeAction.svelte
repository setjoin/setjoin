<svelte:options runes={true} />

<script lang="ts">
	import { Button, IconButton } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';

	let {
		onCompose,
		disabled = false,
		disabledReason = '',
	}: {
		onCompose: () => void;
		disabled?: boolean;
		disabledReason?: string;
	} = $props();
</script>

<span class="sj-inbox__compose-tablet">
	<Button
		data-tour="compose"
		aria-label={t('inbox.compose')}
		onclick={onCompose}
		{disabled}
		title={disabled ? disabledReason : undefined}
	>
		{#snippet icon()}<Icon name="Pencil" size={15} strokeWidth={1.75} />{/snippet}
		{t('inbox.compose')}
	</Button>
</span>

<span class="sj-inbox__compose-mobile">
	<IconButton
		data-tour="compose"
		label={t('inbox.compose')}
		onclick={onCompose}
		{disabled}
		tooltip={disabled ? disabledReason : undefined}
	>
		<Icon name="Pencil" size={17} strokeWidth={1.75} />
	</IconButton>
</span>

<style>
	.sj-inbox__compose-tablet,
	.sj-inbox__compose-mobile {
		display: none;
		flex: none;
	}

	@media (min-width: 768px) and (max-width: 1023px) {
		.sj-inbox__compose-tablet {
			display: inline-flex;
		}
	}

	@media (max-width: 767px) {
		.sj-inbox__compose-mobile {
			display: inline-flex;
		}
		.sj-inbox__compose-mobile :global(button) {
			width: 44px;
			height: 44px;
		}
	}
</style>
