<svelte:options runes={true} />

<script lang="ts">
	import { mirrorBridge } from '$lib/drive/mirrorBridge.svelte';
	import { Button } from '$lib/components/ui';
	import Icon, { type IconName } from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';

	let { onclick }: { onclick: () => void } = $props();

	type SyncStateKey = 'idle' | 'syncing' | 'paused' | 'error' | 'vaultLocked' | 'authExpired' | 'off';

	const ICONS: Record<SyncStateKey, IconName> = {
		idle: 'CheckCircle2',
		syncing: 'RefreshCw',
		paused: 'Pause',
		error: 'AlertTriangle',
		vaultLocked: 'Lock',
		authExpired: 'AlertTriangle',
		off: 'Cloud',
	};

	let overallState = $derived.by((): SyncStateKey => {
		const s = mirrorBridge.status;
		if (s.perSpace.length === 0) return 'off';
		if (s.paused) return 'paused';
		if (s.perSpace.some((p) => p.state === 'error')) return 'error';
		if (s.perSpace.some((p) => p.state === 'vault-locked')) return 'vaultLocked';
		if (s.perSpace.some((p) => p.state === 'auth-expired')) return 'authExpired';
		if (s.perSpace.some((p) => p.state === 'syncing')) return 'syncing';
		return 'idle';
	});

	$effect(() => {
		mirrorBridge.startPolling();
		return () => mirrorBridge.stopPolling();
	});
</script>

{#if mirrorBridge.available}
	<Button variant="ghost" size="sm" {onclick} aria-label={t('drive.sync.pill.label')}>
		<Icon
			name={ICONS[overallState]}
			size={14}
			class={overallState === 'syncing' ? 'drive-sync-pill__spin' : ''}
		/>
		<span aria-live="polite">{t(`drive.sync.status.${overallState}`)}</span>
	</Button>
{/if}

<style>
	:global(.drive-sync-pill__spin) {
		animation: drive-sync-spin 1s linear infinite;
	}

	@keyframes drive-sync-spin {
		from {
			transform: rotate(0deg);
		}
		to {
			transform: rotate(360deg);
		}
	}

	@media (prefers-reduced-motion: reduce) {
		:global(.drive-sync-pill__spin) {
			animation: none;
		}
	}
</style>
