<svelte:options runes={true} />
<script lang="ts">
	import { Badge } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { t } from '$lib/i18n';
	import { enrollBadge } from './device-lockdown';

	let { state }: { state: string } = $props();
	const b = $derived(enrollBadge(state));
</script>

<!-- presentational: no tab stop; icon + label carry the meaning (never color alone) -->
<span class="enroll-badge" data-testid="enroll-badge" aria-hidden={false}>
	<Icon name={b.icon} size={16} strokeWidth={1.75} aria-hidden={true} />
	<Badge variant={b.variant} label={t(b.key)} />
</span>

<style>
	.enroll-badge {
		display: inline-flex;
		align-items: center;
		gap: 5px;
		/* status text never truncates per shared §3 */
		white-space: nowrap;
	}
</style>
