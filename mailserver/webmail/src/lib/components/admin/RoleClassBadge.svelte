<svelte:options runes={true} />
<script lang="ts">
	import { Tag } from '$lib/components/ui';
	import { sodClassBadge } from './sodClass';

	let { sodClass = null }: { sodClass?: string | null } = $props();
	const badge = $derived(sodClassBadge(sodClass));
</script>

<Tag label={badge.label} color={badge.color} size="sm" dot={true} />
