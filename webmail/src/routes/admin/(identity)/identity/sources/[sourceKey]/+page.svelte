<svelte:options runes={true} />

<script lang="ts">
	import { page } from '$app/state';
	import IdentityModelConsole from '$lib/components/admin/identity/IdentityModelConsole.svelte';
</script>

<IdentityModelConsole initialSection="sources" selectedId={page.params.sourceKey} />
