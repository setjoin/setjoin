<svelte:options runes={true} />

<script lang="ts">
	import IdentityModelConsole from '$lib/components/admin/identity/IdentityModelConsole.svelte';
</script>

<IdentityModelConsole initialSection="sources" sourceSetup={true} />
