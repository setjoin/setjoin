<svelte:options runes={true} />
<script lang="ts">
	// The capability guard lives in the root layout's appForPath route guard
	// (src/routes/+layout.svelte) — the same mechanism mail/calendar/contacts/
	// tasks use — so a disabled 'drive' app bounces to $firstEnabledApp before
	// this page ever mounts.
	import DriveApp from '$lib/components/drive/DriveApp.svelte';
</script>
<DriveApp />
