<svelte:options runes={true} />
<script lang="ts">
	// The capability guard lives in the root layout's appForPath route guard
	// (src/routes/+layout.svelte) — the same mechanism mail/calendar/contacts/
	// tasks/drive/chat use — so a disabled 'meet' app bounces to
	// $firstEnabledApp before this page ever mounts.
	import MeetApp from '$lib/components/meet/MeetApp.svelte';
</script>
<MeetApp />
