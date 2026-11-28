<svelte:options runes={true} />

<script lang="ts">
  import type { Email } from '$lib/types/jmap';
  import ExternalSenderBanner from './ExternalSenderBanner.svelte';
  import { effectiveCaps } from '$lib/stores/session';

  interface Props {
    email: Email | null;
  }

  let { email = null }: Props = $props();

  let showExternal = $derived($effectiveCaps.externalLabels && email?.isExternal === true);
  let showNameSpoof = $derived(email?.isNameSpoof === true);
  let showFirstTime = $derived(email?.isFirstTime === true);
  let showAnyBanner = $derived(showExternal || showNameSpoof || showFirstTime);
</script>

{#if email && showAnyBanner}
  <ExternalSenderBanner
    isNameSpoof={showNameSpoof}
    senderDisplayName={email.senderDisplayName ?? undefined}
    isFirstTime={showFirstTime && !showExternal}
    fromAddr={email.from?.[0]?.email ?? undefined}
  />
  <!-- Future annotations (DLP hit, encrypted, signed, bulk mail) add new {#if} blocks here -->
{/if}
