<!-- Test-only harness: mounts authedBootstrap with an injectable loader so the
     composable's onMount/unmount lifecycle is exercisable from Vitest. -->
<svelte:options runes={true} />

<script lang="ts">
	import { untrack } from 'svelte';
	import { authedBootstrap, type AuthedBootstrapLoader, type AuthedBootstrapOptions } from './authed-bootstrap.svelte';

	interface Props {
		loader?: AuthedBootstrapLoader;
		/** Passed straight through as authedBootstrap's options. */
		options?: AuthedBootstrapOptions;
		/** Render marker the tests can wait for. */
		label?: string;
	}

	let { loader, options, label = 'harness' }: Props = $props();

	// ponytail: same prop-injection pattern as settings/security — the harness
	// deliberately snapshots the injected loader once (props never change here).
	untrack(() => {
		if (loader) authedBootstrap(loader, options);
	});
</script>

<p data-testid="harness-label">{label}</p>
