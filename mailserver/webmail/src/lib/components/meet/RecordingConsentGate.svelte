<svelte:options runes={true} />

<script lang="ts">
	// RecordingConsentGate — Meet B2 Task 10, spec §8.1/D5: the join
	// interstitial shared by the member PreJoin flow (MeetApp) and the guest
	// lobby's admitted-grant flicker-window belt (the guest join page).
	// "Non-dismissible" here means no third, skip-shaped affordance — only an
	// explicit Join / Don't join choice; the CALLER decides what each means
	// (connect the room vs. go back), this component only gates rendering.
	//
	// D-5: a consent gate the keyboard/screen-reader user never lands on is
	// not a consent gate — the moment `recordingActive` flips true, focus
	// moves to the interstitial's own heading (tabindex="-1", programmatic
	// focus target only, never in the tab order otherwise).
	import type { Snippet } from 'svelte';
	import { Card, Button } from '$lib/components/ui';
	import { t } from '$lib/i18n';

	let {
		recordingActive,
		onConsent,
		onDecline,
		children,
	}: {
		recordingActive: boolean;
		onConsent: () => void;
		onDecline: () => void;
		children: Snippet;
	} = $props();

	let headingEl = $state<HTMLElement | undefined>();

	$effect(() => {
		if (recordingActive) headingEl?.focus();
	});
</script>

{#if recordingActive}
	<div class="recording-consent-gate">
		<Card>
			<h2 bind:this={headingEl} tabindex="-1" class="recording-consent-gate__heading">
				{t('meet.recording.interstitialTitle')}
			</h2>
			<p>{t('meet.recording.interstitialBody')}</p>
			<div class="recording-consent-gate__actions">
				<Button variant="primary" onclick={onConsent}>{t('meet.recording.joinAnyway')}</Button>
				<Button variant="secondary" onclick={onDecline}>{t('meet.recording.dontJoin')}</Button>
			</div>
		</Card>
	</div>
{:else}
	{@render children()}
{/if}

<style>
	.recording-consent-gate {
		max-width: 480px;
		margin: var(--space-4) auto;
	}
	.recording-consent-gate__heading {
		margin: 0 0 var(--space-2);
		font-size: var(--text-lg);
		font-weight: 600;
		color: var(--text-primary);
		outline: none;
	}
	.recording-consent-gate__actions {
		display: flex;
		gap: var(--space-2);
		margin-top: var(--space-3);
	}
</style>
