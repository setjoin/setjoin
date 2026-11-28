<svelte:options runes={true} />

<script lang="ts">
	// MessageBodyPoll — the `poll` msg_type genre (A3 QoL Task 9's seam, Task
	// 15's render), split out of MessageRow.svelte (whole-pipeline review
	// arch #9). The poll's anchor message IS the poll (posted through
	// chat_message_send) — its authorId is the creator, so `isMine` already
	// tells us if the viewer created it; no createdBy field exists on
	// chat_poll_results to duplicate that check.
	import { chatStore, chatErrorMessage } from '$lib/chat/store.svelte';
	import type { StoreMessage } from '$lib/chat/store.svelte';
	import * as chatApi from '$lib/chat/api';
	import type { RosterMember } from '$lib/chat/api';
	import { showToast } from '$lib/components/ui';
	import { t } from '$lib/i18n';

	let {
		message,
		roster = [],
		isMine,
		canModerate
	}: {
		message: StoreMessage;
		/** A3 QoL Task 15 — poll voter-name resolution only. */
		roster?: RosterMember[];
		isMine: boolean;
		canModerate: boolean;
	} = $props();

	let pollId = $derived((message.payload as { pollId?: number } | null | undefined)?.pollId ?? null);
	let pollResults = $derived(pollId != null ? chatStore.pollResultsByPollId[pollId] : undefined);
	let canClosePoll = $derived(isMine || canModerate);

	$effect(() => {
		const pid = pollId;
		if (pid == null || chatStore.pollResultsByPollId[pid]) return;
		void chatStore.loadPollResults(pid);
	});

	function voterName(userId: number): string {
		return roster.find((m) => m.userId === userId)?.displayName ?? String(userId);
	}
	function pollPct(count: number): number {
		if (!pollResults) return 0;
		const total = pollResults.options.reduce((sum, o) => sum + o.count, 0);
		return total > 0 ? Math.round((count / total) * 100) : 0;
	}
	async function vote(optionId: number): Promise<void> {
		if (pollId == null || pollResults?.closed) return;
		try {
			await chatApi.votePoll(pollId, optionId);
			await chatStore.loadPollResults(pollId);
		} catch (err) {
			// [UX #7/#14, pipeline review] was silent — the checkbox/radio simply
			// didn't visually flip (never optimistically mutated) with no other signal.
			showToast(chatErrorMessage(err), { variant: 'danger' });
		}
	}
	async function doClosePoll(): Promise<void> {
		if (pollId == null) return;
		try {
			await chatApi.closePoll(pollId);
			await chatStore.loadPollResults(pollId);
		} catch (err) {
			// [UX #7/#14, pipeline review] closePoll() had no catch at all — a
			// rejection propagated as an unhandled rejection out of this bare
			// onclick handler.
			showToast(chatErrorMessage(err), { variant: 'danger' });
		}
	}
</script>

<!-- A3 QoL Task 9/15: pollId is stamped into the SAME transaction as the
     send, so a poll message is never observed with a null payload —
     `pollResults` is undefined only until the $effect above's initial
     fetch resolves. -->
<fieldset class="mrow__poll" role={pollResults?.multi ? undefined : 'radiogroup'}>
	<legend class="mrow__poll-question">{pollResults?.question ?? message.body}</legend>
	{#if pollResults}
		{#each pollResults.options as opt (opt.optionId)}
			<label class="mrow__poll-option" class:mrow__poll-option--mine={opt.voters.includes(chatStore.selfUserId ?? -1)}>
				<input
					type={pollResults.multi ? 'checkbox' : 'radio'}
					name={`poll-${pollId}`}
					aria-label={opt.label}
					checked={opt.voters.includes(chatStore.selfUserId ?? -1)}
					disabled={pollResults.closed}
					onchange={() => vote(opt.optionId)}
				/>
				<span class="mrow__poll-label">{opt.label}</span>
				<span class="mrow__poll-bar"><span class="mrow__poll-bar-fill" style={`width:${pollPct(opt.count)}%`}></span></span>
				<span class="mrow__poll-count">{opt.count === 1 ? t('chat.poll.voteCountOne') : t('chat.poll.voteCount', { n: String(opt.count) })}</span>
				<!-- fixed row footprint (plan): always rendered (never conditional
				     on voters.length) and clipped to one line via CSS, so a
				     growing/shrinking voter list never changes row height. -->
				<span class="mrow__poll-voters">{opt.voters.map(voterName).join(', ')}</span>
			</label>
		{/each}
		{#if pollResults.closed}
			<p class="mrow__poll-final">{t('chat.poll.finalResults')}</p>
		{:else if canClosePoll}
			<button type="button" class="mrow__btn" onclick={doClosePoll}>{t('chat.poll.close')}</button>
		{/if}
	{/if}
</fieldset>

<style>
	.mrow__poll {
		flex-basis: 100%;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		margin: 0;
		padding: var(--space-2);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
	}
	.mrow__poll-question {
		padding: 0;
		font-weight: 600;
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	.mrow__poll-option {
		display: grid;
		grid-template-columns: auto 1fr auto;
		align-items: center;
		gap: var(--space-2);
		min-height: 32px;
		padding: 2px 0;
	}
	.mrow__poll-option--mine .mrow__poll-label {
		font-weight: 600;
	}
	.mrow__poll-label {
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	.mrow__poll-bar {
		grid-column: 2;
		display: block;
		height: 6px;
		background: var(--surface-sunken);
		border-radius: var(--radius-full);
		overflow: hidden;
	}
	.mrow__poll-bar-fill {
		display: block;
		height: 100%;
		background: var(--accent);
	}
	.mrow__poll-count {
		font-size: var(--text-2xs);
		color: var(--text-caption);
		white-space: nowrap;
	}
	.mrow__poll-voters {
		grid-column: 2 / span 2;
		/* Fixed row footprint (plan): a single clipped line so a growing/
		   shrinking voter list never changes this option's height. */
		max-height: 1.2em;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		font-size: var(--text-2xs);
		color: var(--text-caption);
	}
	.mrow__poll-final {
		margin: 0;
		font-size: var(--text-2xs);
		color: var(--text-caption);
		font-style: italic;
	}
	.mrow__btn {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		min-height: 44px;
		justify-content: center;
		border: 1px solid var(--border-default);
		background: transparent;
		border-radius: var(--radius-sm);
		color: var(--text-secondary);
		cursor: pointer;
		font-size: var(--text-xs);
		padding: 0 var(--space-2);
	}
	.mrow__btn:hover {
		background: var(--surface-hover);
	}
</style>
