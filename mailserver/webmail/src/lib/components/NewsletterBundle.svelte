<svelte:options runes={true} />
<script lang="ts">
	import { Avatar } from '$lib/components/ui';
	import Icon from './Icon.svelte';

	interface NewsletterSender {
		id: string;
		fromName: string;
		fromAddr: string;
		subject: string;
		count: number;
	}

	interface Props {
		senders: NewsletterSender[];
		expanded?: boolean;
		onselect?: (detail: { messageId: string }) => void;
		onunsubscribe?: (detail: { senderAddr: string }) => void;
		onexpand?: () => void;
	}

	let {
		senders = [],
		expanded = false,
		onselect,
		onunsubscribe,
		onexpand,
	}: Props = $props();

	// Local override: null means "follow the `expanded` prop"; a boolean means the
	// user has toggled locally. This avoids the $effect prop-sync anti-pattern
	// (no one-tick lag, no clobbering of local state when the prop re-renders).
	let localOpen = $state<boolean | null>(null);
	const isExpanded = $derived(localOpen ?? expanded);

	const totalCount = $derived(senders.reduce((sum, s) => sum + s.count, 0));

	function toggleExpand() {
		localOpen = !isExpanded;
		if (localOpen) onexpand?.();
	}

	function onKeydown(e: KeyboardEvent) {
		if (e.key === 'Enter' || e.key === ' ') {
			e.preventDefault();
			toggleExpand();
		}
	}
</script>

<div class="newsletter-bundle">
	<button
		class="bundle-header"
		onclick={toggleExpand}
		onkeydown={onKeydown}
		aria-expanded={isExpanded}
	>
		<div class="bundle-icon">
			<Icon name="Newspaper" size={20} />
		</div>
		<div class="bundle-info">
			<div class="bundle-title">Newsletters</div>
			<div class="bundle-meta">
				{senders.length} sender{senders.length !== 1 ? 's' : ''} &middot; {totalCount} message{totalCount !== 1 ? 's' : ''}
			</div>
		</div>
		<div class="bundle-avatars">
			{#each senders.slice(0, 3) as sender}
				<Avatar name={sender.fromName} size="sm" />
			{/each}
			{#if senders.length > 3}
				<span class="sender-av-overflow">+{senders.length - 3}</span>
			{/if}
		</div>
		<span class="expand-icon"><Icon name={isExpanded ? 'ChevronUp' : 'ChevronDown'} size={16} /></span>
	</button>

	{#if isExpanded}
		<div class="bundle-body">
			{#each senders as sender (sender.id)}
				<div class="sender-row">
					<button
						class="sender-main"
						onclick={() => onselect?.({ messageId: sender.id })}
					>
						<span class="sender-name">{sender.fromName}</span>
						<span class="sender-subject">{sender.subject}</span>
						<span class="sender-count">{sender.count}</span>
					</button>
					<button
						class="unsub-btn"
						title="Unsubscribe from {sender.fromName}"
						onclick={() => onunsubscribe?.({ senderAddr: sender.fromAddr })}
					>
						<Icon name="MailMinus" size={14} />
						Unsubscribe
					</button>
				</div>
			{/each}
		</div>
	{/if}
</div>

<style>
	.newsletter-bundle {
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		background: var(--surface-card);
		overflow: hidden;
		margin: 8px 0;
	}

	.bundle-header {
		display: flex;
		align-items: center;
		gap: 12px;
		width: 100%;
		padding: 12px 16px;
		border: none;
		background: none;
		cursor: pointer;
		font-family: inherit;
		text-align: left;
		transition: background var(--duration-base);
		color: var(--text-primary);
	}
	.bundle-header:hover {
		background: var(--surface-sunken);
	}
	.bundle-header:focus-visible {
		box-shadow: var(--focus-ring);
		outline: none;
	}

	.bundle-icon {
		width: 36px;
		height: 36px;
		border-radius: var(--radius-sm);
		background: var(--tag-amber-bg);
		color: var(--tag-amber-fg);
		display: flex;
		align-items: center;
		justify-content: center;
		flex-shrink: 0;
	}

	.bundle-info {
		flex: 1;
		min-width: 0;
	}
	.bundle-title {
		font-weight: 600;
		font-size: var(--text-sm);
	}
	.bundle-meta {
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		margin-top: 2px;
	}

	.bundle-avatars {
		display: flex;
		gap: 0;
		flex-shrink: 0;
	}
	.bundle-avatars :global(.avatar) {
		width: 28px;
		height: 28px;
		border: 2px solid var(--surface-card);
		margin-left: -6px;
	}
	.bundle-avatars :global(.avatar):first-child {
		margin-left: 0;
	}
	.sender-av-overflow {
		width: 28px;
		height: 28px;
		border-radius: 50%;
		background: var(--surface-sunken);
		color: var(--text-tertiary);
		font-size: var(--text-2xs);
		font-weight: 600;
		display: flex;
		align-items: center;
		justify-content: center;
		border: 2px solid var(--surface-card);
		margin-left: -6px;
	}

	.bundle-body {
		border-top: 1px solid var(--border-subtle);
	}

	.sender-row {
		display: flex;
		align-items: center;
		padding: 8px 16px;
		gap: 8px;
		border-bottom: 1px solid var(--border-subtle);
		transition: background var(--duration-base);
	}
	.sender-row:last-child {
		border-bottom: none;
	}
	.sender-row:hover {
		background: var(--surface-sunken);
	}

	.sender-main {
		display: flex;
		align-items: center;
		gap: 12px;
		flex: 1;
		min-width: 0;
		border: none;
		background: none;
		cursor: pointer;
		font-family: inherit;
		text-align: left;
		padding: 4px 0;
		color: var(--text-primary);
		transition: opacity var(--duration-base);
	}
	.sender-main:hover {
		opacity: 0.8;
	}
	.sender-main:focus-visible {
		box-shadow: var(--focus-ring);
		outline: none;
		border-radius: var(--radius-xs);
	}

	.sender-name {
		font-weight: 500;
		font-size: var(--text-sm);
		white-space: nowrap;
	}
	.sender-subject {
		flex: 1;
		font-size: var(--text-xs);
		color: var(--text-tertiary);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}
	.sender-count {
		font-size: var(--text-2xs);
		color: var(--text-secondary);
		background: var(--surface-sunken);
		padding: 1px 8px;
		border-radius: var(--radius-full);
		font-weight: 600;
		font-family: var(--font-mono);
	}

	.unsub-btn {
		display: flex;
		align-items: center;
		gap: 4px;
		padding: 4px 10px;
		border-radius: var(--radius-sm);
		border: 1px solid var(--border-default);
		background: var(--surface-card);
		color: var(--text-tertiary);
		font-size: var(--text-2xs);
		font-weight: 500;
		cursor: pointer;
		white-space: nowrap;
		font-family: inherit;
		transition: all var(--duration-base);
	}
	.unsub-btn:hover {
		background: var(--danger-bg);
		color: var(--danger-fg);
		border-color: var(--danger-solid);
	}
	.unsub-btn:focus-visible {
		box-shadow: var(--focus-ring);
		outline: none;
	}

	.expand-icon {
		flex-shrink: 0;
		color: var(--text-tertiary);
	}
</style>
