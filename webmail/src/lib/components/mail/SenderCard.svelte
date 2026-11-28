<svelte:options runes={true} />
<script lang="ts">
	import { Avatar, Button } from '$lib/components/ui';
	import { contactQuery, contactGet, galSearch } from '$lib/jmap/client';
	import { createContact } from '$lib/stores/contacts';
	import { vipSenders } from '$lib/stores/vipSenders.svelte';
	import { t } from '$lib/i18n';
	import { Star } from 'lucide-svelte';
	import type { ContactCard } from '$lib/types/jmap';

	/**
	 * The sender people-pane: an avatar trigger that opens a lightweight popover
	 * with the sender's contact/GAL details and an add-to-contacts action. Read-only
	 * beyond the add. Its own trigger button (NOT nested in the card's collapse
	 * toggle — that would be invalid HTML); click-outside closes via svelte:window.
	 */
	interface Props {
		name: string;
		email: string;
	}
	let { name, email }: Props = $props();

	let open = $state(false);
	let looked = $state(false);
	let loading = $state(false);
	let contact = $state<ContactCard | null>(null); // exact personal-contact match
	let galCard = $state<ContactCard | null>(null); // GAL fallback
	let added = $state(false);
	let popoverEl = $state<HTMLElement | null>(null);
	let triggerEl = $state<HTMLElement | null>(null);

	const lower = $derived(email.toLowerCase());

	function matchesEmail(c: ContactCard): boolean {
		if (c.email?.toLowerCase() === lower) return true;
		if ((c.emails ?? []).some((e) => e.address?.toLowerCase() === lower)) return true;
		if ((c.addresses ?? []).some((a) => a.email?.toLowerCase() === lower)) return true;
		return false;
	}

	// contactQuery is a substring ILIKE — exact-match the lowercased email
	// client-side so a partial (e.g. "bob@" matching "bobby@") never dedups wrongly.
	async function lookup() {
		if (looked || !email) return;
		looked = true;
		loading = true;
		try {
			const q = await contactQuery({ text: email }, null, 0, 20);
			if (q.ids.length) {
				const list = await contactGet(q.ids);
				contact = list.find(matchesEmail) ?? null;
			}
			if (!contact) {
				const gal = await galSearch(email);
				galCard = gal.find(matchesEmail) ?? gal[0] ?? null;
			}
		} catch {
			// Degrade to the name/email we already have — the card is still useful.
		} finally {
			loading = false;
		}
	}

	function toggle() {
		open = !open;
		if (open) {
			lookup();
			if (!vipSenders.loaded) vipSenders.load();
		}
	}

	const isVip = $derived(vipSenders.isVip(email));

	async function toggleVip() {
		try {
			await vipSenders.set(email, !isVip);
		} catch {
			// Best-effort — the store already rolled back optimistic state.
		}
	}

	// Click-outside: close when a click lands outside both the trigger and popover.
	// Ref containment (not stopPropagation) keeps the popover a plain, static div.
	function onWindowClick(e: MouseEvent) {
		if (!open) return;
		const target = e.target as Node;
		if (popoverEl?.contains(target) || triggerEl?.contains(target)) return;
		open = false;
	}

	const card = $derived(contact ?? galCard);
	const displayName = $derived(card?.displayName || name || email);
	const company = $derived(card?.company ?? '');
	const jobTitle = $derived(card?.jobTitle ?? '');
	const isPersonal = $derived(!!contact || added);

	async function addToContacts() {
		added = true; // optimistic — hide the button immediately
		try {
			await createContact({ displayName: name || email, emails: [{ type: 'other', address: email }] });
		} catch {
			added = false;
		}
	}
</script>

<svelte:window onclick={onWindowClick} />

<span class="sj-sender-card">
	<button
		bind:this={triggerEl}
		type="button"
		class="sj-sender-card__trigger"
		onclick={toggle}
		aria-haspopup="dialog"
		aria-expanded={open}
		aria-label={t('inbox.sender_details')}
	>
		<Avatar name={name} size="md" />
	</button>

	{#if open}
		<div
			bind:this={popoverEl}
			class="sj-sender-card__popover"
			role="dialog"
			aria-label={t('inbox.sender_details')}
		>
			<div class="sj-sender-card__head">
				<!-- ponytail: no photo src here — the resolved `contact` has no avatar/blobId field yet; wiring the sender→contact photo is a separate, larger change (needs the resolve path to carry avatar). -->
				<Avatar name={displayName} size="lg" />
				<div class="sj-sender-card__id">
					<div class="sj-sender-card__name">{displayName}</div>
					<div class="sj-sender-card__email">{email}</div>
				</div>
				<button
					type="button"
					class="sj-sender-card__vip"
					class:sj-sender-card__vip--on={isVip}
					onclick={toggleVip}
					aria-pressed={isVip}
					aria-label={isVip ? t('inbox.unmark_vip') : t('inbox.mark_vip')}
					title={isVip ? t('inbox.unmark_vip') : t('inbox.mark_vip')}
				>
					<Star size={16} fill={isVip ? 'currentColor' : 'none'} />
				</button>
			</div>
			{#if company || jobTitle}
				<div class="sj-sender-card__meta">
					{jobTitle}{#if jobTitle && company} · {/if}{company}
				</div>
			{/if}
			{#if !isPersonal && !loading}
				<Button size="sm" variant="secondary" onclick={addToContacts}>
					{t('inbox.add_to_contacts')}
				</Button>
			{/if}
		</div>
	{/if}
</span>

<style>
	.sj-sender-card {
		position: relative;
		display: inline-flex;
		flex: none;
	}

	.sj-sender-card__trigger {
		display: inline-flex;
		border: none;
		background: none;
		padding: 0;
		cursor: pointer;
		border-radius: var(--radius-full);
	}

	.sj-sender-card__trigger:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	.sj-sender-card__popover {
		position: absolute;
		top: 100%;
		left: 0;
		z-index: 50;
		margin-top: 6px;
		width: 260px;
		padding: 14px;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		background: var(--surface-card);
		box-shadow: var(--shadow-md);
		display: flex;
		flex-direction: column;
		gap: 10px;
	}

	.sj-sender-card__head {
		display: flex;
		align-items: center;
		gap: 10px;
	}

	.sj-sender-card__id {
		min-width: 0;
	}

	.sj-sender-card__name {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-primary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.sj-sender-card__email {
		font-size: var(--text-xs);
		color: var(--text-caption);
		font-family: var(--font-mono);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.sj-sender-card__meta {
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}

	.sj-sender-card__vip {
		flex: none;
		display: inline-flex;
		align-items: center;
		justify-content: center;
		border: none;
		background: none;
		padding: 4px;
		cursor: pointer;
		border-radius: var(--radius-sm);
		color: var(--text-caption);
		align-self: flex-start;
	}

	.sj-sender-card__vip:hover {
		background: var(--surface-hover);
		color: var(--tag-amber-fg);
	}

	.sj-sender-card__vip--on {
		color: var(--tag-amber-fg);
	}

	.sj-sender-card__vip:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}
</style>
