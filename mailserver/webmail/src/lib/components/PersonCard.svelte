<svelte:options runes={true} />
<script lang="ts">
	import type { Snippet } from 'svelte';
	import { Avatar, Button } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { galSearch } from '$lib/jmap/client';
	import { composeStore } from '$lib/stores/compose';
	import { t } from '$lib/i18n';
	import type { ContactCard } from '$lib/types/jmap';

	/**
	 * Inline people-card popover (#1): click a sender/recipient name anywhere in
	 * mail to pop a mini profile (photo, title, department) with Email + View
	 * profile quick actions — reusing the existing GAL search rather than
	 * navigating to the full directory page.
	 *
	 * Self-contained: its own inline trigger + click-outside close, and a
	 * position:fixed popover anchored to the trigger so it escapes the message
	 * list's overflow clipping. Manager is a nice-to-have, fetched lazily only
	 * once the card is open (org-chart REST), never on hover.
	 */
	interface Props {
		email: string;
		name?: string;
		/** Optional custom trigger content (e.g. an Avatar). Defaults to the name text. */
		trigger?: Snippet;
	}
	let { email, name = '', trigger }: Props = $props();

	let open = $state(false);
	let looked = $state(false);
	let loading = $state(false);
	let card = $state<ContactCard | null>(null);
	let managerName = $state('');
	let triggerEl = $state<HTMLElement | null>(null);
	let popoverEl = $state<HTMLElement | null>(null);
	let pos = $state<{ top: number; left: number }>({ top: 0, left: 0 });

	const lower = $derived(email.toLowerCase());
	const displayName = $derived(card?.displayName || name || email);
	const jobTitle = $derived(card?.jobTitle ?? '');
	const department = $derived(card?.department ?? '');
	const avatarSrc = $derived(
		card?.avatar
			? typeof card.avatar === 'string'
				? card.avatar
				: card.avatar.blobId
					? `/api/blobs/${card.avatar.blobId}`
					: ''
			: '',
	);

	function matchesEmail(c: ContactCard): boolean {
		if (c.email?.toLowerCase() === lower) return true;
		if ((c.emails ?? []).some((e) => e.address?.toLowerCase() === lower)) return true;
		if ((c.addresses ?? []).some((a) => a.email?.toLowerCase() === lower)) return true;
		return false;
	}

	// GAL exact-address lookup (senders are often external → no match, which the
	// "not in directory" state below handles). Only runs once per card.
	async function lookup() {
		if (looked || !email) return;
		looked = true;
		loading = true;
		try {
			const gal = await galSearch(email);
			card = gal.find(matchesEmail) ?? null;
			if (card?.id) loadManager(card.id);
		} catch {
			// Degrade to the name/email we already have — the card is still useful.
		} finally {
			loading = false;
		}
	}

	// Manager chain (nice-to-have): org_chart.sql orders managers DESC by depth,
	// so the LAST entry is the direct manager. Silent-degrade on any failure.
	async function loadManager(userId: string) {
		try {
			const res = await fetch(`/auth/me/org-chart?userId=${encodeURIComponent(userId)}`, {
				credentials: 'include',
			});
			if (!res.ok) return;
			const data = await res.json();
			const managers = Array.isArray(data.managers) ? data.managers : [];
			managerName = managers.length ? (managers[managers.length - 1].displayName ?? '') : '';
		} catch {
			/* manager is optional chrome */
		}
	}

	function toggle(e: MouseEvent) {
		e.stopPropagation();
		open = !open;
		if (open) {
			const r = triggerEl?.getBoundingClientRect();
			if (r) pos = { top: r.bottom + 6, left: r.left };
			lookup();
		}
	}

	function emailAction() {
		open = false;
		composeStore.open({ to: email });
	}

	// Click-outside: close when a click lands outside both the trigger and popover.
	function onWindowClick(e: MouseEvent) {
		if (!open) return;
		const target = e.target as Node;
		if (popoverEl?.contains(target) || triggerEl?.contains(target)) return;
		open = false;
	}
</script>

<svelte:window onclick={onWindowClick} />

<span class="sj-person-card">
	<button
		bind:this={triggerEl}
		type="button"
		class="sj-person-card__trigger"
		onclick={toggle}
		aria-haspopup="dialog"
		aria-expanded={open}
	>
		{#if trigger}{@render trigger()}{:else}{name || email}{/if}
	</button>

	{#if open}
		<div
			bind:this={popoverEl}
			class="sj-person-card__popover"
			role="dialog"
			aria-label={displayName}
			style="top: {pos.top}px; left: {pos.left}px;"
		>
			<div class="sj-person-card__head">
				<Avatar name={displayName} src={avatarSrc} size="lg" />
				<div class="sj-person-card__id">
					<div class="sj-person-card__name">{displayName}</div>
					<div class="sj-person-card__email">{email}</div>
				</div>
			</div>

			{#if loading}
				<div class="sj-person-card__meta">{t('common.loading')}</div>
			{:else if card}
				{#if jobTitle || department}
					<div class="sj-person-card__meta">
						{jobTitle}{#if jobTitle && department} · {/if}{department}
					</div>
				{/if}
				{#if managerName}
					<div class="sj-person-card__meta sj-person-card__manager">
						<Icon name="Users" size={12} strokeWidth={1.75} />
						{managerName}
					</div>
				{/if}
			{:else}
				<div class="sj-person-card__meta">{t('contact_card.not_in_directory')}</div>
			{/if}

			<div class="sj-person-card__actions">
				<Button size="sm" variant="secondary" onclick={emailAction}>
					{t('contact_card.email')}
				</Button>
				{#if card}
					<a class="sj-person-card__link" href="/directory">{t('contact_card.view_profile')}</a>
				{/if}
			</div>
		</div>
	{/if}
</span>

<style>
	.sj-person-card {
		display: inline;
	}

	.sj-person-card__trigger {
		display: inline;
		border: none;
		background: none;
		padding: 0;
		margin: 0;
		font: inherit;
		color: inherit;
		cursor: pointer;
		text-align: inherit;
	}

	.sj-person-card__trigger:hover {
		text-decoration: underline;
	}

	.sj-person-card__trigger:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
		border-radius: var(--radius-xs);
	}

	.sj-person-card__popover {
		position: fixed;
		z-index: 200;
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

	.sj-person-card__head {
		display: flex;
		align-items: center;
		gap: 10px;
	}

	.sj-person-card__id {
		min-width: 0;
	}

	.sj-person-card__name {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-primary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.sj-person-card__email {
		font-size: var(--text-xs);
		color: var(--text-caption);
		font-family: var(--font-mono);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.sj-person-card__meta {
		font-size: var(--text-xs);
		color: var(--text-secondary);
		display: flex;
		align-items: center;
		gap: 4px;
	}

	.sj-person-card__actions {
		display: flex;
		align-items: center;
		gap: 8px;
	}

	.sj-person-card__link {
		font-size: var(--text-xs);
		color: var(--accent);
		text-decoration: none;
	}

	.sj-person-card__link:hover {
		text-decoration: underline;
	}
</style>
