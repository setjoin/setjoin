<!-- mailserver/webmail/src/lib/components/mail/MailSidebar.svelte -->
<svelte:options runes={true} />

<script lang="ts" module>
	/** The fixed inbox views — kit canonical list (mail-kit-reference §3) + Archive (A2). */
	export type ViewId = 'inbox' | 'starred' | 'snoozed' | 'scheduled' | 'drafts' | 'sent' | 'archive' | 'all' | 'trash';

	export const VIEWS: { id: ViewId; label: string; icon: string }[] = [
		{ id: 'inbox', label: 'Inbox', icon: 'Inbox' },
		{ id: 'starred', label: 'Starred', icon: 'Star' },
		{ id: 'snoozed', label: 'Snoozed', icon: 'Clock' },
		{ id: 'scheduled', label: 'Scheduled', icon: 'CalendarClock' },
		{ id: 'drafts', label: 'Drafts', icon: 'FileText' },
		{ id: 'sent', label: 'Sent', icon: 'Send' },
		{ id: 'archive', label: 'Archive', icon: 'Archive' },
		{ id: 'all', label: 'All Mail', icon: 'Mail' },
		{ id: 'trash', label: 'Trash', icon: 'Trash2' },
	];
</script>

<script lang="ts">
	import type { ComponentProps } from 'svelte';
	import { Button, SidebarItem, IconButton, Input, TAG_COLORS } from '$lib/components/ui';
	import Icon from '$lib/components/Icon.svelte';
	import { userTags, buildTagTree } from '$lib/stores/tagHelpers';
	import { t } from '$lib/i18n';
	import type { Mailbox, SavedSearch } from '$lib/types/jmap';
	import type { DelegatedAccount } from '$lib/jmap/client';

	type Hue = (typeof TAG_COLORS)[number];
	// VIEWS.icon is a loose `string` (module-scope const, no Icon.svelte dependency);
	// narrow it here at the one render call site instead of tightening the shared export.
	type IconName = ComponentProps<typeof Icon>['name'];

	interface Props {
		/** Currently selected view id. */
		view: ViewId;
		/** Currently selected tag filter (tag mailbox id), or null. */
		tagFilter: string | null;
		/** All mailboxes (system + user tags). */
		mailboxes: Mailbox[];
		/** Pre-computed counts: unread for Inbox, total for Snoozed, per-tag counts. */
		counts: { inboxUnread: number; snoozedTotal: number; tagCounts: Record<string, number> };
		/** New compose message intent. */
		onCompose: () => void;
		/** View selection intent. */
		onSelectView: (view: ViewId) => void;
		/** Tag filter selection intent. */
		onSelectTag: (tagId: string) => void;
		/** Tag creation intent (from inline TAGS input) — name + chosen hue. */
		onNewTag: (name: string, color: Hue) => void;
		/** Rename/recolor a user tag (Mailbox/set update). */
		onUpdateTag?: (id: string, patch: { name?: string; color?: string }) => void;
		/** Delete a user tag (Mailbox/set destroy). */
		onDeleteTag?: (id: string) => void;
		/** User-defined saved-search folders. */
		savedSearches?: SavedSearch[];
		/** Re-run a saved search intent. */
		onSelectSaved?: (s: SavedSearch) => void;
		/** Delete a saved search intent. */
		onDeleteSaved?: (id: string) => void;
		/** #13 shared-mailbox use-surface: every MAIL-delegated mailbox (session
		 *  accounts other than the caller's own). Renders the SHARED MAILBOXES
		 *  section only when non-empty. */
		sharedMailboxes?: DelegatedAccount[];
		/** Open a shared mailbox's workspace (/inbox?mbx=<id>) intent. */
		onSelectShared?: (id: string) => void;
		/** True while THIS sidebar instance is rendering a shared mailbox's own
		 *  workspace — collapses to the 4 shared-context views (Inbox/Drafts/
		 *  Sent/Trash) and hides Tags/Saved searches/Snoozed/Scheduled (personal
		 *  features, per the #13 design pin). */
		sharedContext?: boolean;
		/** The currently-open shared mailbox's id (highlights its row) + display
		 *  name/permission-level for the sidebar HEADER block (one of the three
		 *  redundant context signals — see also the page's persistent info strip
		 *  and the compose From Select). */
		activeSharedId?: string | null;
		sharedName?: string;
		sharedPermissionLabel?: string;
		/** Back-to-my-mail (X) intent — clears the shared context. */
		onBackToMyMail?: () => void;
		/** #13 DANGER STATE: read-only shared-mailbox grant — the global Compose
		 *  button (not tied to any one message) is part of the disabled compose/
		 *  reply/forward triad too (see ReadingPane/MessageCard for the
		 *  per-message reply/forward gating). */
		composeDisabled?: boolean;
		composeDisabledReason?: string;
	}

	let {
		view,
		tagFilter = null,
		mailboxes = [],
		counts = { inboxUnread: 0, snoozedTotal: 0, tagCounts: {} },
		onCompose,
		onSelectView,
		onSelectTag,
		onNewTag,
		onUpdateTag = () => {},
		onDeleteTag = () => {},
		savedSearches = [],
		onSelectSaved = () => {},
		onDeleteSaved = () => {},
		sharedMailboxes = [],
		onSelectShared = () => {},
		sharedContext = false,
		composeDisabled = false,
		composeDisabledReason = '',
		activeSharedId = null,
		sharedName = '',
		sharedPermissionLabel = '',
		onBackToMyMail = () => {},
	}: Props = $props();

	/** The 4 views a shared-mailbox workspace exposes (#13 design pin). */
	const SHARED_VIEW_IDS: ViewId[] = ['inbox', 'drafts', 'sent', 'trash'];
	let visibleViews = $derived(
		sharedContext ? VIEWS.filter((v) => SHARED_VIEW_IDS.includes(v.id)) : VIEWS,
	);

	/** Map a Mailbox.color to a valid TagHue (sidebar dot), defaulting to blue. */
	function safeTagHue(color?: string): Hue {
		if (color && (TAG_COLORS as ReadonlyArray<string>).includes(color)) {
			return color as Hue;
		}
		return 'blue';
	}

	/** Count rule (mail-kit §3): Inbox=unread, Snoozed=total, others=none. */
	function viewCount(id: ViewId): number | null {
		if (id === 'inbox') return counts.inboxUnread;
		if (id === 'snoozed') return counts.snoozedTotal;
		return null;
	}

	/** Inline new-tag input visibility + value + chosen hue. */
	let showNewTag = $state(false);
	let newTagName = $state('');
	let newTagColor = $state<Hue>('blue');

	function submitNewTag() {
		if (!newTagName.trim()) return;
		onNewTag(newTagName.trim(), newTagColor);
		newTagName = '';
		newTagColor = 'blue';
		showNewTag = false;
	}

	function handleNewTagKeydown(e: KeyboardEvent) {
		if (e.key === 'Enter') {
			submitNewTag();
		} else if (e.key === 'Escape') {
			newTagName = '';
			showNewTag = false;
		}
	}

	/** Inline manage (rename/recolor/delete) state for a single user tag. */
	let editingTagId = $state<string | null>(null);
	let editName = $state('');
	let editColor = $state<Hue>('blue');

	function startEdit(tag: Mailbox) {
		editingTagId = tag.id;
		editName = tag.name;
		editColor = safeTagHue(tag.color);
	}

	function cancelEdit() {
		editingTagId = null;
	}

	function commitEdit() {
		if (!editingTagId) return;
		const patch: { name?: string; color?: string } = { color: editColor };
		if (editName.trim()) patch.name = editName.trim();
		onUpdateTag(editingTagId, patch);
		editingTagId = null;
	}

	function removeTag(id: string) {
		onDeleteTag(id);
		editingTagId = null;
	}

	function handleEditKeydown(e: KeyboardEvent) {
		if (e.key === 'Enter') commitEdit();
		else if (e.key === 'Escape') cancelEdit();
	}

	/** User tag tree (filtered to non-location mailboxes, depth-ordered). */
	let tagTree = $derived(buildTagTree(userTags(mailboxes)));
</script>

<!-- 8-swatch hue picker, shared by the new-tag block and the inline edit form. -->
{#snippet colorSwatches(selected: Hue, onPick: (c: Hue) => void)}
	<div class="sj-mail-sidebar__swatches" role="group" aria-label={t('inbox.manage.color')}>
		{#each TAG_COLORS as hue (hue)}
			<button
				type="button"
				class="sj-swatch"
				class:sj-swatch--on={selected === hue}
				style="--sw: var(--tag-{hue}-dot)"
				aria-label={hue}
				aria-pressed={selected === hue}
				onclick={() => onPick(hue)}
			></button>
		{/each}
	</div>
{/snippet}

<nav class="sj-mail-sidebar">
	<!-- #13 shared-mailbox use-surface — context-guard SIGNAL 1: the sidebar
	     header block (shared mailbox name + a "Shared" badge + a back-to-my-mail
	     X). Signal 2 is the page's persistent info strip; signal 3 is the
	     compose From Select — three REDUNDANT signals per the design pin. -->
	{#if sharedContext}
		<div class="sj-mail-sidebar__shared-header">
			<div class="sj-mail-sidebar__shared-header-row">
				<Icon name="Users" size={15} />
				<span class="sj-mail-sidebar__shared-name">{sharedName}</span>
				<IconButton label={t('inbox.shared.back')} size="sm" onclick={onBackToMyMail}>
					<Icon name="X" size={14} />
				</IconButton>
			</div>
			<span class="sj-mail-sidebar__shared-badge">{t('inbox.shared.badge')}</span>
		</div>
	{/if}

	<!-- Compose button (mail-kit §3). #13 DANGER STATE: disabled (not hidden)
	     with a tooltip on a read-only shared-mailbox grant. -->
	<Button
		variant="primary"
		class="sj-mail-sidebar__compose"
		data-tour="compose"
		onclick={onCompose}
		disabled={composeDisabled}
		title={composeDisabled ? composeDisabledReason : undefined}
	>
		{#snippet icon()}<Icon name="Pencil" size={15} />{/snippet}
		{t('inbox.compose')}
	</Button>

	<!-- Fixed VIEWS (mail-kit §3) — the shared-mailbox workspace collapses this
	     to Inbox/Drafts/Sent/Trash only (#13 design pin: personal features —
	     Snoozed/Scheduled/Archive/All Mail/Tags/Saved searches — are hidden). -->
	{#each visibleViews as v (v.id)}
		<SidebarItem
			label={v.id === 'starred' ? t('inbox.view.starred') : v.label}
			count={viewCount(v.id)}
			active={view === v.id && tagFilter === null}
			onclick={() => onSelectView(v.id)}
		>
			{#snippet icon()}<Icon name={v.icon as IconName} size={16} />{/snippet}
		</SidebarItem>
	{/each}

	{#if !sharedContext}
		<!-- TAGS header (mail-kit §3) -->
		<div class="sj-mail-sidebar__tags-header">
			<span>Tags</span>
			<IconButton size="sm" label="New tag" onclick={() => (showNewTag = !showNewTag)}>
				<Icon name="Plus" size={12} />
			</IconButton>
		</div>

		<!-- Inline new-tag input + hue picker -->
		{#if showNewTag}
			<div class="sj-mail-sidebar__new">
				<Input
					class="sj-mail-sidebar__new-input"
					placeholder="Tag name"
					bind:value={newTagName}
					onkeydown={handleNewTagKeydown}
				/>
				{@render colorSwatches(newTagColor, (c) => (newTagColor = c))}
			</div>
		{/if}

		<!-- Tag rows (mail-kit §3) with inline manage (rename/recolor/delete) -->
		{#each tagTree as tag (tag.id)}
			{#if editingTagId === tag.id}
				<div class="sj-mail-sidebar__tag-edit">
					<Input
						class="sj-mail-sidebar__new-input"
						placeholder={t('inbox.manage.name_placeholder')}
						bind:value={editName}
						onkeydown={handleEditKeydown}
					/>
					{@render colorSwatches(editColor, (c) => (editColor = c))}
					<div class="sj-mail-sidebar__tag-edit-actions">
						<Button size="sm" variant="secondary" onclick={commitEdit}>{t('inbox.manage.save')}</Button>
						<IconButton size="sm" label={t('inbox.manage.delete')} onclick={() => removeTag(tag.id)}>
							<Icon name="Trash2" size={14} />
						</IconButton>
					</div>
				</div>
			{:else}
				<div class="sj-mail-sidebar__tag-row">
					<SidebarItem
						label={tag.name}
						dotColor={safeTagHue(tag.color)}
						depth={tag.depth}
						count={counts.tagCounts[tag.id] ?? null}
						active={tagFilter === tag.id}
						onclick={() => onSelectTag(tag.id)}
					/>
					<IconButton
						class="sj-mail-sidebar__tag-manage"
						size="sm"
						label={t('inbox.manage.edit')}
						onclick={() => startEdit(tag)}
					>
						<Icon name="Pencil" size={12} />
					</IconButton>
				</div>
			{/if}
		{/each}

		<!-- SAVED SEARCHES section (named re-runnable queries; saved from the search bar) -->
		{#if savedSearches.length > 0}
			<div class="sj-mail-sidebar__tags-header">
				<span>Saved searches</span>
			</div>
			{#each savedSearches as s (s.id)}
				<div class="sj-mail-sidebar__saved-row">
					<SidebarItem label={s.name} onclick={() => onSelectSaved(s)}>
						{#snippet icon()}<Icon name="Search" size={16} />{/snippet}
					</SidebarItem>
					<IconButton
						class="sj-mail-sidebar__saved-delete"
						size="sm"
						label="Delete saved search"
						onclick={() => onDeleteSaved(s.id)}
					>
						<Icon name="X" size={12} />
					</IconButton>
				</div>
			{/each}
		{/if}
	{/if}

	<!-- SHARED MAILBOXES (#13 use-surface) — renders only with ≥1 MAIL delegate
	     grant. Each row opens that mailbox's workspace at /inbox?mbx=<id>. -->
	{#if sharedMailboxes.length > 0}
		<div class="sj-mail-sidebar__tags-header">
			<span>{t('inbox.shared.section')}</span>
		</div>
		{#each sharedMailboxes as acct (acct.id)}
			<SidebarItem label={acct.name} active={acct.id === activeSharedId} onclick={() => onSelectShared(acct.id)}>
				{#snippet icon()}<Icon name="Users" size={16} />{/snippet}
			</SidebarItem>
		{/each}
	{/if}
</nav>

<style>
	.sj-mail-sidebar {
		display: flex;
		flex-direction: column;
		gap: 1px;
		width: 100%;
		padding: 12px 8px;
		background: var(--surface-sidebar);
		border-right: 1px solid var(--border-default);
		overflow-y: auto;
		flex: none;
	}

	/* Desktop: fixed width (mail-kit §3) */
	@media (min-width: 1024px) {
		.sj-mail-sidebar {
			width: var(--sidebar-width); /* 232px */
			display: flex;
		}
	}

	/* Hidden below 1024px (drawer variant) */
	@media (max-width: 1023px) {
		.sj-mail-sidebar {
			display: none;
		}
	}

	/* #13 shared-mailbox context-guard header (signal 1 of 3). */
	.sj-mail-sidebar__shared-header {
		display: flex;
		flex-direction: column;
		gap: 2px;
		padding: 4px 6px 12px;
		margin-bottom: 4px;
		border-bottom: 1px solid var(--border-default);
	}
	.sj-mail-sidebar__shared-header-row {
		display: flex;
		align-items: center;
		gap: 6px;
		color: var(--text-primary);
	}
	.sj-mail-sidebar__shared-name {
		flex: 1;
		min-width: 0;
		font-size: var(--text-sm);
		font-weight: 600;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.sj-mail-sidebar__shared-badge {
		align-self: flex-start;
		font-size: var(--text-2xs);
		font-weight: 600;
		letter-spacing: var(--tracking-caps);
		text-transform: uppercase;
		color: var(--indigo-600);
		background: var(--surface-selected);
		border-radius: var(--radius-sm);
		padding: 2px 6px;
	}

	.sj-mail-sidebar__tags-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 14px 8px 4px;
		font-size: var(--text-2xs);
		font-weight: 600;
		letter-spacing: var(--tracking-caps);
		text-transform: uppercase;
		color: var(--text-tertiary);
	}

	.sj-mail-sidebar :global(.sj-mail-sidebar__compose) {
		margin: 0 4px 12px;
		justify-content: flex-start;
	}

	.sj-mail-sidebar :global(.sj-mail-sidebar__new-input) {
		margin: 4px 8px;
	}

	.sj-mail-sidebar__new,
	.sj-mail-sidebar__tag-edit {
		display: flex;
		flex-direction: column;
		gap: 4px;
		padding: 4px 0 8px;
	}

	/* 8-swatch hue picker (new-tag + inline edit). */
	.sj-mail-sidebar__swatches {
		display: flex;
		flex-wrap: wrap;
		gap: 6px;
		padding: 2px 8px;
	}
	.sj-swatch {
		width: 16px;
		height: 16px;
		border-radius: 50%;
		background: var(--sw);
		border: 2px solid transparent;
		cursor: pointer;
		padding: 0;
	}
	.sj-swatch:focus-visible {
		outline: var(--focus-ring);
	}
	.sj-swatch--on {
		border-color: var(--text-primary);
	}

	.sj-mail-sidebar__tag-edit-actions {
		display: flex;
		align-items: center;
		gap: 6px;
		padding: 0 8px;
	}

	/* Tag row: manage (pencil) control revealed on hover/focus, like saved-search. */
	.sj-mail-sidebar__tag-row {
		position: relative;
	}
	.sj-mail-sidebar__tag-row :global(.sj-mail-sidebar__tag-manage) {
		position: absolute;
		right: 6px;
		top: 50%;
		transform: translateY(-50%);
		opacity: 0;
		transition: opacity var(--duration-fast) var(--ease-out);
	}
	.sj-mail-sidebar__tag-row:hover :global(.sj-mail-sidebar__tag-manage),
	.sj-mail-sidebar__tag-row:focus-within :global(.sj-mail-sidebar__tag-manage) {
		opacity: 1;
	}

	/* Saved-search row: delete control revealed on hover/focus. */
	.sj-mail-sidebar__saved-row {
		position: relative;
	}
	.sj-mail-sidebar__saved-row :global(.sj-mail-sidebar__saved-delete) {
		position: absolute;
		right: 6px;
		top: 50%;
		transform: translateY(-50%);
		opacity: 0;
		transition: opacity var(--duration-fast) var(--ease-out);
	}
	.sj-mail-sidebar__saved-row:hover :global(.sj-mail-sidebar__saved-delete),
	.sj-mail-sidebar__saved-row:focus-within :global(.sj-mail-sidebar__saved-delete) {
		opacity: 1;
	}
</style>
