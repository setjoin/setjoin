<svelte:options runes={true} />
<!--
  PrincipalPicker — resolved exclude picker (chips + typeahead combobox).
  Reusable for both user and group exclusions on the CA admin console.

  Props:
    kind     'user' | 'group'  — controls search endpoint + avatar/icon rendering
    value    number[]           — current list of selected principal IDs
    onChange (ids: number[]) => void — callback when the set changes

  API consumed:
    Resolve: GET /admin/conditional-access/resolve-principals?users=…&groups=…
    Search users:  GET /admin/users?q=…
    Search groups: GET /admin/user-groups?q=…  (directory groups list with ?q=)

  Resolve endpoint response shape (Task 7):
    { users: [{id,email,display_name}], groups: [{id,name}] }
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { Avatar, Badge, Spinner, Tooltip } from '$lib/components/ui';
	import { t } from '$lib/i18n';
	import { adminFetch } from '$lib/admin/client';

	interface UserPrincipal {
		id: number;
		email: string;
		display_name: string;
	}
	interface GroupPrincipal {
		id: number;
		name: string;
	}
	type Principal = UserPrincipal | GroupPrincipal;

	interface ChipEntry {
		id: number;
		label: string;    // display_name or name
		sub: string;      // email or '' for groups
		resolved: boolean; // false = unresolvable id (danger chip)
	}

	let {
		kind,
		value = [],
		onChange,
	}: {
		kind: 'user' | 'group';
		value?: number[];
		onChange: (ids: number[]) => void;
	} = $props();

	// ── State ──
	let chips: ChipEntry[] = $state([]);
	let resolveLoading = $state(false);
	let resolveError = $state('');

	let query = $state('');
	let searchResults: Principal[] = $state([]);
	let searchLoading = $state(false);
	let searchError = $state('');
	let listOpen = $state(false);
	let partialResults = $state(false);

	// A11y combobox state
	let activeIdx = $state(-1);
	let inputEl: HTMLInputElement | undefined = $state(undefined);
	let listboxEl: HTMLElement | undefined = $state(undefined);
	const listboxId = `pp-listbox-${Math.random().toString(36).slice(2, 9)}`;

	// ── Resolve on mount (and when value changes externally) ──
	$effect(() => {
		const ids = value;
		if (ids.length === 0) {
			chips = [];
			return;
		}
		void resolveIds(ids);
	});

	async function resolveIds(ids: number[]) {
		resolveLoading = true;
		resolveError = '';
		try {
			const param = kind === 'user' ? `users=${ids.join(',')}` : `groups=${ids.join(',')}`;
			const res = await adminFetch(`/admin/conditional-access/resolve-principals?${param}`);
			if (!res.ok) throw new Error(String(res.status));
			const data: { users: UserPrincipal[]; groups: GroupPrincipal[] } = await res.json();
			const list = kind === 'user' ? data.users : data.groups;
			// Build chips — ids that weren't returned are unresolvable
			chips = ids.map((id) => {
				const found = list.find((p) => p.id === id);
				if (!found) {
					return { id, label: String(id), sub: '', resolved: false };
				}
				if (kind === 'user') {
					const u = found as UserPrincipal;
					return { id, label: u.display_name || u.email, sub: u.email, resolved: true };
				}
				const g = found as GroupPrincipal;
				return { id, label: g.name || String(id), sub: '', resolved: true };
			});
		} catch {
			resolveError = t('admin.ca.picker.load_error');
		} finally {
			resolveLoading = false;
		}
	}

	// ── Search (debounced) ──
	let searchTimer: ReturnType<typeof setTimeout> | undefined;

	function handleQueryInput(e: Event) {
		query = (e.target as HTMLInputElement).value;
		activeIdx = -1;
		clearTimeout(searchTimer);
		if (!query.trim()) {
			listOpen = false;
			searchResults = [];
			return;
		}
		searchTimer = setTimeout(() => void doSearch(), 220);
	}

	async function doSearch() {
		searchLoading = true;
		searchError = '';
		listOpen = true;
		try {
			const endpoint =
				kind === 'user'
					? `/admin/users?q=${encodeURIComponent(query)}&limit=21`
					: `/admin/user-groups?q=${encodeURIComponent(query)}&limit=21`;
			const res = await adminFetch(endpoint);
			if (!res.ok) throw new Error(String(res.status));
			const raw: Principal[] = await res.json();
			partialResults = raw.length > 20;
			searchResults = raw.slice(0, 20);
		} catch {
			searchError = t('admin.ca.picker.load_error');
			// Keep the listbox open so the user can see the actionable search error.
			// Closing it here made the error state unreachable even though it was set.
			listOpen = true;
		} finally {
			searchLoading = false;
		}
	}

	// ── Add chip from search result ──
	function addResult(p: Principal) {
		const id = p.id;
		if (value.includes(id)) return; // already added
		const label = kind === 'user'
			? ((p as UserPrincipal).display_name || (p as UserPrincipal).email)
			: (p as GroupPrincipal).name || String(id);
		const sub = kind === 'user' ? (p as UserPrincipal).email : '';
		chips = [...chips, { id, label, sub, resolved: true }];
		onChange([...value, id]);
		query = '';
		searchResults = [];
		listOpen = false;
		activeIdx = -1;
		inputEl?.focus();
	}

	// ── Remove chip ──
	function removeChip(id: number) {
		chips = chips.filter((c) => c.id !== id);
		onChange(value.filter((x) => x !== id));
	}

	// ── Keyboard navigation ──
	function handleKeydown(e: KeyboardEvent) {
		if (e.key === 'Escape') {
			listOpen = false;
			activeIdx = -1;
			return;
		}
		if (e.key === 'Backspace' && query === '' && chips.length > 0) {
			const last = chips[chips.length - 1];
			removeChip(last.id);
			return;
		}
		if (!listOpen || searchResults.length === 0) return;

		if (e.key === 'ArrowDown') {
			e.preventDefault();
			activeIdx = (activeIdx + 1) % searchResults.length;
		} else if (e.key === 'ArrowUp') {
			e.preventDefault();
			activeIdx = activeIdx <= 0 ? searchResults.length - 1 : activeIdx - 1;
		} else if (e.key === 'Enter' && activeIdx >= 0) {
			e.preventDefault();
			addResult(searchResults[activeIdx]);
		}
	}

	// ── Has invalid chips (blocks save) ──
	export function hasInvalid(): boolean {
		return chips.some((c) => !c.resolved);
	}

	// ── Retry resolve ──
	async function retryResolve() {
		if (value.length > 0) await resolveIds(value);
	}
</script>

<div class="pp" data-testid="principal-picker-{kind}">
	<!-- Screen-reader status for loading -->
	{#if resolveLoading}
		<span class="sr-only" role="status">{t('admin.ca.list.loading')}</span>
	{/if}

	<!-- Resolve error banner -->
	{#if resolveError}
		<div class="pp__error" role="alert" data-testid="pp-resolve-error">
			{resolveError}
			<button type="button" class="pp__retry-btn" onclick={retryResolve}>{t('common.retry')}</button>
		</div>
	{/if}

	<!-- Chip list + combobox input (the labelled field) -->
	<!-- svelte-ignore a11y_role_has_required_aria_props -->
	<div
		class="pp__field"
		role="combobox"
		aria-expanded={listOpen}
		aria-controls={listboxId}
		aria-haspopup="listbox"
	>
		<!-- Chips -->
		{#each chips as chip (chip.id)}
			<span
				class="pp__chip"
				class:pp__chip--invalid={!chip.resolved}
				data-testid={chip.resolved ? 'pp-chip' : 'pp-chip-invalid'}
				title={chip.label}
				aria-label={chip.label}
			>
				{#if kind === 'user' && chip.resolved}
					<Avatar name={chip.label} size="sm" />
				{:else if kind === 'group' && chip.resolved}
					<!-- group icon -->
					<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
						<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/>
						<path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>
					</svg>
				{:else}
					<!-- unresolvable: warning icon -->
					<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
						<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
					</svg>
				{/if}
				<span class="pp__chip-label" title={chip.label}>{chip.label}</span>
				{#if chip.sub}
					<Tooltip text={chip.sub}>
						<span class="pp__chip-sub" aria-hidden="true">({chip.sub.slice(0, 12)}{chip.sub.length > 12 ? '…' : ''})</span>
					</Tooltip>
				{/if}
				{#if !chip.resolved}
					<Badge variant="danger" label={t('admin.ca.picker.not_found')} />
				{/if}
				<button
					type="button"
					class="pp__chip-x"
					aria-label={t('admin.ca.picker.remove', { name: chip.label })}
					onclick={() => removeChip(chip.id)}
				>
					<svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" aria-hidden="true">
						<path d="M18 6 6 18M6 6l12 12" />
					</svg>
				</button>
			</span>
		{/each}

		<!-- Typeahead input -->
		<input
			bind:this={inputEl}
			class="pp__input"
			type="text"
			placeholder={chips.length === 0 ? t('admin.ca.picker.empty') : t('admin.ca.picker.search')}
			value={query}
			autocomplete="off"
			aria-label={kind === 'user' ? t('admin.ca.field.exclude_users') : t('admin.ca.field.exclude_groups')}
			aria-autocomplete="list"
			aria-controls={listboxId}
			aria-activedescendant={activeIdx >= 0 ? `${listboxId}-opt-${activeIdx}` : undefined}
			oninput={handleQueryInput}
			onkeydown={handleKeydown}
			onfocus={() => { if (query.trim() && searchResults.length > 0) listOpen = true; }}
			onblur={() => setTimeout(() => { listOpen = false; activeIdx = -1; }, 150)}
		/>

		{#if searchLoading}
			<span class="pp__spinner"><Spinner size={16} label={t('admin.ca.list.loading')} /></span>
		{/if}
	</div>

	<!-- Dropdown listbox -->
	{#if listOpen && !searchLoading}
		<!-- svelte-ignore a11y_interactive_supports_focus -->
		<ul
			id={listboxId}
			bind:this={listboxEl}
			class="pp__list"
			role="listbox"
			aria-label={kind === 'user' ? t('admin.ca.field.exclude_users') : t('admin.ca.field.exclude_groups')}
		>
			{#if searchError}
				<li class="pp__list-error" role="alert">{searchError}</li>
			{:else if searchResults.length === 0}
				<li class="pp__list-empty">{t('admin.ca.picker.empty')}</li>
			{:else}
				{#each searchResults as result, i (result.id)}
					<!-- svelte-ignore a11y_interactive_supports_focus -->
					<li
						id="{listboxId}-opt-{i}"
						role="option"
						aria-selected={activeIdx === i}
						class="pp__list-item"
						class:pp__list-item--active={activeIdx === i}
						onmousedown={(e) => { e.preventDefault(); addResult(result); }}
					>
						{#if kind === 'user'}
							<Avatar name={(result as UserPrincipal).display_name || (result as UserPrincipal).email} size="sm" />
							<span class="pp__list-name">{(result as UserPrincipal).display_name || (result as UserPrincipal).email}</span>
							<span class="pp__list-sub">{(result as UserPrincipal).email}</span>
						{:else}
							<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
								<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/>
								<path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>
							</svg>
							<span class="pp__list-name">{(result as GroupPrincipal).name}</span>
						{/if}
					</li>
				{/each}
				{#if partialResults}
					<li class="pp__list-partial">{t('admin.ca.picker.refine')}</li>
				{/if}
			{/if}
		</ul>
	{/if}

	<!-- Invalid chip error -->
	{#if chips.some((c) => !c.resolved)}
		<p class="pp__invalid-msg" role="alert" data-testid="pp-invalid-msg">
			{t('admin.ca.picker.invalid')}
		</p>
	{/if}
</div>

<style>
	.pp {
		position: relative;
		display: flex;
		flex-direction: column;
		gap: 6px;
		font-family: var(--font-sans);
	}

	.pp__field {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 6px;
		min-height: var(--control-height);
		padding: 4px 8px;
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		background: var(--surface-card);
		cursor: text;
		transition: border-color var(--duration-fast) var(--ease-out),
			box-shadow var(--duration-fast) var(--ease-out);
	}

	.pp__field:focus-within {
		border-color: var(--accent);
		box-shadow: var(--focus-ring);
	}

	.pp__chip {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		height: 22px;
		padding: 0 6px 0 4px;
		border-radius: var(--radius-sm);
		background: var(--accent-subtle);
		color: var(--accent-fg-on-subtle);
		font-size: var(--text-xs);
		font-weight: var(--weight-medium);
		max-width: 200px;
		/* chip add/remove animation */
		animation: pp-chip-in var(--duration-fast) var(--ease-out);
	}

	.pp__chip--invalid {
		background: var(--danger-bg);
		color: var(--danger-fg);
	}

	.pp__chip-label {
		max-width: 120px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.pp__chip-sub {
		color: var(--text-tertiary);
		font-size: var(--text-2xs);
	}

	.pp__chip-x {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		position: relative;
		width: 14px;
		height: 14px;
		border: none;
		background: transparent;
		color: inherit;
		opacity: 0.6;
		cursor: pointer;
		border-radius: var(--radius-xs);
		padding: 0;
		flex: none;
	}

	/* ≥44px touch target via ::before hit-area expansion (keeps inline chip layout) */
	.pp__chip-x::before {
		content: '';
		position: absolute;
		inset: -15px;
		min-width: 44px;
		min-height: 44px;
	}

	.pp__chip-x:hover {
		opacity: 1;
		background: var(--surface-hover);
	}

	.pp__chip-x:focus-visible {
		outline: none;
		box-shadow: var(--focus-ring);
	}

	.pp__input {
		flex: 1 1 120px;
		min-width: 80px;
		border: none;
		outline: none;
		background: transparent;
		font-family: var(--font-sans);
		font-size: var(--text-sm);
		color: var(--text-primary);
		padding: 0;
		line-height: var(--leading-normal);
	}

	.pp__input::placeholder {
		color: var(--text-disabled);
	}

	.pp__spinner {
		display: inline-flex;
		align-items: center;
		margin-left: 4px;
	}

	.pp__list {
		position: absolute;
		top: calc(100% + 4px);
		left: 0;
		right: 0;
		z-index: 100;
		background: var(--surface-card);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		box-shadow: var(--shadow-md);
		list-style: none;
		margin: 0;
		padding: 4px 0;
		max-height: 240px;
		overflow-y: auto;
		animation: pp-list-in var(--duration-fast) var(--ease-out);
	}

	.pp__list-item {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 6px 10px;
		cursor: pointer;
		font-size: var(--text-sm);
		color: var(--text-primary);
	}

	.pp__list-item--active,
	.pp__list-item:hover {
		background: var(--surface-hover);
	}

	.pp__list-name {
		flex: 1;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.pp__list-sub {
		color: var(--text-tertiary);
		font-size: var(--text-xs);
		flex-shrink: 0;
	}

	.pp__list-empty,
	.pp__list-partial {
		padding: 8px 10px;
		font-size: var(--text-sm);
		color: var(--text-tertiary);
	}

	.pp__list-partial {
		border-top: 1px solid var(--border-subtle);
	}

	.pp__list-error {
		padding: 8px 10px;
		font-size: var(--text-sm);
		color: var(--danger-fg);
	}

	.pp__error {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 8px 10px;
		border-radius: var(--radius-sm);
		background: var(--danger-bg);
		color: var(--danger-fg);
		font-size: var(--text-sm);
	}

	.pp__retry-btn {
		border: none;
		background: transparent;
		color: inherit;
		font: inherit;
		cursor: pointer;
		text-decoration: underline;
		padding: 0;
	}

	.pp__invalid-msg {
		font-size: var(--text-sm);
		color: var(--danger-fg);
		margin: 0;
	}

	.sr-only {
		position: absolute;
		width: 1px;
		height: 1px;
		padding: 0;
		margin: -1px;
		overflow: hidden;
		clip-path: inset(50%);
		white-space: nowrap;
		border: 0;
	}

	@keyframes pp-chip-in {
		from { opacity: 0; transform: scale(0.9); }
		to { opacity: 1; transform: none; }
	}

	@keyframes pp-list-in {
		from { opacity: 0; transform: translateY(-4px); }
		to { opacity: 1; transform: none; }
	}

	@media (prefers-reduced-motion: reduce) {
		.pp__chip,
		.pp__list {
			animation: none;
		}
	}
</style>
