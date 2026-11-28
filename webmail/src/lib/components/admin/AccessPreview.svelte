<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { Select, Card, Tag, EmptyState, Spinner, Input } from '$lib/components/ui';
	import { adminUserList, type AdminUser } from '$lib/admin/client';
	import { adminEffectivePermissions, type EffectivePerms } from '$lib/admin/roles';
	import { sourceFor } from '$lib/rbac/effectivePerms';
	import { CAPABILITIES, type CapabilityCap } from '$lib/admin/capabilityCatalog';
	import { CONSOLES, type ConsoleId } from '$lib/admin/consoles';
	import { parseError } from '$lib/errors';
	import { t } from '$lib/i18n';

	let { userId = null }: { userId?: number | null } = $props();

	let userQuery = $state('');
	let users = $state<AdminUser[]>([]);
	let pickedStr = $state('');
	let data = $state<EffectivePerms | null>(null);
	let loading = $state(false);
	let error = $state('');

	let userOptions = $derived([
		{ value: '', label: '—' },
		...users.map((u) => ({ value: String(u.id), label: u.email }))
	]);

	// The 5 consoles in declared order, each with access derived from data.consoles.
	let consoleRows = $derived(
		CONSOLES.map((c) => ({
			id: c.id as ConsoleId,
			label: t(c.label),
			open: (data?.consoles ?? []).includes(c.id)
		}))
	);

	// Capabilities grouped console → list, only for consoles in the catalog.
	let capsByConsole = $derived(
		CONSOLES.map((c) => ({
			id: c.id as ConsoleId,
			label: t(c.label),
			caps: CAPABILITIES.filter((cap) => cap.console === c.id)
		})).filter((g) => g.caps.length > 0)
	);

	let grantedCount = $derived(
		data ? CAPABILITIES.filter((cap) => data!.permissions.includes(cap.perm)).length : 0
	);
	let consoleCount = $derived(data?.consoles?.length ?? 0);

	// Sync the userId prop into pickedStr so Task 4 deep-link preselect works.
	$effect(() => {
		pickedStr = userId == null ? '' : String(userId);
	});

	onMount(() => void searchUsers());

	async function searchUsers() {
		try {
			users = await adminUserList(userQuery || undefined);
		} catch (e) {
			error = parseError(e).message;
		}
	}

	$effect(() => {
		const id = pickedStr === '' ? null : Number(pickedStr);
		void pick(id);
	});

	async function pick(id: number | null) {
		data = null;
		error = '';
		if (id == null) return;
		loading = true;
		try {
			data = await adminEffectivePermissions(id);
		} catch (e) {
			error = parseError(e).message;
		} finally {
			loading = false;
		}
	}

	function can(cap: CapabilityCap): boolean {
		return data?.permissions.includes(cap.perm) ?? false;
	}
	function via(cap: CapabilityCap): string {
		return sourceFor(data, cap.perm);
	}
	const isEmpty = $derived(data != null && data.permissions.length === 0);
</script>

<div class="sj-ap">
	<Input label={t('admin.access_preview.search_user')} bind:value={userQuery} oninput={() => void searchUsers()} />
	<Select label={t('admin.access_preview.pick_user')} options={userOptions} bind:value={pickedStr} />

	{#if error}
		<div class="sj-alert-danger" role="alert">{error}</div>
	{:else if loading}
		<Spinner size={20} label={t('admin.access_preview.resolving')} />
	{:else if !data}
		<!-- Initial state: no user selected -->
		<div class="sj-ap-empty">
			<EmptyState title={t('admin.access_preview.initial_title')} />
			<p class="sj-ap-empty-sub">{t('admin.access_preview.initial_sub')}</p>
		</div>
	{:else if isEmpty}
		<!-- Non-admin user: no permissions -->
		<div class="sj-ap-empty">
			<EmptyState title={t('admin.access_preview.none_title')} />
			<p class="sj-ap-empty-sub">{t('admin.access_preview.none_sub')}</p>
		</div>
	{:else}
		<!-- Headline summary (Pass 1: the 3-second answer) -->
		<div class="sj-ap-head">
			<span class="sj-ap-scope">
				{data.domainScope == null
					? t('admin.access_preview.scope_global')
					: t('admin.access_preview.scope_domain', { id: String(data.domainScope) })}
			</span>
			<span class="sj-ap-roles">
				<!-- Tag color: 'purple' is the closest to indigo in the 8-hue system -->
				{#each data.sources as s}<Tag label={s.roleName} color="purple" />{/each}
			</span>
			<span class="sj-ap-counts">{t('admin.access_preview.counts', { consoles: String(consoleCount), caps: String(grantedCount), total: String(CAPABILITIES.length) })}</span>
		</div>

		<!-- Consoles (●/○ + label; neutral, not color-only) -->
		<Card>
			<div class="sj-ap-consoles">
				{#each consoleRows as c}
					<span class="sj-ap-console" class:on={c.open}>
						<span aria-hidden="true">{c.open ? '●' : '○'}</span>
						<span class="sj-vh">{c.open ? t('admin.access_preview.console_on') : t('admin.access_preview.console_off')}</span>
						{c.label}
					</span>
				{/each}
			</div>
		</Card>

		<!-- Capability grid grouped console → page (a list, not a card mosaic) -->
		{#each capsByConsole as group}
			<div class="sj-ap-group">
				<h4 class="sj-ap-group-h">{group.label}</h4>
				{#each group.caps as cap}
					<div class="sj-ap-row">
						<!-- ✓/✗: glyph + aria-label (can/cannot) + visible text — never color-alone -->
						<span
							class="sj-ap-mark"
							class:granted={can(cap)}
							class:denied={!can(cap)}
							aria-label={can(cap) ? t('admin.access_preview.can') : t('admin.access_preview.cannot')}
						>
							{can(cap) ? '✓' : '✗'}
						</span>
						<span class="sj-ap-label">{cap.label}</span>
						<code class="sj-ap-perm">{cap.perm}</code>
						<!-- Granting role is inline (not hover-only) -->
						<span class="sj-ap-via">{can(cap) ? t('admin.access_preview.via', { role: via(cap) }) : t('admin.access_preview.not_granted')}</span>
					</div>
				{/each}
			</div>
		{/each}

		<!-- Raw permissions (collapsible, keyboard-native) -->
		<details class="sj-ap-raw">
			<summary>{t('admin.access_preview.raw', { n: String(data.permissions.length) })}</summary>
			{#each data.permissions as p}
				<div class="sj-ap-rawrow">
					<code>{p}</code>
					<span class="sj-ap-via">{t('admin.access_preview.via', { role: sourceFor(data, p) })}</span>
				</div>
			{/each}
		</details>
	{/if}
</div>

<style>
	.sj-ap { display: flex; flex-direction: column; gap: var(--space-4); }
	.sj-alert-danger {
		padding: var(--space-2) var(--space-3); border-radius: var(--radius-sm);
		background: var(--danger-bg); color: var(--danger-fg); border: 1px solid var(--danger-fg);
		font-size: var(--text-sm);
	}
	.sj-ap-empty { display: flex; flex-direction: column; align-items: center; }
	.sj-ap-empty-sub { margin: 0; font-size: var(--text-sm); color: var(--text-caption); text-align: center; }
	.sj-ap-head { display: flex; align-items: center; gap: var(--space-3); flex-wrap: wrap; }
	.sj-ap-scope, .sj-ap-counts { font-size: var(--text-sm); color: var(--text-caption); }
	.sj-ap-roles { display: flex; gap: var(--space-1); flex-wrap: wrap; }
	.sj-ap-consoles { display: flex; gap: var(--space-4); flex-wrap: wrap; }
	.sj-ap-console { font-size: var(--text-sm); color: var(--text-tertiary); display: inline-flex; gap: var(--space-1); align-items: baseline; }
	.sj-ap-console.on { color: var(--text-primary); }
	.sj-ap-group { display: flex; flex-direction: column; }
	.sj-ap-group-h { font-size: var(--text-xs); font-weight: var(--weight-semibold); text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary); margin: var(--space-3) 0 var(--space-1); }
	.sj-ap-row { display: grid; grid-template-columns: 20px 1fr auto auto; gap: var(--space-2); align-items: baseline; padding: var(--space-1) 0; border-bottom: 1px solid var(--border-subtle); }
	.sj-ap-mark { font-weight: var(--weight-bold); }
	.sj-ap-mark.granted { color: var(--success-fg); }
	.sj-ap-mark.denied { color: var(--danger-fg); }
	.sj-ap-label { font-size: var(--text-sm); color: var(--text-primary); }
	.sj-ap-perm { font-family: var(--font-mono); font-size: var(--text-xs); color: var(--text-caption); }
	.sj-ap-via { font-size: var(--text-xs); color: var(--text-caption); }
	.sj-ap-raw { font-family: var(--font-sans); font-size: var(--text-sm); }
	.sj-ap-rawrow { display: flex; justify-content: space-between; padding: var(--space-1) 0; }
	.sj-vh { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); }
</style>
