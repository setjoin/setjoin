<svelte:options runes={true} />

<script lang="ts">
	import { Dialog, Button, Input, Select, Spinner, showToast } from '$lib/components/ui';
	import { t } from '$lib/i18n';
	import { loadShares, shareCalendar, revokeShare } from '$lib/stores/calendar';
	import type { CalendarShare, CalendarShareLevel } from '$lib/types/jmap';
	import {
		getSharingOverview,
		setMyDefault,
		type SharingAudience,
		type SharingDefault,
		type SharingLevel
	} from '$lib/api/sharing';
	import { directoryTree, setDirectoryAccountId, type DirectoryNode } from '$lib/stores/directory';
	import LevelSegment from '$lib/components/LevelSegment.svelte';
	import { parseError } from '$lib/errors';

	let {
		open = false,
		calendarId,
		calendarName = '',
		onClose
	}: {
		open?: boolean;
		calendarId: string;
		calendarName?: string;
		onClose: () => void;
	} = $props();

	let shares = $state<CalendarShare[]>([]);
	let loading = $state(false);
	let newEmail = $state('');
	let newLevel = $state<CalendarShareLevel>('read');
	let busy = $state(false);
	let error = $state('');

	// ── Default visibility (§6-A) — hidden when sharing.defaults is OFF (D11) ──
	let defaultsEnabled = $state(false);
	let myDefault = $state<SharingDefault | null>(null); // ponytail: edits the first user-scope row; one-rule UX
	let inherited = $state<SharingDefault[]>([]);
	let defAudience = $state<SharingAudience>('everyone');
	let defLevel = $state<SharingLevel>('none');
	let defDeptId = $state('');
	let departments = $state<DirectoryNode[]>([]);
	let defSaving = $state(false);
	let defError = $state('');

	$effect(() => {
		if (open && calendarId) {
			void refresh();
			void loadDefaults();
		}
	});

	async function refresh() {
		loading = true;
		error = '';
		try {
			shares = await loadShares(calendarId);
		} catch {
			error = 'load_failed';
		} finally {
			loading = false;
		}
	}

	async function loadDefaults() {
		try {
			const ov = await getSharingOverview();
			defaultsEnabled = ov.defaultsEnabled;
			inherited = ov.inheritedDefaults;
			myDefault = ov.myDefaults[0] ?? null;
			if (myDefault) {
				defAudience = myDefault.audience;
				defLevel = myDefault.level;
				if (myDefault.audience === 'ou') defDeptId = String(myDefault.audienceRef);
			}
		} catch {
			defaultsEnabled = false; // fail closed — section hidden
		}
	}

	// Departments for the "A department" audience, from the user-facing
	// directory tree (flat list with depth for indentation).
	$effect(() => {
		if (defaultsEnabled && defAudience === 'ou' && departments.length === 0) {
			setDirectoryAccountId('-1');
			directoryTree()
				.then((nodes) => (departments = nodes))
				.catch(() => (defError = t('sharing.departments_failed')));
		}
	});

	const departmentOptions = $derived(
		departments.map((d) => ({ value: d.id, label: `${' '.repeat(d.depth)}${d.name}` }))
	);

	// 'group' is not user-settable (no user-facing group source) — offered only
	// to display/keep an existing group-audience default.
	const audienceOptions = $derived([
		{ value: 'everyone', label: t('sharing.audience.everyone') },
		{ value: 'ou', label: t('sharing.audience.ou') },
		...(myDefault?.audience === 'group' ? [{ value: 'group', label: t('sharing.audience.group') }] : [])
	]);

	// Most specific inherited baseline (group > ou > org) for the status line.
	const inheritedBaseline = $derived.by(() => {
		for (const scope of ['group', 'ou', 'org'] as const) {
			const row = inherited.find((r) => r.ownerScope === scope);
			if (row) return row;
		}
		return null;
	});

	async function saveDefault() {
		if (defSaving) return;
		if (defAudience === 'ou' && !defDeptId) {
			defError = t('sharing.pick_department');
			return;
		}
		defSaving = true;
		defError = '';
		const audienceRef = defAudience === 'ou' ? Number(defDeptId) : defAudience === 'group' ? (myDefault?.audienceRef ?? 0) : 0;
		try {
			const id = await setMyDefault(defAudience, audienceRef, defLevel);
			myDefault = { id, ownerScope: 'user', audience: defAudience, audienceRef, level: defLevel };
			showToast(
				t('sharing.default_saved', {
					audience: t(`sharing.audience.${defAudience}`),
					level: t(`sharing.level.${defLevel}`)
				})
			);
		} catch (e) {
			defError = parseError(e).message;
			// §6-D: the prior (persisted) value stays selected on failure.
			if (myDefault) {
				defAudience = myDefault.audience;
				defLevel = myDefault.level;
				if (myDefault.audience === 'ou') defDeptId = String(myDefault.audienceRef);
			}
		} finally {
			defSaving = false;
		}
	}

	const levelOptions = $derived([
		{ value: 'freebusy', label: t('calendar.share.level.freebusy') },
		{ value: 'read', label: t('calendar.share.level.read') },
		{ value: 'write', label: t('calendar.share.level.write') },
		{ value: 'admin', label: t('calendar.share.level.admin') }
	]);

	function levelLabel(level: string): string {
		return t(`calendar.share.level.${level}`);
	}

	async function add() {
		const email = newEmail.trim();
		if (!email || busy) return;
		busy = true;
		try {
			await shareCalendar(calendarId, email, newLevel);
			newEmail = '';
			newLevel = 'read';
			await refresh();
		} finally {
			busy = false;
		}
	}

	async function revoke(email: string) {
		if (busy) return;
		busy = true;
		try {
			await revokeShare(calendarId, email);
			await refresh();
		} finally {
			busy = false;
		}
	}
</script>

<Dialog {open} title={`${t('calendar.share.title')}${calendarName ? ` — ${calendarName}` : ''}`} onClose={onClose}>
	<div class="share-dialog">
		{#if defaultsEnabled}
			<section class="sd-default" aria-label={t('sharing.default_section')}>
				<h4 class="share-section">{t('sharing.default_section')}</h4>
				<div class="sd-default__controls">
					<Select
						label={t('sharing.audience_label')}
						value={defAudience}
						options={audienceOptions}
						onchange={(e: Event) => (defAudience = (e.currentTarget as HTMLSelectElement).value as SharingAudience)}
					/>
					{#if defAudience === 'ou'}
						<Select
							label={t('sharing.department_label')}
							value={defDeptId}
							options={[{ value: '', label: t('sharing.pick_department') }, ...departmentOptions]}
							onchange={(e: Event) => (defDeptId = (e.currentTarget as HTMLSelectElement).value)}
						/>
					{/if}
				</div>
				<div class="sd-default__level">
					<LevelSegment value={defLevel} label={t('sharing.level_label')} onChange={(l) => (defLevel = l)} />
					<Button variant="primary" size="sm" disabled={defSaving} onclick={saveDefault}>
						{t('common.save')}
					</Button>
				</div>
				{#if inheritedBaseline}
					<p class="sd-default__inherited">
						{t('sharing.inherited_line', {
							scope: t(`sharing.scope.${inheritedBaseline.ownerScope}`),
							level: t(`sharing.level.${inheritedBaseline.level}`)
						})}
					</p>
				{/if}
				{#if defError}
					<p class="sd-default__error" role="alert">{defError}</p>
				{/if}
			</section>
		{/if}

		<h4 class="share-section">{t('calendar.share.existing')}</h4>
		{#if loading}
			<div class="sd-loading"><Spinner size={16} label={t('calendar.share.title')} /></div>
		{:else if shares.length === 0}
			<p class="sd-empty">{t('calendar.share.empty')}</p>
		{:else}
			<ul class="sd-list">
				{#each shares as grant (grant.userEmail)}
					<li class="sd-row">
						<div class="sd-person">
							<span class="sd-email">{grant.userEmail}</span>
							<span class="sd-level">{levelLabel(grant.level)}</span>
						</div>
						<Button variant="ghost" size="sm" onclick={() => revoke(grant.userEmail)}>
							{t('calendar.share.revoke')}
						</Button>
					</li>
				{/each}
			</ul>
		{/if}

		<div class="sd-add">
			<Input label={t('calendar.share.add_email')} type="email" bind:value={newEmail} />
			<Select
				aria-label="access level"
				value={newLevel}
				options={levelOptions}
				onchange={(e: Event) => (newLevel = (e.currentTarget as HTMLSelectElement).value as CalendarShareLevel)}
			/>
			<Button variant="primary" size="sm" disabled={busy} onclick={add}>
				{t('calendar.share.add')}
			</Button>
		</div>
	</div>

	{#snippet footer()}
		<Button variant="secondary" size="md" onclick={onClose}>{t('common.close')}</Button>
	{/snippet}
</Dialog>

<style>
	.share-dialog {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
		min-width: 24rem;
	}
	.share-section {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.sd-loading {
		display: flex;
		justify-content: center;
		padding: var(--space-3);
	}
	.sd-empty {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		margin: 0;
	}
	.sd-list {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.sd-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: var(--space-2) var(--space-3);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
	}
	.sd-person {
		display: flex;
		flex-direction: column;
	}
	.sd-email {
		color: var(--text-primary);
	}
	.sd-level {
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.sd-add {
		display: flex;
		gap: var(--space-2);
		align-items: flex-end;
		border-top: 1px solid var(--border-subtle);
		padding-top: var(--space-3);
	}
	.sd-default {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-md);
		padding: var(--space-3);
		background: var(--surface-sunken);
	}
	.sd-default__controls {
		display: flex;
		gap: var(--space-2);
		align-items: flex-end;
		flex-wrap: wrap;
	}
	.sd-default__level {
		display: flex;
		gap: var(--space-2);
		align-items: center;
		flex-wrap: wrap;
	}
	.sd-default__inherited {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--text-caption);
	}
	.sd-default__error {
		margin: 0;
		font-size: var(--text-sm);
		color: var(--danger-fg);
	}
</style>
