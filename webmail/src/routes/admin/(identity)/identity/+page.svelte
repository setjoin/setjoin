<svelte:options runes={true} />

<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import {
		adminAuthMethodList, adminAuthMethodUpdate,
		adminADConfig, adminADSetConfig, adminADTestConnection,
		adminADSync, adminADHealth, adminADConflicts,
		adminADResolveConflict, adminADResolveAllConflicts,
		adminGetGroupMappings, adminUpdateGroupMappings,
		adminLDAPConfig, adminLDAPSetConfig, adminLDAPTestConnection,
		adminLDAPPreview, adminLDAPSync, adminLDAPHealth, adminLDAPSyncLog,
		getAuditPolicy,
		type AuthMethod, type ADHealth, type SyncConflict, type GroupMapping,
		type LDAPHealth, type LDAPPreview, type LDAPPreviewRow, type SyncLogEntry,
	} from '$lib/admin/client';
	import { parseError } from '$lib/errors';
	import { adminPermissions, hasPermission } from '$lib/stores/auth';
	import IdentityModelConsole from '$lib/components/admin/identity/IdentityModelConsole.svelte';
	import { t } from '$lib/i18n';
	import { Card, Badge, Button, Input, Select, Checkbox, Switch, Table, Tabs, Dialog, EmptyState, Spinner, showToast } from '$lib/components/ui';
	import type { TableColumn, TabItem } from '$lib/components/ui';
	import AdminSignInActivity from '$lib/components/admin/AdminSignInActivity.svelte';
	import ReasonPrompt from '$lib/components/admin/ReasonPrompt.svelte';

	// Per-user drill-down: ?user=123 shows sign-in activity for that user below the identity config.
	// ponytail: query-param approach — no new route needed, piggybacks the identity console URL.
	// $app/state (non-store rune) is used — it's already mocked in vitest.setup.ts.
	const selectedUserId = $derived.by((): number | null => {
		const raw = page.url?.searchParams?.get('user');
		if (!raw) return null;
		const n = parseInt(raw, 10);
		return Number.isFinite(n) && n > 0 ? n : null;
	});

	let authMethods = $state<AuthMethod[]>([]);
	let adConfig = $state<Record<string, string>>({});
	let adHealth = $state<ADHealth | null>(null);
	let conflicts = $state<SyncConflict[]>([]);
	let loading = $state(true);
	let error = $state('');
	let saving = $state(false);
	let testingConn = $state(false);
	let testResult = $state<{ ok: boolean; msg: string } | null>(null);

	let activeTab = $state('auth');
	let showAdvanced = $state(false);
	let showConflicts = $state(false);

	let groupMappings = $state<Record<string, Record<string, GroupMapping[]>>>({ saml: {}, oidc: {} });
	let gmProvider = $state('');
	let gmType = $state<'saml' | 'oidc'>('saml');
	let gmSaving = $state(false);

	// ── Audit policy: reason-required gate ──
	// ponytail: fetched once on mount; false = no prompt (default policy)
	let identityReasonRequired = $state(false);
	let gmReasonPromptOpen = $state(false);

	let adDomain = $state(''); let adBindDn = $state(''); let adPassword = $state('');
	let adInterval = $state('15'); let adAutoDepts = $state(false); let adProxyAliases = $state(false);

	// ── Custom LDAP sync (#15) ──
	let ldapHealth = $state<LDAPHealth | null>(null);
	let ldapSyncLog = $state<SyncLogEntry[]>([]);
	let ldapPreview = $state<LDAPPreview | null>(null);
	let ldapHost = $state(''); let ldapPort = $state('636'); let ldapTLS = $state(true);
	let ldapBindDn = $state(''); let ldapPassword = $state(''); let ldapBaseDn = $state('');
	let ldapFilter = $state('');
	let ldapInterval = $state('15'); let ldapAutoDepts = $state(false); let ldapEnabled = $state(false);
	let ldapSaving = $state(false);
	let ldapTesting = $state(false);
	let ldapTestResult = $state<{ ok: boolean; msg: string } | null>(null);
	let ldapPreviewing = $state(false);
	let ldapEnableConfirmOpen = $state(false);

	onMount(() => {
		// ponytail: audit policy failure is non-fatal
		void getAuditPolicy().then((p) => {
			identityReasonRequired = p.reasonRequiredAreas.includes('identity');
		}).catch(() => { /* non-fatal: default = no prompt */ });
		loadAll();
	});

	async function loadAll() { loading = true; error = ''; try { const methods = await adminAuthMethodList(); authMethods = methods; await loadADConfig(); await loadADHealth(); await loadConflicts(); await loadGroupMappings(); await loadLDAPConfig(); await loadLDAPHealth(); await loadLDAPSyncLog(); } catch (e) { error = parseError(e).message; } finally { loading = false; } }
	async function loadADConfig() { try { const cfg = await adminADConfig(); adConfig = cfg; adDomain = cfg['ad_sync_domain'] ?? ''; adBindDn = cfg['ad_sync_bind_dn'] ?? ''; adInterval = cfg['ad_sync_interval_min'] ?? '15'; adAutoDepts = cfg['ad_sync_auto_create_depts'] === 'true'; adProxyAliases = cfg['ad_sync_proxy_as_aliases'] === 'true'; } catch { /* AD may not be configured */ } }
	async function loadADHealth() { try { adHealth = await adminADHealth(); } catch { /* AD may not be configured */ } }
	async function loadConflicts() { try { conflicts = await adminADConflicts(); } catch { /* conflicts endpoint may not exist yet */ } }
	async function loadGroupMappings() { try { groupMappings = await adminGetGroupMappings(); } catch { /* empty */ } }

	async function testConnection() { testingConn = true; try { await adminADTestConnection(); testResult = { ok: true, msg: 'Connected successfully' }; } catch (e) { testResult = { ok: false, msg: parseError(e).message }; } finally { testingConn = false; } }
	async function saveADConfig() {
		saving = true; error = '';
		const cfg: Record<string, string> = {};
		if (adDomain) cfg['ad_sync_domain'] = adDomain;
		if (adBindDn) cfg['ad_sync_bind_dn'] = adBindDn;
		if (adPassword) cfg['ad_sync_password_enc'] = adPassword; // blank = keep current (server-side; mirrors the LDAP form)
		cfg['ad_sync_interval_min'] = adInterval;
		cfg['ad_sync_auto_create_depts'] = adAutoDepts ? 'true' : 'false';
		cfg['ad_sync_proxy_as_aliases'] = adProxyAliases ? 'true' : 'false';
		try {
			await adminADSetConfig(cfg);
			adPassword = ''; // never keep the raw secret in the form after it's sent
			showToast('AD config saved');
		} catch (e) {
			error = parseError(e).message;
		} finally {
			saving = false;
		}
	}
	async function syncNow() { error = ''; try { await adminADSync(); await loadADHealth(); showToast('Sync started'); } catch (e) { error = parseError(e).message; } }

	// ── Custom LDAP sync (#15) ──
	async function loadLDAPConfig() {
		try {
			const cfg = await adminLDAPConfig();
			ldapHost = cfg['ldap_sync_host'] ?? '';
			ldapPort = cfg['ldap_sync_port'] ?? '636';
			ldapTLS = cfg['ldap_sync_tls'] !== 'false';
			ldapBindDn = cfg['ldap_sync_bind_dn'] ?? '';
			ldapBaseDn = cfg['ldap_sync_base_dn'] ?? '';
			ldapFilter = cfg['ldap_sync_user_filter'] ?? '';
			ldapInterval = cfg['ldap_sync_interval_min'] ?? '15';
			ldapAutoDepts = cfg['ldap_sync_auto_create_depts'] === 'true';
			ldapEnabled = cfg['ldap_sync_enabled'] === 'true';
		} catch { /* LDAP may not be configured yet */ }
	}
	async function loadLDAPHealth() { try { ldapHealth = await adminLDAPHealth(); } catch { /* LDAP may not be configured yet */ } }
	async function loadLDAPSyncLog() { try { ldapSyncLog = await adminLDAPSyncLog(); } catch { /* empty */ } }

	async function saveLDAPConfig(extra?: Record<string, string>) {
		ldapSaving = true; error = '';
		const cfg: Record<string, string> = { ...(extra ?? {}) };
		if (ldapHost) cfg['ldap_sync_host'] = ldapHost;
		cfg['ldap_sync_port'] = ldapPort;
		cfg['ldap_sync_tls'] = ldapTLS ? 'true' : 'false';
		if (ldapBindDn) cfg['ldap_sync_bind_dn'] = ldapBindDn;
		if (ldapPassword) cfg['ldap_sync_password_enc'] = ldapPassword; // blank = keep current (server-side)
		if (ldapBaseDn) cfg['ldap_sync_base_dn'] = ldapBaseDn;
		cfg['ldap_sync_user_filter'] = ldapFilter;
		cfg['ldap_sync_interval_min'] = ldapInterval;
		cfg['ldap_sync_auto_create_depts'] = ldapAutoDepts ? 'true' : 'false';
		try {
			await adminLDAPSetConfig(cfg);
			ldapPassword = ''; // never keep the raw secret in the form after it's sent
			showToast(t('admin.ldap.saved_toast'));
			await loadLDAPHealth();
		} catch (e) {
			error = parseError(e).message;
		} finally {
			ldapSaving = false;
		}
	}

	async function testLDAPConnection() {
		ldapTesting = true; ldapTestResult = null;
		try {
			const r = await adminLDAPTestConnection();
			ldapTestResult = { ok: true, msg: `${r.checked} found` };
		} catch (e) {
			ldapTestResult = { ok: false, msg: parseError(e).message };
		} finally {
			ldapTesting = false;
		}
	}

	async function previewLDAP() {
		ldapPreviewing = true; error = '';
		try { ldapPreview = await adminLDAPPreview(25); } catch (e) { error = parseError(e).message; } finally { ldapPreviewing = false; }
	}

	async function syncLDAPNow() {
		error = '';
		try { await adminLDAPSync(); await loadLDAPHealth(); await loadLDAPSyncLog(); showToast('Sync started'); } catch (e) { error = parseError(e).message; }
	}

	// Enabling is the one irreversible-consequence step (DESIGN.md §6): once
	// on, a directory-disabled/removed user gets disabled locally + logged out
	// on the next sync. Disabling is a plain, reversible toggle — no dialog.
	function onLDAPEnableChange(next: boolean) {
		if (next) {
			ldapEnabled = false; // revert the switch's optimistic flip until confirmed
			ldapEnableConfirmOpen = true;
		} else {
			void saveLDAPConfig({ ldap_sync_enabled: 'false' }).then(() => { ldapEnabled = false; });
		}
	}
	function confirmLDAPEnable() {
		ldapEnableConfirmOpen = false;
		void saveLDAPConfig({ ldap_sync_enabled: 'true' }).then(() => { ldapEnabled = true; });
	}
	function cancelLDAPEnable() { ldapEnableConfirmOpen = false; }

	function ldapActionVariant(a: string): 'neutral' | 'success' | 'info' | 'danger' | 'warning' {
		switch (a) {
			case 'create': return 'success';
			case 'update': return 'info';
			case 'disable': return 'danger';
			default: return 'neutral';
		}
	}
	function ldapActionLabel(a: string): string {
		switch (a) {
			case 'create': return t('admin.ldap.action_create');
			case 'update': return t('admin.ldap.action_update');
			case 'disable': return t('admin.ldap.action_disable');
			default: return t('admin.ldap.action_skip');
		}
	}
	async function toggleAuthMethod(m: AuthMethod) { try { await adminAuthMethodUpdate(m.slug, { enabled: !m.enabled, priority: m.priority }); m.enabled = !m.enabled; } catch (e) { error = parseError(e).message; } }
	async function resolveConflict(id: number, resolution: 'keep_local' | 'accept_remote') { try { await adminADResolveConflict(id, resolution); await loadConflicts(); await loadADHealth(); } catch (e) { error = parseError(e).message; } }
	async function acceptAllRemote() { try { await adminADResolveAllConflicts('accept_remote'); await loadConflicts(); await loadADHealth(); } catch (e) { error = parseError(e).message; } }
	async function keepAllLocal() { try { await adminADResolveAllConflicts('keep_local'); await loadConflicts(); await loadADHealth(); } catch (e) { error = parseError(e).message; } }

	async function doSaveGroupMappings(reason?: string) {
		gmSaving = true;
		try {
			await adminUpdateGroupMappings(gmType, gmProvider, groupMappings[gmType][gmProvider], reason);
			showToast('Group mappings saved');
		} catch (e) {
			error = parseError(e).message;
		} finally {
			gmSaving = false;
		}
	}

	function saveGroupMappings() {
		if (identityReasonRequired) {
			gmReasonPromptOpen = true;
		} else {
			void doSaveGroupMappings();
		}
	}

	function onGmReasonSubmit(reason: string) {
		gmReasonPromptOpen = false;
		void doSaveGroupMappings(reason);
	}

	function onGmReasonCancel() {
		gmReasonPromptOpen = false;
	}

	function healthColor(s: string) { return s === 'healthy' ? 'var(--success-fg)' : s === 'error' ? 'var(--danger-fg)' : 'var(--text-tertiary)'; }
	function fmtStatus(s: string): string { return s === 'healthy' ? 'Healthy' : s === 'error' ? 'Errors detected' : 'Unknown'; }
	function fmtDate(iso?: string | null): string { return iso ? new Date(iso).toLocaleString() : '—'; }

	const tabItems: TabItem[] = [
		{ id: 'overview', label: 'Identity model' },
		{ id: 'auth', label: 'Auth methods' },
		{ id: 'ad', label: 'Active directory' },
		{ id: 'ldap', label: t('admin.ldap.tab') },
		{ id: 'groups', label: 'Groups' },
	];

	const AUTH_COLUMNS: TableColumn[] = [
		{ key: 'name', label: 'Method', sortable: false },
		{ key: 'priority', label: 'Priority', sortable: false },
		{ key: 'enabled', label: 'Enabled', sortable: false },
	];

	const CONFLICT_COLUMNS: TableColumn[] = [
		{ key: 'email', label: 'User', sortable: false },
		{ key: 'field', label: 'Field', sortable: false },
		{ key: 'local', label: 'Local', sortable: false },
		{ key: 'remote', label: 'AD', sortable: false },
		{ key: 'actions', label: '', sortable: false },
	];

	const LDAP_PREVIEW_COLUMNS: TableColumn[] = [
		{ key: 'email', label: t('admin.ldap.preview_col_email'), sortable: false },
		{ key: 'displayName', label: t('admin.ldap.preview_col_name'), sortable: false },
		{ key: 'action', label: t('admin.ldap.preview_col_action'), sortable: false },
		{ key: 'reason', label: t('admin.ldap.preview_col_reason'), sortable: false },
	];

	const LDAP_LOG_COLUMNS: TableColumn[] = [
		{ key: 'when', label: t('admin.ldap.log_col_when'), sortable: false },
		{ key: 'checked', label: t('admin.ldap.log_col_checked'), sortable: false },
		{ key: 'created', label: t('admin.ldap.log_col_created'), sortable: false },
		{ key: 'updated', label: t('admin.ldap.log_col_updated'), sortable: false },
		{ key: 'disabled', label: t('admin.ldap.log_col_disabled'), sortable: false },
		{ key: 'skipped', label: t('admin.ldap.log_col_skipped'), sortable: false },
		{ key: 'errors', label: t('admin.ldap.log_col_errors'), sortable: false },
	];
</script>

<div class="sj-page">
	<header class="sj-page-head"><div class="sj-page-head-left"><h1>Identity</h1></div></header>

	{#if error}<div class="alert alert-danger">{error}</div>{/if}

	<Tabs items={tabItems} active={activeTab} onChange={(id: string) => activeTab = id} />

	<div style="margin-top:12px">
	{#if loading}
		<EmptyState title="Loading…" />
	{:else if activeTab === 'overview'}
		<IdentityModelConsole />
	{:else if activeTab === 'auth'}
		<Card title="Authentication methods" flush={true}>
			{@const rows = authMethods as unknown as Record<string, unknown>[]}
			<Table columns={AUTH_COLUMNS} rows={rows}>
				{#snippet cell(row, col)}
					{@const m = row as unknown as AuthMethod}
					{#if col.key === 'name'}<span class="sj-bold">{m.name}</span>
					{:else if col.key === 'priority'}{m.priority}
					{:else if col.key === 'enabled'}<Switch checked={m.enabled} label="" onchange={() => toggleAuthMethod(m)} disabled={!hasPermission($adminPermissions, 'identity.write')} />
					{/if}
				{/snippet}
			</Table>
		</Card>

	{:else if activeTab === 'ad'}
		<Card title="AD configuration">
			{#snippet children()}
				<div class="sj-ad-grid">
					<Input label="Domain" id="ad-domain" bind:value={adDomain} placeholder="corp.local" maxlength={253} />
					<Select label="Sync interval (min)" id="ad-interval" bind:value={adInterval}>
							<option value="5">5</option>
							<option value="15">15</option>
							<option value="30">30</option>
							<option value="60">60</option>
						</Select>
					<Input label="Bind DN" id="ad-bind" bind:value={adBindDn} placeholder="CN=svc,CN=Users,DC=corp,DC=local" maxlength={255} />
					<Input label="Password (encrypted at rest)" id="ad-pwd" type="password" autocomplete="new-password" bind:value={adPassword} placeholder="Leave empty to keep current" />
				</div>
				<div class="sj-check-row">
					<Checkbox bind:checked={adAutoDepts} label="Auto-create departments" />
					<Checkbox bind:checked={adProxyAliases} label="Sync proxyAddresses as aliases" />
				</div>
				<div class="sj-btn-row">
					<Button variant="primary" size="sm" onclick={saveADConfig} disabled={saving || !hasPermission($adminPermissions, 'identity.write')}>{saving ? 'Saving…' : 'Save config'}</Button>
					<Button variant="secondary" size="sm" onclick={testConnection} disabled={testingConn || !hasPermission($adminPermissions, 'identity.write')}>{testingConn ? 'Testing…' : 'Test connection'}</Button>
					<Button variant="secondary" size="sm" onclick={syncNow} disabled={!hasPermission($adminPermissions, 'identity.write')}>Sync now</Button>
					{#if testResult}<Badge variant={testResult.ok ? 'success' : 'danger'} label={testResult.msg} />{/if}
				</div>
			{/snippet}
		</Card>

		{#if adHealth}
			{@const h = adHealth}
			<div style="margin-top:12px">
			<Card title="AD health">
				{#snippet children()}
					<div class="sj-health-row">
						<span class="sj-health-dot" style="background:{healthColor(h.status)}"></span>
						{fmtStatus(h.status)}
						{#if h.lastSync}<span class="sj-muted">Last sync: {fmtDate(h.lastSync)}</span>{/if}
					</div>
					<div class="sj-badge-row">
						<Badge variant="neutral" label={'Checked: ' + h.checked} />
						<Badge variant="success" label={'Created: ' + h.created} />
						<Badge variant="info" label={'Updated: ' + h.updated} />
						<Badge variant="danger" label={'Disabled: ' + h.disabled} />
						<Badge variant="warning" label={'Skipped: ' + h.skipped} />
						{#if h.errors > 0}<Badge variant="danger" label={'Errors: ' + h.errors} />{/if}
					</div>
					{#if h.pendingConflicts > 0}
						<button class="sj-link-btn" onclick={() => showConflicts = !showConflicts}>
							{h.pendingConflicts} pending conflicts {showConflicts ? '▾' : '▸'}
						</button>
						{#if showConflicts && conflicts.length > 0}
							{@const cRows = conflicts as unknown as Record<string, unknown>[]}
							<div class="sj-conflicts">
								<div class="sj-btn-row"><Button variant="secondary" size="sm" onclick={acceptAllRemote} disabled={!hasPermission($adminPermissions, 'identity.write')}>Accept all remote</Button><Button variant="secondary" size="sm" onclick={keepAllLocal} disabled={!hasPermission($adminPermissions, 'identity.write')}>Keep all local</Button></div>
								<Table columns={CONFLICT_COLUMNS} rows={conflicts as unknown as Record<string, unknown>[]}>
									{#snippet cell(row2, col)}
										{@const c = row2 as unknown as SyncConflict}
										{#if col.key === 'email'}{c.email}
										{:else if col.key === 'field'}<code>{c.field}</code>
										{:else if col.key === 'local'}<span class="sj-ellipsis">{c.localValue}</span>
										{:else if col.key === 'remote'}<span class="sj-ellipsis">{c.remoteValue}</span>
										{:else if col.key === 'actions'}<div class="sj-actions"><Button variant="ghost" size="sm" onclick={() => resolveConflict(c.id, 'keep_local')} disabled={!hasPermission($adminPermissions, 'identity.write')}>Keep local</Button><Button variant="ghost" size="sm" onclick={() => resolveConflict(c.id, 'accept_remote')} disabled={!hasPermission($adminPermissions, 'identity.write')}>Accept AD</Button></div>
										{/if}
									{/snippet}
								</Table>
							</div>
						{/if}
					{/if}
				{/snippet}
			</Card>
			</div>
		{/if}

		<div style="margin-top:12px">
		<Card>
			<button class="sj-expand-btn" onclick={() => showAdvanced = !showAdvanced}>Attribute mapping {showAdvanced ? '▾' : '▸'}</button>
			{#if showAdvanced}
				<table class="sj-table">
					<thead><tr><th>AD attribute</th><th>Local field</th></tr></thead>
					<tbody>
						<tr><td>mail</td><td>email</td></tr><tr><td>displayName</td><td>display_name</td></tr><tr><td>givenName</td><td>first_name</td></tr><tr><td>sn</td><td>last_name</td></tr><tr><td>department</td><td>department_id</td></tr><tr><td>title</td><td>job_title</td></tr><tr><td>telephoneNumber</td><td>phone</td></tr><tr><td>userPrincipalName</td><td>krb5_principal</td></tr>
					</tbody>
				</table>
			{/if}
		</Card>
		</div>

	{:else if activeTab === 'groups'}
		<Card title="Group mappings">
			{#snippet children()}
				<p class="sj-hint">Map IdP groups to local distribution groups, admin roles, and departments. Applied on every SSO login.</p>
				<div class="sj-gm-selects">
					<div class="form-group" style="flex:1"><label for="gm-type">Provider type</label><select class="sj-input" id="gm-type" bind:value={gmType} onchange={() => gmProvider = ''}><option value="saml">SAML</option><option value="oidc">OIDC</option></select></div>
					<div class="form-group" style="flex:1"><label for="gm-provider">Provider</label><select class="sj-input" id="gm-provider" bind:value={gmProvider}><option value="">Select…</option>{#each Object.keys(groupMappings[gmType] || {}) as id}<option value={id}>{id}</option>{/each}</select></div>
				</div>
				{#if gmProvider}
					{@const mappings = groupMappings[gmType]?.[gmProvider] || []}
					<table class="sj-table">
						<thead><tr><th>IdP group</th><th>Dist. group ID</th><th>Admin role</th><th>Dept ID</th><th></th></tr></thead>
						<tbody>
							{#each mappings as gm, i}
								<tr>
									<td><input class="sj-input sj-input-sm" type="text" bind:value={gm.idp_group} placeholder="e.g. Engineering" /></td>
									<td><input class="sj-input sj-input-sm" type="number" bind:value={gm.distribution_group_id} placeholder="Group ID" style="width:100px" /></td>
									<td><select class="sj-input sj-input-sm" bind:value={gm.admin_role}><option value={null}>None</option><option value="super_admin">Super admin</option><option value="user_admin">User admin</option><option value="read_only">Read only</option><option value="auditor">Auditor</option></select></td>
									<td><input class="sj-input sj-input-sm" type="number" bind:value={gm.department_id} placeholder="Dept ID" style="width:100px" /></td>
									<td><Button variant="ghost" size="sm" onclick={() => { const arr = [...groupMappings[gmType][gmProvider]]; arr.splice(i, 1); groupMappings[gmType][gmProvider] = arr; groupMappings = groupMappings; }}>Remove</Button></td>
								</tr>
							{/each}
						</tbody>
					</table>
					<div class="sj-btn-row">
						<Button variant="secondary" size="sm" onclick={() => { const arr = [...(groupMappings[gmType]?.[gmProvider] || [])]; arr.push({ idp_group: '', distribution_group_id: null, admin_role: null, department_id: null }); if (!groupMappings[gmType]) groupMappings[gmType] = {}; groupMappings[gmType][gmProvider] = arr; groupMappings = groupMappings; }}>Add mapping</Button>
						<Button variant="primary" size="sm" onclick={saveGroupMappings} disabled={gmSaving || !hasPermission($adminPermissions, 'identity.write')}>{gmSaving ? 'Saving…' : 'Save'}</Button>
					</div>
				{/if}
			{/snippet}
		</Card>
	{:else if activeTab === 'ldap'}
		<Card title={t('admin.ldap.tab')}>
			{#snippet children()}
				<div class="sj-ad-grid">
					<Input label={t('admin.ldap.host')} id="ldap-host" bind:value={ldapHost} placeholder="ldap.corp.local" maxlength={253} />
					<Input label={t('admin.ldap.port')} id="ldap-port" bind:value={ldapPort} placeholder="636" maxlength={5} />
					<Input label={t('admin.ldap.bind_dn')} id="ldap-bind" bind:value={ldapBindDn} placeholder="cn=svc,dc=corp,dc=local" maxlength={255} />
					<Input label={t('admin.ldap.password')} id="ldap-pwd" type="password" autocomplete="new-password" bind:value={ldapPassword} placeholder={t('admin.ldap.password_placeholder')} />
					<Input label={t('admin.ldap.base_dn')} id="ldap-basedn" bind:value={ldapBaseDn} placeholder="dc=corp,dc=local" maxlength={255} />
					<Input label={t('admin.ldap.filter')} id="ldap-filter" bind:value={ldapFilter} placeholder="(objectClass=person)" maxlength={500} />
					<Select label={t('admin.ldap.interval')} id="ldap-interval" bind:value={ldapInterval}>
						<option value="5">5</option>
						<option value="15">15</option>
						<option value="30">30</option>
						<option value="60">60</option>
					</Select>
				</div>
				<div class="sj-check-row">
					<Checkbox bind:checked={ldapTLS} label={t('admin.ldap.tls')} />
					<Checkbox bind:checked={ldapAutoDepts} label={t('admin.ldap.auto_depts')} />
				</div>
				<div class="sj-btn-row">
					<Button variant="primary" size="sm" onclick={() => saveLDAPConfig()} disabled={ldapSaving || !hasPermission($adminPermissions, 'identity.write')}>{ldapSaving ? t('common.loading') : t('admin.ldap.save')}</Button>
					<Button variant="secondary" size="sm" onclick={testLDAPConnection} disabled={ldapTesting || !hasPermission($adminPermissions, 'identity.write')}>{ldapTesting ? t('admin.ldap.testing') : t('admin.ldap.test')}</Button>
					<Button variant="secondary" size="sm" onclick={previewLDAP} disabled={ldapPreviewing || !hasPermission($adminPermissions, 'identity.write')}>{ldapPreviewing ? t('admin.ldap.previewing') : t('admin.ldap.preview_cta')}</Button>
					<Button variant="secondary" size="sm" onclick={syncLDAPNow} disabled={!hasPermission($adminPermissions, 'identity.write')}>{t('admin.ldap.sync_now')}</Button>
					{#if ldapTestResult}<Badge variant={ldapTestResult.ok ? 'success' : 'danger'} label={ldapTestResult.msg} />{/if}
				</div>
				<div class="sj-btn-row">
					<Switch bind:checked={ldapEnabled} label={t('admin.ldap.enable')} onchange={(e) => onLDAPEnableChange(e.currentTarget.checked)} disabled={!hasPermission($adminPermissions, 'identity.write')} />
				</div>
			{/snippet}
		</Card>

		{#if ldapPreview}
			{@const lp = ldapPreview}
			<div style="margin-top:12px">
			<Card title={t('admin.ldap.preview_title')}>
				{#snippet children()}
					<p class="sj-hint">{t('admin.ldap.preview_total', { count: String(lp.total) })}</p>
					{#if lp.rows.length === 0}
						<EmptyState title={t('admin.ldap.empty_preview')} />
					{:else}
						<Table columns={LDAP_PREVIEW_COLUMNS} rows={lp.rows as unknown as Record<string, unknown>[]}>
							{#snippet cell(row, col)}
								{@const p = row as unknown as LDAPPreviewRow}
								{#if col.key === 'email'}{p.email}
								{:else if col.key === 'displayName'}{p.displayName}
								{:else if col.key === 'action'}<Badge variant={ldapActionVariant(p.action)} label={ldapActionLabel(p.action)} />
								{:else if col.key === 'reason'}<span class="sj-muted">{p.reason ?? '—'}</span>
								{/if}
							{/snippet}
						</Table>
					{/if}
				{/snippet}
			</Card>
			</div>
		{/if}

		{#if ldapHealth}
			{@const lh = ldapHealth}
			<div style="margin-top:12px">
			<Card title={t('admin.ldap.health_title')}>
				{#snippet children()}
					<div class="sj-health-row">
						<span class="sj-health-dot" style="background:{healthColor(lh.status)}"></span>
						{fmtStatus(lh.status)}
						{#if lh.lastSync}<span class="sj-muted">Last sync: {fmtDate(lh.lastSync)}</span>{/if}
					</div>
					<div class="sj-badge-row">
						<Badge variant="neutral" label={'Checked: ' + lh.checked} />
						<Badge variant="success" label={'Created: ' + lh.created} />
						<Badge variant="info" label={'Updated: ' + lh.updated} />
						<Badge variant="danger" label={'Disabled: ' + lh.disabled} />
						<Badge variant="warning" label={'Skipped: ' + lh.skipped} />
						{#if lh.errors > 0}<Badge variant="danger" label={'Errors: ' + lh.errors} />{/if}
					</div>
				{/snippet}
			</Card>
			</div>
		{/if}

		<div style="margin-top:12px">
		<Card title={t('admin.ldap.sync_log_title')} flush={true}>
			{#snippet children()}
				{#if ldapSyncLog.length === 0}
					<EmptyState title={t('admin.ldap.empty_log')} />
				{:else}
					<Table columns={LDAP_LOG_COLUMNS} rows={ldapSyncLog as unknown as Record<string, unknown>[]}>
						{#snippet cell(row, col)}
							{@const l = row as unknown as SyncLogEntry}
							{#if col.key === 'when'}{fmtDate(l.syncedAt)}
							{:else if col.key === 'checked'}{l.checked}
							{:else if col.key === 'created'}{l.created}
							{:else if col.key === 'updated'}{l.updated}
							{:else if col.key === 'disabled'}{l.disabled}
							{:else if col.key === 'skipped'}{l.skipped}
							{:else if col.key === 'errors'}{l.errors}
							{/if}
						{/snippet}
					</Table>
				{/if}
			{/snippet}
		</Card>
		</div>
	{/if}
	</div>

	<!-- Per-user sign-in activity drill-down (D-C surface 4 / Task 13) -->
	{#if selectedUserId !== null}
		<AdminSignInActivity userId={selectedUserId} />
	{/if}
</div>

{#if gmReasonPromptOpen}
	<!-- ponytail: reason prompt only when policy requires it for 'identity' area -->
	<Dialog open={gmReasonPromptOpen} title="Reason for change" onClose={onGmReasonCancel}>
		{#snippet children()}
			<ReasonPrompt
				area="identity"
				onSubmit={onGmReasonSubmit}
				onCancel={onGmReasonCancel}
				submitLabel="Save"
			/>
		{/snippet}
	</Dialog>
{/if}

{#if ldapEnableConfirmOpen}
	<!-- DESIGN.md §6: dialogs are reserved for irreversible admin actions with
	     concrete consequence copy — this is the one gated by a confirm here. -->
	<Dialog open={ldapEnableConfirmOpen} title={t('admin.ldap.enable_confirm_title')} onClose={cancelLDAPEnable}>
		{#snippet children()}
			<p>{t('admin.ldap.enable_confirm_body')}</p>
			<div class="sj-btn-row">
				<Button variant="secondary" size="sm" onclick={cancelLDAPEnable}>{t('common.cancel')}</Button>
				<Button variant="primary" size="sm" onclick={confirmLDAPEnable}>{t('admin.ldap.enable')}</Button>
			</div>
		{/snippet}
	</Dialog>
{/if}

<style>
	.sj-page { max-width: 980px; }
	.sj-page-head { display: flex; align-items: flex-start; gap: 12px; margin-bottom: 16px; }
	.sj-page-head-left { flex: 1 1 260px; min-width: 0; }
	.sj-page-head-left h1 { margin: 0; font-size: clamp(20px, 16px + 1.2vw, 24px); font-weight: 600; letter-spacing: var(--tracking-display); color: var(--text-primary); }
	.sj-bold { font-weight: 500; }
	.sj-muted { font-size: var(--text-sm); color: var(--text-tertiary); margin-left: 12px; }
	.sj-ad-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px; }
	.sj-check-row { display: flex; gap: 16px; margin-bottom: 12px; flex-wrap: wrap; }
	.sj-check-row label { display: flex; align-items: center; gap: 6px; font-size: var(--text-sm); }
	.sj-btn-row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-top: 8px; }
	.sj-health-row { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; font-size: var(--text-md); }
	.sj-health-dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
	.sj-badge-row { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 8px; }
	.sj-link-btn { margin-top: 8px; font-size: var(--text-sm); color: var(--warning-fg); cursor: pointer; border: none; background: none; padding: 0; }
	.sj-conflicts { margin-top: 8px; }
	.sj-ellipsis { display: block; max-width: 150px; overflow: hidden; text-overflow: ellipsis; }
	.sj-actions { display: flex; gap: 4px; }
	.sj-expand-btn { cursor: pointer; width: 100%; text-align: left; border: none; background: none; font: inherit; font-size: var(--text-sm); font-weight: 600; color: var(--text-primary); padding: 0; }
	.sj-table { width: 100%; border-collapse: collapse; }
	.sj-table th { text-align: left; padding: 8px 12px; font-size: var(--text-2xs); letter-spacing: var(--tracking-caps); text-transform: uppercase; color: var(--text-tertiary); font-weight: 600; border-bottom: 1px solid var(--border-default); }
	.sj-table td { padding: 8px 12px; font-size: var(--text-sm); border-bottom: 1px solid var(--border-subtle); }
	.sj-hint { font-size: var(--text-sm); color: var(--text-secondary); margin-bottom: 12px; }
	.sj-gm-selects { display: flex; gap: 16px; margin-bottom: 12px; }
	.sj-input { width: 100%; height: var(--control-height); padding: 0 10px; border: 1px solid var(--border-default); border-radius: var(--radius-sm); background: var(--surface-card); color: var(--text-primary); font: var(--font-sans); font-size: var(--text-sm); box-sizing: border-box; }
	.sj-input:focus-visible { outline: none; box-shadow: var(--focus-ring); }
	.sj-input-sm { height: var(--control-height-sm); font-size: var(--text-xs); }
	.form-group label { display: block; font-size: var(--text-sm); font-weight: 500; margin-bottom: 4px; color: var(--text-primary); }
	.form-group select.sj-input { appearance: auto; }
	.alert { padding: 8px 12px; border-radius: var(--radius-sm); margin-bottom: 12px; font-size: var(--text-sm); }
	.alert-danger { background: var(--danger-bg); color: var(--danger-fg); border: 1px solid var(--danger-fg); }
</style>
