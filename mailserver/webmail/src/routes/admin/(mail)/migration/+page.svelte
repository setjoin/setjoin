<svelte:options runes={true} />

<script lang="ts">
    import { onMount, onDestroy } from 'svelte';
    import { Checkbox, Badge } from '$lib/components/ui';
    import Icon from '$lib/components/Icon.svelte';
    import { logger } from '$lib/logger';
    import { parseError } from '$lib/errors';
    import { downloadBlob } from '$lib/utils/downloadBlob';
    import { adminPermissions, hasPermission } from '$lib/stores/auth';
    import {
        getGlobalSourceConfig,
        saveGlobalIMAPConfig,
        saveGlobalEWSConfig,
        saveM365Config,
        deleteGlobalSourceConfig,
        getM365ConnectUrl,
        type GlobalIMAPConfig,
        type GlobalEWSConfig,
        type M365Config,
    } from '$lib/admin/client';

    interface JobRow {
        id: number;
        user_id: number;
        source_type: string;
        status: string;
        conflict_strategy: string;
        progress: Record<string, unknown>;
        error_log: string[];
        started_at: string | null;
        completed_at: string | null;
        created_at: string;
    }

    interface TargetEntry {
        sourceEmail: string;
        targetEmail: string;
        password?: string;
    }

	let jobs = $state<JobRow[]>([]);
	let loading = $state(true);
	let expandedJob = $state<number | null>(null);
	let selectedJobs = $state<Set<number>>(new Set());

    let sourceType = $state<'imap' | 'ews' | 'm365'>('imap');
    let authMode = $state<'impersonation' | 'per_user'>('impersonation');

    // IMAP fields
    let imapHost = $state('');
    let imapPort = $state(993);
    let imapSSL = $state(true);

    // EWS fields
    let ewsUrl = $state('');
    let ewsDomain = $state('');
    let ewsUser = $state('');
    let ewsPassword = $state('');

    // Targets
    let targets = $state<TargetEntry[]>([]);
    let showAddForm = $state(false);
    let newSourceEmail = $state('');
    let newTargetEmail = $state('');
    let newPassword = $state('');

    // CSV preview
    let csvPreview = $state<TargetEntry[]>([]);


    // Permissions guide
    let showPermGuide = $state(false);

    // M365 global config
    let m365Cloud = $state<'global' | 'china'>('global');
    let m365ClientId = $state('');
    let m365ClientSecret = $state('');
    let m365TenantId = $state('');
    let m365Connected = $derived(m365TenantId !== '');
    let m365Saving = $state(false);
    let m365ShowPsGuide = $state(false);

    // Save state for IMAP/EWS config
    let savingSourceConfig = $state(false);
    let sourceConfigError = $state('');

    // Testing connection
    let testingConnection = $state(false);
    let connectionResult = $state<'success' | 'fail' | null>(null);
    let connectionMessage = $state('');

    // Refresh
    let autoRefresh = $state(false);
    let timer: ReturnType<typeof setInterval> | null = null;

    onMount(() => {
        loadJobs();
        loadSourceConfig();
    });

    $effect(() => {
        const hasActive = jobs.some(j => j.status === 'fetching' || j.status === 'importing' || j.status === 'pending');
        if (autoRefresh || hasActive) {
            timer = setInterval(loadJobs, 5000);
        } else if (timer) {
            clearInterval(timer);
            timer = null;
        }
        return () => { if (timer) clearInterval(timer); };
    });

    onDestroy(() => { if (timer) clearInterval(timer); });

    function switchSourceType(type: 'imap' | 'ews' | 'm365') {
        sourceType = type;
        // Reset connection test results when switching
        connectionResult = null;
        connectionMessage = '';
        sourceConfigError = '';
        loadSourceConfig();
    }

    async function loadSourceConfig() {
        try {
            const cfg = await getGlobalSourceConfig(sourceType);
            if (!cfg) return;
            if (sourceType === 'imap') {
                const c = cfg as GlobalIMAPConfig;
                imapHost = c.host || '';
                imapPort = c.port || 993;
                imapSSL = c.tls_mode === 'ssl';
            } else if (sourceType === 'ews') {
                const c = cfg as GlobalEWSConfig;
                ewsUrl = c.serverURL || '';
                if (c.username && c.username.includes('\\')) {
                    const parts = c.username.split('\\');
                    ewsDomain = parts[0];
                    ewsUser = parts[1];
                } else {
                    ewsDomain = '';
                    ewsUser = c.username || '';
                }
                // Secret hygiene (S19): the server redacts Password/ClientSecret on
                // GET, so they are NEVER bound into editable state — secret fields
                // stay blank for fresh entry (EWS save requires re-entering it).
                authMode = (c.authMode as 'impersonation' | 'per_user') || 'impersonation';
            } else if (sourceType === 'm365') {
                const c = cfg as M365Config;
                m365ClientId = c.client_id || '';
                m365TenantId = c.tenant_id || '';
                m365Cloud = (c.cloud as 'global' | 'china') || 'global';
            }
        } catch {
            // Config may not be saved yet — fields stay at defaults
        }
    }

    async function saveIMAPConfig() {
        sourceConfigError = '';
        savingSourceConfig = true;
        try {
            await saveGlobalIMAPConfig({
                host: imapHost,
                port: imapPort,
                tls_mode: imapSSL ? 'ssl' : 'none',
            });
        } catch (err) {
            logger.error('save IMAP config', err);
        } finally {
            savingSourceConfig = false;
        }
    }

    async function saveEWSConfig() {
        // The save endpoint replaces the whole stored config, so an empty password
        // would silently blank-overwrite the stored service-account secret (S19
        // data-loss guard). Require a fresh secret on every save.
        if (!ewsPassword.trim()) {
            sourceConfigError = 'Enter the service account password to save — saving without it would clear the stored credential.';
            return;
        }
        sourceConfigError = '';
        savingSourceConfig = true;
        try {
            await saveGlobalEWSConfig({
                serverURL: ewsUrl,
                username: `${ewsDomain}\\${ewsUser}`,
                password: ewsPassword,
                authMode: authMode,
                insecureSkipVerify: false,
            });
        } catch (err) {
            logger.error('save EWS config', err);
        } finally {
            savingSourceConfig = false;
        }
    }

    async function saveM365SourceConfig() {
        m365Saving = true;
        try {
            await saveM365Config({
                client_id: m365ClientId,
                client_secret: m365ClientSecret,
                cloud: m365Cloud,
            });
            // Reload config to pick up tenant_id if auto-detected
            await loadSourceConfig();
        } catch (err) {
            logger.error('save M365 config', err);
        } finally {
            m365Saving = false;
        }
    }

    async function disconnectM365() {
        try {
            await deleteGlobalSourceConfig('m365');
            m365ClientId = '';
            m365ClientSecret = '';
            m365TenantId = '';
        } catch (err) {
            logger.error('disconnect M365', err);
        }
    }

    function connectM365() {
        window.location.href = getM365ConnectUrl(m365Cloud);
    }

    async function loadJobs() {
        try {
            const res = await fetch('/api/admin/migration/jobs', { credentials: 'include' });
            if (!res.ok) return;
            jobs = await res.json();
        } catch (err) {
            logger.error('load migration jobs', err);
        } finally {
            loading = false;
        }
    }

    async function testConnection() {
        testingConnection = true;
        connectionResult = null;
        connectionMessage = '';
        try {
            const payload: Record<string, unknown> = { source_type: sourceType };
            if (sourceType === 'imap') {
                payload.host = imapHost;
                payload.port = imapPort;
                payload.ssl = imapSSL;
            } else if (sourceType === 'ews') {
                payload.url = ewsUrl;
                payload.username = `${ewsDomain}\\${ewsUser}`;
                payload.password = ewsPassword;
            }
            const res = await fetch('/api/admin/migration/test-connection', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify(payload),
            });
            if (res.ok) {
                connectionResult = 'success';
                connectionMessage = 'Connection successful';
            } else {
                connectionResult = 'fail';
                const text = await res.text();
                connectionMessage = text || 'Connection failed';
            }
        } catch (err) {
            connectionResult = 'fail';
            connectionMessage = (err as Error).message;
        } finally {
            testingConnection = false;
        }
    }

    async function startMigration() {
        if (targets.length === 0) return;
        try {
            const payload: Record<string, unknown> = {
                source_type: sourceType,
                auth_mode: authMode,
                targets: targets.map(t => ({
                    source_email: t.sourceEmail,
                    target_email: t.targetEmail,
                    password: t.password || '',
                })),
            };
            if (sourceType === 'imap') {
                payload.imap_host = imapHost;
                payload.imap_port = imapPort;
                payload.imap_ssl = imapSSL;
            } else if (sourceType === 'ews') {
                payload.ews_url = ewsUrl;
                payload.ews_username = `${ewsDomain}\\${ewsUser}`;
                payload.ews_password = ewsPassword;
            }
            const res = await fetch('/api/admin/migration/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify(payload),
            });
            if (res.ok) {
                targets = [];
                csvPreview = [];
                await loadJobs();
            }
        } catch (err) {
            logger.error('start migration', err);
        }
    }

    function addTarget() {
        if (!newSourceEmail || !newTargetEmail) return;
        if (authMode === 'per_user' && !newPassword) return;
        targets = [...targets, {
            sourceEmail: newSourceEmail.trim(),
            targetEmail: newTargetEmail.trim(),
            password: authMode === 'per_user' ? newPassword : undefined,
        }];
        newSourceEmail = '';
        newTargetEmail = '';
        newPassword = '';
        showAddForm = false;
    }

    function removeTarget(index: number) {
        targets = targets.filter((_, i) => i !== index);
    }

    function downloadTemplate() {
        const headers = authMode === 'impersonation'
            ? 'source_email,target_email'
            : 'source_email,target_email,password';
        const blob = new Blob([headers + '\n'], { type: 'text/csv' });
        downloadBlob(blob, 'migration-template.csv');
    }

    function importCSV(file: File) {
        const reader = new FileReader();
        reader.onload = () => {
            const lines = (reader.result as string).split('\n').filter(l => l.trim());
            const headers = lines[0].toLowerCase().split(',');
            const imported: TargetEntry[] = [];
            for (let i = 1; i < lines.length; i++) {
                const cols = lines[i].split(',');
                const t: TargetEntry = { sourceEmail: cols[0]?.trim() || '', targetEmail: cols[1]?.trim() || '' };
                if (cols[2]) t.password = cols[2].trim();
                if (t.sourceEmail && t.targetEmail) imported.push(t);
            }
            csvPreview = imported;
        };
        reader.readAsText(file);
    }

    function applyCSVPreview() {
        targets = [...targets, ...csvPreview];
        csvPreview = [];
    }

    function clearCSVPreview() {
        csvPreview = [];
    }

    async function cancelJob(id: number) {
        try {
            await fetch(`/api/admin/migration/jobs/${id}/cancel`, { method: 'POST', credentials: 'include' });
            await loadJobs();
        } catch (err) {
            logger.error('cancel migration job', err);
        }
    }

    async function retryJob(id: number) {
        try {
            await fetch(`/api/admin/migration/jobs/${id}/retry`, { method: 'POST', credentials: 'include' });
            await loadJobs();
        } catch (err) {
            logger.error('retry migration job', err);
        }
    }

    async function cancelSelected() {
        for (const id of selectedJobs) {
            try {
                await fetch(`/api/admin/migration/jobs/${id}/cancel`, { method: 'POST', credentials: 'include' });
            } catch (err) {
                logger.error('cancel migration job', err);
            }
        }
        selectedJobs.clear();
        await loadJobs();
    }

    function toggleJobSelection(id: number, checked: boolean) {
        if (checked) {
            selectedJobs.add(id);
        } else {
            selectedJobs.delete(id);
        }
        selectedJobs = new Set(selectedJobs);
    }

    function toggleAll(e: Event) {
        const checked = (e.target as HTMLInputElement).checked;
        if (checked) {
            selectedJobs = new Set(jobs.filter(j => j.status !== 'completed' && j.status !== 'cancelled').map(j => j.id));
        } else {
            selectedJobs = new Set();
        }
    }

    type BadgeVariant = 'neutral' | 'success' | 'warning' | 'danger' | 'info';

    function statusBadge(status: string): { label: string; variant: BadgeVariant } {
        switch (status) {
            case 'pending':   return { label: 'Pending',   variant: 'warning' };
            case 'testing':   return { label: 'Testing',   variant: 'info' };
            case 'fetching':  return { label: 'Fetching',  variant: 'info' };
            case 'importing': return { label: 'Importing', variant: 'info' };
            case 'completed': return { label: 'Completed', variant: 'success' };
            case 'cancelled': return { label: 'Cancelled', variant: 'neutral' };
            case 'failed':    return { label: 'Failed',    variant: 'danger' };
            default:          return { label: status,      variant: 'neutral' };
        }
    }

    // Aggregate stats
    const stats = $derived({
        total: jobs.length,
        done: jobs.filter(j => j.status === 'completed').length,
        running: jobs.filter(j => j.status === 'fetching' || j.status === 'importing').length,
        failed: jobs.filter(j => j.status === 'failed').length,
        pending: jobs.filter(j => j.status === 'pending' || j.status === 'testing').length,
        totalItems: jobs.reduce((sum, j) => sum + (Number(j.progress?.items_done) || 0), 0),
        totalItemsTarget: jobs.reduce((sum, j) => sum + (Number(j.progress?.items_total) || 0), 0),
        totalSpeed: jobs.reduce((sum, j) => sum + (Number(j.progress?.speed) || 0), 0),
    });

    const hasActive = $derived(jobs.some(j => j.status === 'fetching' || j.status === 'importing' || j.status === 'pending'));

    // EWS permission guide content
    const ewsPermissions = [
        { name: 'Impersonation', desc: 'ApplicationImpersonation management role. Allows the service account to access all mailboxes without per-user passwords.' },
        { name: 'EWS Enabled', desc: 'EWS must be enabled for the organization (Set-OrganizationConfig -EwsEnabled $true).' },
        { name: 'Basic Auth', desc: 'If using Basic authentication (not OAuth), it must be enabled for EWS (Set-AuthenticationPolicy -AllowBasicAuthWebServices).' },
        { name: 'Mailbox Access', desc: 'The service account needs Full Access or Impersonation rights to each source mailbox.' },
    ];
</script>

<div class="migration-dashboard" style="max-width:1100px;margin:0 auto;padding:1.5rem;display:flex;flex-direction:column;gap:1.25rem;height:100%">

    <!-- Page header -->
    <header class="page-header" style="margin-bottom:0">
        <div>
            <h1>Migration</h1>
            <p class="small">Migrate email from external sources: IMAP, Exchange EWS, Microsoft 365</p>
        </div>
        <div style="margin-left:auto;display:flex;align-items:center;gap:var(--space-2)">
            <label class="small" style="display:flex;align-items:center;gap:var(--space-1);cursor:pointer;color:var(--text-tertiary)">
                <Checkbox bind:checked={autoRefresh} label="Auto-refresh" />
            </label>
        </div>
    </header>

    <!-- Summary bar -->
    <div class="stat-grid">
        <div class="stat-card">
            <div class="stat-label">Total Jobs</div>
            <div class="stat-value">{stats.total}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Done</div>
            <div class="stat-value" style="color:var(--success-solid)">{stats.done}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Running</div>
            <div class="stat-value" style="color:var(--info-solid)">{stats.running}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Failed</div>
            <div class="stat-value" style="color:var(--danger-solid)">{stats.failed}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Pending</div>
            <div class="stat-value" style="color:var(--warning-solid)">{stats.pending}</div>
        </div>
        {#if stats.totalItems > 0}
            <div class="stat-card">
                <div class="stat-label">Throughput</div>
                <div class="stat-value" style="font-size:var(--text-lg)">{stats.totalSpeed} msg/min</div>
            </div>
        {/if}
        {#if hasActive}
            <div class="stat-card" style="border-color:var(--accent-ring)">
                <div class="stat-label">Auto-refresh Active</div>
                <div class="stat-value" style="font-size:var(--text-lg)">
                    <span class="dot dot--online" style="margin-right:var(--space-1)"></span> Live
                </div>
            </div>
        {/if}
    </div>

    <!-- Source Config card -->
    <div class="sj-pane" style="padding:var(--space-4)">
        <h2 class="h3" style="margin-bottom:var(--space-3)">Source Configuration</h2>

        <!-- Tabs -->
        <div class="tabs">
            <button class="tab" class:active={sourceType === 'imap'} onclick={() => switchSourceType('imap')}>IMAP</button>
            <button class="tab" class:active={sourceType === 'ews'} onclick={() => switchSourceType('ews')}>Exchange EWS</button>
            <button class="tab" class:active={sourceType === 'm365'} onclick={() => switchSourceType('m365')}>Microsoft 365</button>
        </div>

        {#if sourceType === 'imap'}
            <div style="display:flex;gap:var(--space-2);flex-wrap:wrap;margin-bottom:var(--space-3)">
                <div class="form-group" style="flex:2;min-width:200px">
                    <label for="imap-host">IMAP Host</label>
                    <input id="imap-host" class="input" type="text" bind:value={imapHost} placeholder="imap.example.com" />
                </div>
                <div class="form-group" style="flex:0 0 100px">
                    <label for="imap-port">Port</label>
                    <input id="imap-port" class="input" type="number" bind:value={imapPort} />
                </div>
                <div class="form-group" style="flex:0 0 auto;justify-content:flex-end">
                    <span aria-hidden="true" style="font:var(--weight-medium) var(--text-xs)/1 var(--font-sans);color:var(--text-tertiary);text-transform:uppercase;letter-spacing:var(--tracking-caps)">&nbsp;</span>
                    <label style="display:flex;align-items:center;gap:var(--space-1);height:32px;cursor:pointer;font-weight:var(--weight-regular);text-transform:none;letter-spacing:0">
                        <Checkbox bind:checked={imapSSL} label="Use SSL" />
                    </label>
                </div>
            </div>

            <!-- Action bar -->
            <div style="display:flex;gap:var(--space-2);align-items:center;margin-bottom:var(--space-3);flex-wrap:wrap">
                <button class="btn btn--secondary" onclick={saveIMAPConfig} disabled={savingSourceConfig || !hasPermission($adminPermissions, 'mail.pipeline')}>
                    {savingSourceConfig ? 'Saving...' : 'Save IMAP Config'}
                </button>
                <button class="btn btn--primary" onclick={testConnection} disabled={testingConnection}>
                    {testingConnection ? 'Testing...' : 'Test Connection'}
                </button>
                <button class="btn btn--ghost btn--sm" onclick={() => showPermGuide = !showPermGuide}>
                    {showPermGuide ? 'Hide' : 'Show'} Setup Guide
                </button>
                {#if connectionResult}
                    <Badge
                        variant={connectionResult === 'success' ? 'success' : 'danger'}
                        label="{connectionResult === 'success' ? 'Connected' : 'Failed'}: {connectionMessage}"
                    />
                {/if}
            </div>

            <!-- Collapsible setup guide -->
            {#if showPermGuide}
                <div style="background:var(--surface-sunken);border-radius:var(--radius-md);padding:var(--space-3);border:1px solid var(--border-default)">
                    <h3 class="small" style="font-weight:var(--weight-semibold);color:var(--text-secondary);margin-bottom:var(--space-2);text-transform:uppercase;letter-spacing:var(--tracking-caps)">
                        IMAP Connection Requirements
                    </h3>
                    <ul style="list-style:none;padding:0;display:flex;flex-direction:column;gap:var(--space-1)">
                        <li style="display:flex;gap:var(--space-1);align-items:flex-start">
                            <span class="badge badge--active" style="flex-shrink:0;margin-top:2px">1</span>
                            <small>Enable IMAP on the source server (Google Workspace: enable IMAP in Gmail settings; Exchange: Set-ImapSettings -ProtocolEnabled $true).</small>
                        </li>
                        <li style="display:flex;gap:var(--space-1);align-items:flex-start">
                            <span class="badge badge--active" style="flex-shrink:0;margin-top:2px">2</span>
                            <small>Ensure the IMAP port (993 for SSL, 143 for plain) is reachable from this server. Check firewalls and security groups.</small>
                        </li>
                        <li style="display:flex;gap:var(--space-1);align-items:flex-start">
                            <span class="badge badge--active" style="flex-shrink:0;margin-top:2px">3</span>
                            <small>For Google Workspace, use an App Password (not the account password). For Exchange, use the primary SMTP address as the username.</small>
                        </li>
                        <li style="display:flex;gap:var(--space-1);align-items:flex-start">
                            <span class="badge badge--active" style="flex-shrink:0;margin-top:2px">4</span>
                            <small>Migrating from Zimbra: this IMAP tab covers mail (Zimbra ships a standard IMAP server). Calendar and contacts have no IMAP equivalent — export each user's Zimbra calendar/address book as <code>.ics</code>/<code>.vcf</code> and upload them per-user from Settings &gt; Migration. See the "Zimbra" section of <code>docs/guides/M365_MIGRATION.md</code>.</small>
                        </li>
                    </ul>
                </div>
            {/if}

        {:else if sourceType === 'ews'}
            <div style="display:flex;gap:var(--space-2);flex-wrap:wrap;margin-bottom:var(--space-3)">
                <div class="form-group" style="flex:2;min-width:200px">
                    <label for="ews-url">Server URL</label>
                    <input id="ews-url" class="input" type="text" bind:value={ewsUrl} placeholder="https://mail.example.com/EWS/Exchange.asmx" />
                </div>
            </div>
            <div style="display:flex;gap:var(--space-2);flex-wrap:wrap;margin-bottom:var(--space-3)">
                <div class="form-group" style="flex:1;min-width:140px">
                    <label for="ews-domain">Domain\User</label>
                    <input id="ews-domain" class="input" type="text" bind:value={ewsDomain} placeholder="DOMAIN" style="max-width:160px" />
                    <span style="display:inline-flex;align-items:center;padding:0 var(--space-1);color:var(--text-disabled)">\</span>
                    <input class="input" type="text" bind:value={ewsUser} placeholder="username" style="flex:1" />
                </div>
                <div class="form-group" style="flex:1;min-width:140px">
                    <label for="ews-password">Password</label>
                    <input id="ews-password" class="input" type="password" autocomplete="new-password" bind:value={ewsPassword} placeholder="Service account password" />
                </div>
            </div>

            <!-- Auth mode toggle -->
            <fieldset style="border:none;padding:0;margin:0 0 var(--space-3) 0">
                <legend style="font:var(--weight-medium) var(--text-xs)/1 var(--font-sans);color:var(--text-tertiary);text-transform:uppercase;letter-spacing:var(--tracking-caps);display:block;margin-bottom:var(--space-1);padding:0">
                    Authentication Mode
                </legend>
                <div style="display:flex;gap:var(--space-4)">
                    <label style="display:flex;align-items:center;gap:var(--space-1);cursor:pointer;font-weight:var(--weight-regular);font-size:var(--text-md)">
                        <input type="radio" bind:group={authMode} value="impersonation" /> Service Account (Impersonation)
                    </label>
                    <label style="display:flex;align-items:center;gap:var(--space-1);cursor:pointer;font-weight:var(--weight-regular);font-size:var(--text-md)">
                        <input type="radio" bind:group={authMode} value="per_user" /> Per-User Credentials
                    </label>
                </div>
            </fieldset>

            <!-- Action bar -->
            <div style="display:flex;gap:var(--space-2);align-items:center;margin-bottom:var(--space-3);flex-wrap:wrap">
                <button class="btn btn--secondary" onclick={saveEWSConfig} disabled={savingSourceConfig || !hasPermission($adminPermissions, 'mail.pipeline')}>
                    {savingSourceConfig ? 'Saving...' : 'Save EWS Config'}
                </button>
                <button class="btn btn--primary" onclick={testConnection} disabled={testingConnection}>
                    {testingConnection ? 'Testing...' : 'Test Connection'}
                </button>
                <button class="btn btn--ghost btn--sm" onclick={() => showPermGuide = !showPermGuide}>
                    {showPermGuide ? 'Hide' : 'Show'} Permission Guide
                </button>
                {#if sourceConfigError}
                    <Badge variant="danger" label={sourceConfigError} />
                {/if}
                {#if connectionResult}
                    <Badge
                        variant={connectionResult === 'success' ? 'success' : 'danger'}
                        label="{connectionResult === 'success' ? 'Connected' : 'Failed'}: {connectionMessage}"
                    />
                {/if}
            </div>

            <!-- Collapsible permission guide -->
            {#if showPermGuide}
                <div style="background:var(--surface-sunken);border-radius:var(--radius-md);padding:var(--space-3);border:1px solid var(--border-default)">
                    <h3 class="small" style="font-weight:var(--weight-semibold);color:var(--text-secondary);margin-bottom:var(--space-2);text-transform:uppercase;letter-spacing:var(--tracking-caps)">
                        EWS Impersonation Setup Guide
                    </h3>
                    <ul style="list-style:none;padding:0;display:flex;flex-direction:column;gap:var(--space-1)">
                        {#each ewsPermissions as perm, i}
                            <li style="display:flex;gap:var(--space-1);align-items:flex-start">
                                <span class="badge badge--active" style="flex-shrink:0;margin-top:2px">{i + 1}</span>
                                <div>
                                    <small style="font-weight:var(--weight-semibold);color:var(--text-secondary);display:block">{perm.name}</small>
                                    <small>{perm.desc}</small>
                                </div>
                            </li>
                        {/each}
                    </ul>
                </div>
            {/if}

        {:else if sourceType === 'm365'}
            <!-- M365 Global Config -->
            <!-- Cloud selector -->
            <div class="form-group" style="margin-bottom:var(--space-3);max-width:280px">
                <label for="m365-cloud">Cloud</label>
                <select id="m365-cloud" class="input" bind:value={m365Cloud}>
                    <option value="global">Global</option>
                    <option value="china">China (21Vianet)</option>
                </select>
            </div>

            <!-- Step 1: Create app registration -->
            <div style="background:var(--surface-sunken);border-radius:var(--radius-md);padding:var(--space-3);margin-bottom:var(--space-3);border:1px solid var(--border-default)">
                <h3 class="small" style="font-weight:var(--weight-semibold);color:var(--text-secondary);margin-bottom:var(--space-1);text-transform:uppercase;letter-spacing:var(--tracking-caps)">
                    Step 1: Create app registration in Azure
                </h3>
                <a class="btn btn--secondary btn--sm" style="display:inline-flex;margin-bottom:var(--space-1)"
                   href={m365Cloud === 'china' ? 'https://portal.azure.cn/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade' : 'https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade'}
                   target="_blank" rel="noopener noreferrer">
                    {m365Cloud === 'china' ? 'Open Azure China Portal' : 'Open Azure Portal'} &rarr;
                </a>
                <ol style="padding-left:var(--space-4);margin:0;display:flex;flex-direction:column;gap:var(--space-1)">
                    <li><small>App registrations &rarr; New Registration</small></li>
                    <li><small>Add permissions: Mail.Read, Calendars.Read, Contacts.Read (Application type)</small></li>
                    <li><small>Create client secret &rarr; copy values below</small></li>
                </ol>
            </div>

            <!-- Step 2: Paste credentials -->
            <div style="background:var(--surface-sunken);border-radius:var(--radius-md);padding:var(--space-3);margin-bottom:var(--space-3);border:1px solid var(--border-default)">
                <h3 class="small" style="font-weight:var(--weight-semibold);color:var(--text-secondary);margin-bottom:var(--space-1);text-transform:uppercase;letter-spacing:var(--tracking-caps)">
                    Step 2: Paste credentials
                </h3>
                <div style="display:flex;gap:var(--space-2);flex-wrap:wrap;margin-bottom:var(--space-2)">
                    <div class="form-group" style="flex:1;min-width:240px">
                        <label for="m365-client-id">Client ID</label>
                        <input id="m365-client-id" class="input" type="text" bind:value={m365ClientId} placeholder="00000000-0000-0000-0000-000000000000" />
                    </div>
                    <div class="form-group" style="flex:1;min-width:240px">
                        <label for="m365-client-secret">Client Secret</label>
                        <input id="m365-client-secret" class="input" type="password" autocomplete="new-password" bind:value={m365ClientSecret} placeholder="Client secret value" />
                    </div>
                </div>
                <button class="btn btn--primary" onclick={saveM365SourceConfig} disabled={m365Saving || !m365ClientId || !m365ClientSecret || !hasPermission($adminPermissions, 'mail.pipeline')}>
                    {m365Saving ? 'Saving...' : 'Save'}
                </button>
            </div>

            <!-- Step 3: Grant consent -->
            <div style="background:var(--surface-sunken);border-radius:var(--radius-md);padding:var(--space-3);margin-bottom:var(--space-3);border:1px solid var(--border-default)">
                <h3 class="small" style="font-weight:var(--weight-semibold);color:var(--text-secondary);margin-bottom:var(--space-1);text-transform:uppercase;letter-spacing:var(--tracking-caps)">
                    Step 3: Grant consent
                </h3>
                <div style="display:flex;gap:var(--space-2);align-items:center;flex-wrap:wrap;margin-bottom:var(--space-1)">
                    <button class="btn btn--primary" onclick={connectM365} disabled={!m365ClientId || !m365ClientSecret}>
                        Connect to Microsoft 365 &rarr;
                    </button>
                    {#if m365Connected}
                        <span class="chip chip--accent" style="display:inline-flex;align-items:center;gap:var(--space-1)">
                            <span class="dot dot--online"></span> Connected
                        </span>
                        {#if m365TenantId}
                            <small style="color:var(--text-tertiary)">Tenant: {m365TenantId}</small>
                        {/if}
                        <button class="btn btn--destructive btn--sm" onclick={disconnectM365} disabled={!hasPermission($adminPermissions, 'mail.pipeline')}>Disconnect</button>
                    {:else}
                        <small style="color:var(--text-tertiary)">Tenant ID auto-detected from consent</small>
                    {/if}
                </div>
            </div>

            <!-- M365 RBAC PowerShell guide -->
            <div style="background:var(--surface-sunken);border-radius:var(--radius-md);padding:var(--space-3);border:1px solid var(--border-default)">
                <button class="btn btn--ghost btn--sm ps-guide-toggle"
                        onclick={() => m365ShowPsGuide = !m365ShowPsGuide}>
                    <span class="ps-guide-caret" class:ps-guide-caret--open={m365ShowPsGuide}>
                        <Icon name="ChevronRight" size={14} strokeWidth={1.75} />
                    </span>
                    Permission scoping (RBAC for Applications)
                </button>
                {#if m365ShowPsGuide}
                    <div style="margin-top:var(--space-2);padding-top:var(--space-2);border-top:1px solid var(--border-default)">
                        <small style="color:var(--text-tertiary);display:block;margin-bottom:var(--space-1)">
                            To restrict which mailboxes the app can access, use Exchange Online PowerShell:
                        </small>
                        <pre style="background:var(--surface-sunken);border:1px solid var(--border-subtle);padding:var(--space-2);border-radius:var(--radius-sm);font-family:var(--font-mono);font-size:11px;overflow-x:auto;margin:0;line-height:1.5"><code># Connect to Exchange Online
Connect-ExchangeOnline

# Create an application access policy scoped to specific mailboxes
New-ApplicationAccessPolicy -AppId "{m365ClientId || 'YOUR_APP_ID'}" \
  -PolicyScopeGroupId "group@domain.com" \
  -AccessRight RestrictAccess \
  -Description "Migration scope"

# Verify the policy
Test-ApplicationAccessPolicy -Identity "user@domain.com" -AppId "{m365ClientId || 'YOUR_APP_ID'}"</code></pre>
                        <small style="color:var(--text-tertiary);display:block;margin-top:var(--space-1)">
                            Without scoping, the application has access to all mailboxes in the tenant.
                        </small>
                    </div>
                {/if}
            </div>
        {/if}
    </div>

    <!-- Migration Targets card -->
    <div class="sj-pane" style="padding:var(--space-4)">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:var(--space-3);flex-wrap:wrap;gap:var(--space-2)">
            <h2 class="h3" style="margin-bottom:0">Migration Targets ({targets.length})</h2>
            <div style="display:flex;gap:var(--space-1);flex-wrap:wrap">
                <button class="btn btn--primary btn--sm" onclick={() => showAddForm = !showAddForm}>
                    {showAddForm ? 'Cancel' : '+ Add User'}
                </button>
                <label class="btn btn--secondary btn--sm" style="cursor:pointer">
                    Import CSV
                    <input type="file" accept=".csv" style="display:none"
                           onchange={(e) => { const f = (e.target as HTMLInputElement).files?.[0]; if (f) importCSV(f); }} />
                </label>
                <button class="btn btn--ghost btn--sm" onclick={downloadTemplate}>
                    Download Template
                </button>
            </div>
        </div>

        <!-- Inline add form -->
        {#if showAddForm}
            <div style="background:var(--surface-sunken);border-radius:var(--radius-md);padding:var(--space-3);margin-bottom:var(--space-3);border:1px solid var(--border-default)">
                <div style="display:flex;gap:var(--space-2);align-items:flex-end;flex-wrap:wrap">
                    <div class="form-group" style="flex:1;min-width:180px">
                        <label for="add-source">Source Email</label>
                        <input id="add-source" class="input" type="email" bind:value={newSourceEmail} placeholder="user@source.com" />
                    </div>
                    <div class="form-group" style="flex:1;min-width:180px">
                        <label for="add-target">Target Email</label>
                        <input id="add-target" class="input" type="email" bind:value={newTargetEmail} placeholder="user@target.com" />
                    </div>
                    {#if authMode === 'per_user'}
                        <div class="form-group" style="flex:1;min-width:180px">
                            <label for="add-password">Password</label>
                            <input id="add-password" class="input" type="password" bind:value={newPassword} placeholder="User password" />
                        </div>
                    {/if}
                    <button class="btn btn--primary btn--sm" onclick={addTarget}>Add</button>
                </div>
            </div>
        {/if}

        <!-- CSV preview -->
        {#if csvPreview.length > 0}
            <div style="background:var(--surface-sunken);border-radius:var(--radius-md);padding:var(--space-3);margin-bottom:var(--space-3);border:1px solid var(--accent-ring)">
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:var(--space-2)">
                    <small style="font-weight:var(--weight-semibold);color:var(--text-secondary)">
                        CSV Preview: {csvPreview.length} entries ready to import
                    </small>
                    <div style="display:flex;gap:var(--space-1)">
                        <button class="btn btn--primary btn--sm" onclick={applyCSVPreview}>Import All</button>
                        <button class="btn btn--ghost btn--sm" onclick={clearCSVPreview}>Discard</button>
                    </div>
                </div>
                <div style="max-height:150px;overflow:auto" class="scroll">
                    <table class="data-table">
                        <thead><tr>
                            <th>Source Email</th>
                            <th>Target Email</th>
                            {#if authMode === 'per_user'}<th>Password</th>{/if}
                        </tr></thead>
                        <tbody>
                            {#each csvPreview as row}
                                <tr>
                                    <td>{row.sourceEmail}</td>
                                    <td>{row.targetEmail}</td>
                                    {#if authMode === 'per_user'}<td>****</td>{/if}
                                </tr>
                            {/each}
                        </tbody>
                    </table>
                </div>
            </div>
        {/if}

        <!-- Targets table -->
        {#if targets.length > 0}
            <div style="margin-bottom:var(--space-3);overflow:auto" class="scroll">
                <table class="data-table">
                    <thead><tr>
                        <th style="width:40px"></th>
                        <th>Source Email</th>
                        <th>Target Email</th>
                        {#if authMode === 'per_user'}<th>Password</th>{/if}
                        <th style="width:60px"></th>
                    </tr></thead>
                    <tbody>
                        {#each targets as t, i}
                            <tr>
                                <td><span class="small" style="color:var(--text-disabled)">{i + 1}</span></td>
                                <td>{t.sourceEmail}</td>
                                <td>{t.targetEmail}</td>
                                {#if authMode === 'per_user'}<td>****</td>{/if}
                                <td>
                                    <button class="btn btn--ghost btn--sm" style="color:var(--danger-solid)"
                                            onclick={() => removeTarget(i)}>Remove</button>
                                </td>
                            </tr>
                        {/each}
                    </tbody>
                </table>
            </div>

            <button class="btn btn--primary" onclick={startMigration} disabled={targets.length === 0}>
                Start Migration ({targets.length} user{targets.length === 1 ? '' : 's'})
            </button>
        {:else if !showAddForm && csvPreview.length === 0}
            <div class="empty-state">
                <div class="empty-state-icon">+</div>
                <p>No targets configured</p>
                <small>Add users manually, import a CSV, or download the template to get started.</small>
            </div>
        {/if}
    </div>

    <!-- Jobs table -->
    <div class="sj-pane" style="padding:var(--space-4);flex:1;display:flex;flex-direction:column;min-height:0">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:var(--space-3);flex-wrap:wrap;gap:var(--space-2)">
            <h2 class="h3" style="margin-bottom:0">Migration Jobs</h2>
            {#if selectedJobs.size > 0}
                <button class="btn btn--destructive btn--sm" onclick={cancelSelected} disabled={!hasPermission($adminPermissions, 'mail.pipeline')}>
                    Cancel Selected ({selectedJobs.size})
                </button>
            {/if}
        </div>

        <div style="flex:1;overflow:auto;min-height:0" class="scroll">
            {#if loading && jobs.length === 0}
                <div class="empty-state">
                    <p>Loading...</p>
                </div>
            {:else if jobs.length === 0}
                <div class="empty-state">
                    <div class="empty-state-icon">+</div>
                    <p>No migration jobs</p>
                    <small>Configure a source and add targets above to start a migration.</small>
                </div>
            {:else}
                <table class="data-table">
                    <thead><tr>
                        <th style="width:40px">
                            <Checkbox
                                checked={selectedJobs.size > 0 && jobs.filter(j => j.status !== 'completed' && j.status !== 'cancelled').every(j => selectedJobs.has(j.id))}
                                onchange={toggleAll} />
                        </th>
                        <th style="width:50px">ID</th>
                        <th>Source</th>
                        <th>Status</th>
                        <th>Progress</th>
                        <th>Created</th>
                        <th style="width:120px">Actions</th>
                    </tr></thead>
                    <tbody>
                        {#each jobs as job}
                            {@const badge = statusBadge(job.status)}
                            <tr role="button" tabindex="0" style="cursor:pointer"
                                onclick={() => expandedJob = expandedJob === job.id ? null : job.id}
                                onkeypress={(e) => e.key === 'Enter' && (expandedJob = expandedJob === job.id ? null : job.id)}>
                                <td onclick={(e) => e.stopPropagation()}>
                                    {#if job.status !== 'completed' && job.status !== 'cancelled'}
                                        <Checkbox
                                            checked={selectedJobs.has(job.id)}
                                            onchange={(e) => toggleJobSelection(job.id, (e.target as HTMLInputElement).checked)} />
                                    {/if}
                                </td>
                                <td class="small">{job.id}</td>
                                <td>{job.source_type}</td>
                                <td><Badge variant={badge.variant} label={badge.label} /></td>
                                <td>
                                    {#if job.progress && Object.keys(job.progress).length > 0}
                                        <div style="display:flex;align-items:center;gap:var(--space-1)">
                                            <div style="flex:1;max-width:120px;background:var(--border-default);border-radius:4px;height:4px">
                                                <div style="background:var(--accent);height:100%;border-radius:4px;width:{String(job.progress.pct || 0)}%"></div>
                                            </div>
                                            <small>{String(job.progress.pct || 0)}%</small>
                                        </div>
                                    {:else}
                                        <small style="color:var(--text-disabled)">&mdash;</small>
                                    {/if}
                                </td>
                                <td class="small">{new Date(job.created_at).toLocaleString()}</td>
                                <td>
                                    <div style="display:flex;gap:var(--space-1)">
                                        {#if job.status !== 'completed' && job.status !== 'cancelled'}
                                            <button class="btn btn--ghost btn--sm" style="color:var(--danger-solid)"
                                                    onclick={(e) => { e.stopPropagation(); cancelJob(job.id); }}
                                                    disabled={!hasPermission($adminPermissions, 'mail.pipeline')}>
                                                Cancel
                                            </button>
                                        {/if}
                                        {#if job.status === 'failed' || job.status === 'cancelled'}
                                            <button class="btn btn--ghost btn--sm"
                                                    onclick={(e) => { e.stopPropagation(); retryJob(job.id); }}
                                                    disabled={!hasPermission($adminPermissions, 'mail.pipeline')}>
                                                Retry
                                            </button>
                                        {/if}
                                    </div>
                                </td>
                            </tr>
                            <!-- Expandable row -->
                            {#if expandedJob === job.id}
                                <tr>
                                    <td colspan="7" style="padding:0;border-bottom:1px solid var(--border-default)">
                                        <div style="padding:var(--space-2) var(--space-4);background:var(--surface-sunken)">
                                            <!-- Progress detail -->
                                            {#if job.progress && Object.keys(job.progress).length > 0}
                                                <div style="padding:0.5rem 0">
                                                    <div style="background:var(--border-default);border-radius:4px;height:6px;margin-bottom:0.25rem">
                                                        <div style="background:var(--accent);height:100%;border-radius:4px;width:{String(job.progress.pct || 0)}%"></div>
                                                    </div>
                                                    <small style="color:var(--text-tertiary)">
                                                        {String(job.progress.items_done || 0)}/{String(job.progress.items_total || 0)} items &middot;
                                                        {String(job.progress.speed || 0)} msg/min &middot;
                                                        ETA {String(job.progress.eta || '—')}
                                                    </small>
                                                </div>
                                            {/if}

                                            <!-- Details -->
                                            <dl style="display:grid;grid-template-columns:140px 1fr;gap:var(--space-1) var(--space-2);margin-top:var(--space-2)">
                                                <dt class="small" style="font-weight:var(--weight-semibold);color:var(--text-secondary)">Source Type</dt>
                                                <dd class="small">{job.source_type}</dd>
                                                <dt class="small" style="font-weight:var(--weight-semibold);color:var(--text-secondary)">Conflict Strategy</dt>
                                                <dd class="small">{job.conflict_strategy || 'Default'}</dd>
                                                {#if job.started_at}
                                                    <dt class="small" style="font-weight:var(--weight-semibold);color:var(--text-secondary)">Started</dt>
                                                    <dd class="small">{new Date(job.started_at).toLocaleString()}</dd>
                                                {/if}
                                                {#if job.completed_at}
                                                    <dt class="small" style="font-weight:var(--weight-semibold);color:var(--text-secondary)">Completed</dt>
                                                    <dd class="small">{new Date(job.completed_at).toLocaleString()}</dd>
                                                {/if}
                                            </dl>

                                            <!-- Error log -->
                                            {#if job.error_log && job.error_log.length > 0}
                                                <div style="margin-top:var(--space-2)">
                                                    <small style="font-weight:var(--weight-semibold);color:var(--danger-solid);display:block;margin-bottom:var(--space-1)">Errors</small>
                                                    <ul style="list-style:none;padding:0;display:flex;flex-direction:column;gap:var(--space-1)">
                                                        {#each job.error_log as err}
                                                            <li>
                                                                <small style="color:var(--danger-fg);background:var(--danger-bg);padding:var(--space-1) var(--space-1);border-radius:var(--radius-sm);display:block;font-family:var(--font-mono);font-size:11px">{err}</small>
                                                            </li>
                                                        {/each}
                                                    </ul>
                                                </div>
                                            {/if}
                                        </div>
                                    </td>
                                </tr>
                            {/if}
                        {/each}
                    </tbody>
                </table>
            {/if}
        </div>
    </div>

</div>

<style>
    .tabs {
        display: flex;
        gap: 0;
        border-bottom: 1px solid var(--border-strong);
        margin-bottom: var(--space-3);
    }
    .tab {
        padding: var(--space-1) var(--space-3);
        border: none;
        border-bottom: 2px solid transparent;
        background: none;
        cursor: pointer;
        font-family: var(--font-sans);
        font-size: var(--text-md);
        font-weight: var(--weight-medium);
        color: var(--text-tertiary);
        transition: color 0.15s, border-color 0.15s;
    }
    .tab:hover {
        color: var(--text-primary);
    }
    .tab.active {
        color: var(--text-primary);
        border-bottom-color: var(--info-solid);
    }
    .dot {
        display: inline-block;
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: var(--text-disabled);
    }
    .dot--online {
        background: var(--success-solid);
    }
	h1 { font-size: 1.5rem; margin-bottom: 1rem; }
	table {
		width: 100%;
		border-collapse: collapse;
		font-size: var(--text-sm);
	}
	th, td {
		text-align: left;
		padding: 0.5rem;
		border-bottom: 1px solid var(--border-default);
	}
	th {
		font-weight: var(--weight-semibold);
		background: var(--surface-sunken);
	}
	/* PS guide toggle button */
	.ps-guide-toggle {
		display: flex;
		align-items: center;
		gap: var(--space-1);
		margin-bottom: 0;
		padding: 0;
		color: var(--text-secondary);
	}
	.ps-guide-caret {
		display: inline-flex;
		transition: transform var(--duration-fast) var(--ease-out);
	}
	.ps-guide-caret--open {
		transform: rotate(90deg);
	}
</style>
