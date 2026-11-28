<svelte:options runes={true} />

<script lang="ts">
    import { Checkbox } from '$lib/components/ui';
    import Icon from '$lib/components/Icon.svelte';
    import { adminFetch } from '$lib/admin/client';
    import { adminPermissions, hasPermission } from '$lib/stores/auth';

    let keywords = $state('');
    let fromAddr = $state('');
    let dateFrom = $state('');
    let dateTo = $state('');
    let loading = $state(false);
    let error = $state('');
    let results = $state<any[]>([]);
    let searchID = $state<number | null>(null);
    let searchStatus = $state('');
    let selected = $state<Set<number>>(new Set());

    async function startSearch() {
        if (!keywords && !fromAddr) return;
        loading = true; results = []; error = '';
        try {
            const body: Record<string, unknown> = {
                name: `Search ${new Date().toLocaleString()}`,
                keywords,
                fromAddr: fromAddr || undefined,
            };
            if (dateFrom) body.dateFrom = dateFrom;
            if (dateTo) body.dateTo = dateTo;
            const res = await adminFetch('/admin/ediscovery/search', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
            });
            if (!res.ok) throw new Error(`Search failed (${res.status})`);
            const data = await res.json();
            searchID = data.id;
            searchStatus = 'running';
            setTimeout(pollSearch, 2000);
        } catch (e) {
            error = e instanceof Error ? e.message : 'Search failed';
            loading = false;
        }
    }

    async function pollSearch() {
        if (!searchID) return;
        try {
            const res = await adminFetch(`/admin/ediscovery/${searchID}`);
            if (!res.ok) throw new Error(`Search status failed (${res.status})`);
            const data = await res.json();
            searchStatus = data.search?.status || '';
            results = data.results || [];
            if (searchStatus === 'complete') loading = false;
            else if (searchStatus === 'pending' || searchStatus === 'running') setTimeout(pollSearch, 2000);
        } catch (e) {
            error = e instanceof Error ? e.message : 'Search status failed';
            loading = false;
        }
    }

    function toggleSelect(id: number) {
        const s = new Set(selected);
        if (s.has(id)) s.delete(id); else s.add(id);
        selected = s;
    }

    async function holdSelected() {
        if (selected.size === 0) return;
        if (!confirm(`Place ${selected.size} messages on litigation hold?`)) return;
        error = '';
        try {
            const res = await adminFetch('/admin/ediscovery/hold', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ids: Array.from(selected) }),
            });
            if (!res.ok) throw new Error(`Hold failed (${res.status})`);
            const data = await res.json(); alert(`Held ${data.held} of ${data.total} messages`);
        } catch (e) {
            error = e instanceof Error ? e.message : 'Hold failed';
        }
    }

    async function exportSelected() {
        if (selected.size === 0) return;
        const ids = Array.from(selected).join(',');
        window.open(`/admin/ediscovery/export?ids=${ids}`, '_blank');
    }
</script>

<header class="page-header">
    <h1>eDiscovery</h1>
</header>

{#if error}<div class="alert alert-danger" role="alert">{error}</div>{/if}

<div class="search-bar">
    <input class="input" type="search" placeholder="Keywords (body/subject search)" bind:value={keywords} />
    <input class="input" type="text" placeholder="From address" bind:value={fromAddr} />
    <input class="input" type="date" bind:value={dateFrom} />
    <input class="input" type="date" bind:value={dateTo} />
    <button class="btn btn-primary" onclick={startSearch} disabled={loading || !hasPermission($adminPermissions, 'compliance.write')}>Search</button>
</div>

{#if loading && !results.length}
    <div class="empty-state">
        <Icon name="FileSearch" size={24} strokeWidth={1.75} />
        <div>Searching... {searchStatus}</div>
    </div>
{:else if results.length === 0 && !loading}
    <div class="empty-state">
        <Icon name="FileSearch" size={24} strokeWidth={1.75} />
        <div>Enter keywords and click Search to find messages across all mailboxes.</div>
    </div>
{:else}
    <div class="card">
        <div class="card-header" style="display:flex;justify-content:space-between;align-items:center">
            <span>{results.length} results ({searchStatus})</span>
            <div style="display:flex;gap:0.5rem">
                <button class="btn btn-ghost btn-sm" onclick={holdSelected} disabled={selected.size === 0 || !hasPermission($adminPermissions, 'compliance.write')}>
                    Hold ({selected.size})
                </button>
                <button class="btn btn-primary btn-sm" onclick={exportSelected} disabled={selected.size === 0}>
                    Export ({selected.size})
                </button>
            </div>
        </div>
        <table class="data-table">
            <thead><tr><th>#</th><th>Subject</th><th>From</th><th>Mailbox</th><th>Date</th></tr></thead>
            <tbody>
                {#each results as r}
                    <tr>
                        <td><Checkbox checked={selected.has(r.id)} onchange={() => toggleSelect(r.id)} /></td>
                        <td>{r.subject}</td>
                        <td>{r.from}</td>
                        <td>{r.mailbox}</td>
                        <td>{new Date(r.receivedAt).toLocaleDateString()}</td>
                    </tr>
                {/each}
            </tbody>
        </table>
    </div>
{/if}
