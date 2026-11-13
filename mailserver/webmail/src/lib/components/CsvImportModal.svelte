<svelte:options runes={true} />

<script lang="ts">
	import { Dialog, Button, Select } from '$lib/components/ui';
	import { t } from '$lib/i18n';
	import { parseError } from '$lib/errors';

	let {
		open = false,
		addressBookId = '',
		onClose,
		onDone
	}: {
		open?: boolean;
		addressBookId?: string;
		onClose: () => void;
		onDone?: () => void;
	} = $props();

	// Target fields the server maps CSV columns onto. Index -1 = not imported.
	const FIELDS = [
		'firstName',
		'lastName',
		'fullName',
		'email',
		'company',
		'jobTitle',
		'phone',
		'notes'
	] as const;
	type FieldKey = (typeof FIELDS)[number];

	type Mapping = Partial<Record<FieldKey, number>>;

	let step = $state<'choose' | 'map' | 'result'>('choose');
	// vCard (.vcf) is self-describing — it skips the column-map step, but reuses the
	// same 'map' step for the strategy picker + import button, then the result UI.
	let format = $state<'csv' | 'vcf'>('csv');
	let file = $state<File | null>(null);
	let headers = $state<string[]>([]);
	let mapping = $state<Mapping>({});
	let sample = $state<string[][]>([]);
	let strategy = $state<'skip' | 'overwrite'>('skip');
	let busy = $state(false);
	let error = $state('');
	let result = $state<{ imported: number; skipped: number; errors: string[] } | null>(null);

	// Reset the wizard each time it opens.
	$effect(() => {
		if (!open) return;
		step = 'choose';
		format = 'csv';
		file = null;
		headers = [];
		mapping = {};
		sample = [];
		strategy = 'skip';
		busy = false;
		error = '';
		result = null;
	});

	function columnOptions() {
		return [
			{ value: '-1', label: t('contacts.csv.none') },
			...headers.map((h, i) => ({ value: String(i), label: h }))
		];
	}

	function fieldLabel(f: FieldKey): string {
		return t(`contacts.csv.field.${f}`);
	}

	async function onFile(e: Event) {
		const input = e.currentTarget as HTMLInputElement;
		const f = input.files?.[0] ?? null;
		file = f;
		if (!f) return;
		// vCard is self-describing — no preview/column-map. Straight to strategy.
		if (f.name.toLowerCase().endsWith('.vcf')) {
			format = 'vcf';
			error = '';
			step = 'map';
			return;
		}
		format = 'csv';
		busy = true;
		error = '';
		try {
			const body = new FormData();
			body.append('file', f);
			const res = await fetch('/api/contacts/import/csv/preview', { method: 'POST', body });
			if (!res.ok) throw new Error(`Preview failed (${res.status})`);
			const data = await res.json();
			headers = data.headers ?? [];
			mapping = data.mapping ?? {};
			sample = data.sample ?? [];
			step = 'map';
		} catch (err) {
			error = parseError(err).message;
		} finally {
			busy = false;
		}
	}

	function setColumn(field: FieldKey, value: string) {
		const idx = parseInt(value, 10);
		mapping = { ...mapping, [field]: idx };
	}

	async function doImport() {
		if (busy || !file) return;
		busy = true;
		error = '';
		try {
			const body = new FormData();
			body.append('file', file);
			body.append('addressBookId', addressBookId);
			body.append('strategy', strategy);
			if (format === 'csv') body.append('mapping', JSON.stringify(mapping));
			const endpoint = format === 'vcf' ? '/api/contacts/import/vcf' : '/api/contacts/import/csv';
			const res = await fetch(endpoint, { method: 'POST', body });
			if (!res.ok) throw new Error(`Import failed (${res.status})`);
			result = await res.json();
			step = 'result';
			onDone?.();
		} catch (err) {
			error = parseError(err).message;
		} finally {
			busy = false;
		}
	}
</script>

<Dialog {open} title={t('contacts.import.title')} onClose={onClose} wide>
	{#snippet children()}
		<div class="csv-body">
			{#if error}<div class="csv-error" role="alert">{error}</div>{/if}

			{#if step === 'choose'}
				<label class="csv-file" for="csv-file-input">{t('contacts.import.choose_file')}</label>
				<input
					id="csv-file-input"
					type="file"
					accept=".csv,.vcf,text/csv,text/vcard"
					onchange={onFile}
					disabled={busy}
				/>
			{:else if step === 'map'}
				{#if format === 'vcf'}
					<div class="csv-section-label">{t('contacts.vcf.hint')}</div>
				{:else}
				<div class="csv-section-label">{t('contacts.csv.map_columns')}</div>
				<table class="csv-map">
					<thead>
						<tr>
							<th>{t('contacts.csv.field')}</th>
							<th>{t('contacts.csv.column')}</th>
						</tr>
					</thead>
					<tbody>
						{#each FIELDS as field}
							<tr>
								<td>{fieldLabel(field)}</td>
								<td>
									<Select
										value={String(mapping[field] ?? -1)}
										options={columnOptions()}
										aria-label={field}
										onchange={(e: Event) =>
											setColumn(field, (e.currentTarget as HTMLSelectElement).value)}
									/>
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
				{/if}

				<div class="csv-strategy">
					<Select
						label={t('contacts.csv.strategy')}
						bind:value={strategy}
						options={[
							{ value: 'skip', label: t('contacts.csv.strategy_skip') },
							{ value: 'overwrite', label: t('contacts.csv.strategy_overwrite') }
						]}
					/>
				</div>

				{#if sample.length}
					<div class="csv-section-label">{t('contacts.csv.sample')}</div>
					<table class="csv-sample">
						<thead>
							<tr>{#each headers as h}<th>{h}</th>{/each}</tr>
						</thead>
						<tbody>
							{#each sample as row}
								<tr>{#each row as cell}<td>{cell}</td>{/each}</tr>
							{/each}
						</tbody>
					</table>
				{/if}
			{:else if step === 'result' && result}
				<div class="csv-result">
					{t('contacts.csv.result', {
						imported: String(result.imported),
						skipped: String(result.skipped)
					})}
				</div>
				{#if result.errors?.length}
					<ul class="csv-errors">
						{#each result.errors as err}<li>{err}</li>{/each}
					</ul>
				{/if}
			{/if}
		</div>
	{/snippet}
	{#snippet footer()}
		{#if step === 'map'}
			<Button variant="primary" disabled={busy} onclick={doImport}>
				{busy ? t('contacts.csv.importing') : t('contacts.csv.import')}
			</Button>
		{/if}
		<Button variant="secondary" onclick={onClose}>{t('common.close')}</Button>
	{/snippet}
</Dialog>

<style>
	.csv-body {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}
	.csv-error {
		color: var(--danger-fg);
		background: var(--danger-bg);
		font-size: var(--text-sm);
		padding: 0.4rem 0.6rem;
		border-radius: var(--radius-sm);
	}
	.csv-file {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
	}
	.csv-section-label {
		font-size: var(--text-sm);
		font-weight: var(--weight-medium);
		color: var(--text-primary);
	}
	.csv-map,
	.csv-sample {
		width: 100%;
		border-collapse: collapse;
		font-size: var(--text-sm);
	}
	.csv-map th,
	.csv-map td,
	.csv-sample th,
	.csv-sample td {
		text-align: left;
		padding: 0.25rem 0.4rem;
		border-bottom: 1px solid var(--border-subtle);
		color: var(--text-primary);
	}
	.csv-sample th {
		color: var(--text-tertiary);
		font-weight: var(--weight-medium);
	}
	.csv-map td:first-child {
		width: 40%;
	}
	.csv-strategy {
		max-width: 16rem;
	}
	.csv-result {
		font-size: var(--text-md);
		color: var(--text-primary);
	}
	.csv-errors {
		margin: 0;
		padding-left: 1.1rem;
		font-size: var(--text-sm);
		color: var(--danger-fg);
	}
</style>
