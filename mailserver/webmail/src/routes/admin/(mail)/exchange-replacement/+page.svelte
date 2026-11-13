<svelte:options runes={true} />

<script lang="ts">
  import { onMount } from 'svelte';
  import { adminPermissions, hasPermission } from '$lib/stores/auth';
  import { parseError } from '$lib/errors';
  import {
    adminExchangeRegistry, adminExchangeProjects, adminExchangeRuns,
    adminCreateExchangeProject, adminCreateExchangeRun, adminExchangeTransitionRun, adminExchangeDecision, adminExchangeAttest,
    adminExchangeResolveClaims, adminExchangeAudit, adminExchangePublish, adminExchangeDelete,
    type ExchangeRegistryProjection, type ExchangeAssessmentProject,
    type ExchangeAssessmentRun,
  } from '$lib/admin/client';

  type View = 'overview' | 'assessments' | 'outcomes' | 'mappings' | 'documents' | 'settings';
  const views: Array<{ id: View; zh: string; en: string }> = [
    { id: 'overview', zh: '概览', en: 'Overview' },
    { id: 'assessments', zh: '评估运行', en: 'Assessments' },
    { id: 'outcomes', zh: '功能结果', en: 'Outcomes' },
    { id: 'mappings', zh: '映射', en: 'Mappings' },
    { id: 'documents', zh: '文档', en: 'Documents' },
    { id: 'settings', zh: '设置', en: 'Settings' },
  ];
  const permissionKeys = ['read','run','decide','attest','audit','publish','delete'].map((v) => `exchange.assessment.${v}`);

  let loading = $state(true);
  let error = $state('');
  let registry = $state<ExchangeRegistryProjection | null>(null);
  let projects = $state<ExchangeAssessmentProject[]>([]);
  let runs = $state<ExchangeAssessmentRun[]>([]);
  let selectedProjectId = $state<number | null>(null);
  let selectedView = $state<View>('overview');
  let locale = $state<'zh' | 'en'>('zh');
  let announced = $state('');
  let actionError = $state('');
  let actionBusy = $state(false);
  let projectDomainId = $state(0);
  let projectName = $state('');
  let nextRunState = $state('preflight');
  let decisionCapability = $state('');
  let decisionMapping = $state('native');
  let decisionValue = $state('accepted');
  let decisionReason = $state('');
  let attestationKind = $state('completeness');
  let attestationDigest = $state('');
  let auditSnapshot = $state<{claims: Record<string, unknown>[]; attestations: Record<string, unknown>[]; evidence: Record<string, unknown>[]; publications: Record<string, unknown>[]} | null>(null);
  let publishDigest = $state('');
  let deletionScope = $state<'artifact'|'run'|'project'>('run');
  let deletionArtifactId = $state(0);
  let deletionReason = $state('');
  let selectedProject = $derived(projects.find((p) => p.id === selectedProjectId) ?? null);
  let latestRun = $derived(runs[0] ?? null);

  function copy(zh: string, en: string): string {
    return locale === 'zh' ? zh : en;
  }

  async function load(): Promise<void> {
    loading = true;
    error = '';
    try {
      [registry, projects] = await Promise.all([adminExchangeRegistry(), adminExchangeProjects()]);
      selectedProjectId = selectedProjectId ?? projects[0]?.id ?? null;
      runs = selectedProjectId ? await adminExchangeRuns(selectedProjectId) : [];
      announced = copy('Exchange 替代评估已加载', 'Exchange replacement assessment loaded');
    } catch (cause) {
      error = parseError(cause).message;
      announced = error;
    } finally {
      loading = false;
    }
  }

  async function selectProject(value: string): Promise<void> {
    selectedProjectId = Number(value) || null;
    runs = selectedProjectId ? await adminExchangeRuns(selectedProjectId) : [];
  }

  function label(item: { zh: string; en: string }): string {
    return item[locale];
  }

  function permissionStatus(permission: string): string {
    if (hasPermission($adminPermissions, permission)) return copy('已授予', 'Granted');
    return copy('未授予', 'Not granted');
  }

  function selectedProjectLabel(): string {
    if (selectedProject) return `${selectedProject.name} · ${selectedProject.state}`;
    return copy('未选择项目', 'No project selected');
  }

  async function act(work: () => Promise<unknown>, success: string): Promise<void> {
    actionBusy = true;
    actionError = '';
    try {
      await work();
      announced = success;
      await load();
    } catch (cause) {
      actionError = parseError(cause).message;
      announced = actionError;
    } finally {
      actionBusy = false;
    }
  }

  async function createRun(): Promise<void> {
    const currentRegistry = registry;
    const projectId = selectedProjectId;
    const cell = currentRegistry?.supportCells[0];
    if (!cell || !projectId || !currentRegistry) return;

    await act(() => adminCreateExchangeRun(projectId, {
      supportCellId: cell.id,
      supportCellDigest: cell.digest,
      registryVersion: currentRegistry.registryVersion,
      registryDigest: currentRegistry.sourceDigest,
      catalogVersion: currentRegistry.catalogVersion,
      collectorVersion: cell.collectorVersion,
    }), copy('运行已创建', 'Run created'));
  }

  async function createProject(): Promise<void> {
    if (projectDomainId < 1 || !projectName.trim()) return;
    await act(
      () => adminCreateExchangeProject({ domainId: projectDomainId, name: projectName.trim() }),
      copy('项目已创建', 'Project created'),
    );
  }

  async function transitionRun(): Promise<void> {
    const run = latestRun;
    if (!run) return;
    await act(
      () => adminExchangeTransitionRun(run.id, run.generation, nextRunState),
      copy('运行状态已更新', 'Run state updated'),
    );
  }

  async function decide(): Promise<void> {
    const run = latestRun;
    if (!run || !decisionCapability || !decisionReason.trim()) return;
    await act(() => adminExchangeDecision(run.id, {
      expectedGeneration: run.generation,
      capabilityId: decisionCapability,
      outcomeMapping: decisionMapping,
      decision: decisionValue,
      reason: decisionReason.trim(),
    }), copy('决定已记录', 'Decision recorded'));
  }

  async function attest(): Promise<void> {
    const run = latestRun;
    if (!run || !/^[0-9a-f]{64}$/.test(attestationDigest)) return;
    await act(() => adminExchangeAttest(run.id, {
      kind: attestationKind,
      subjectDigest: attestationDigest,
      statement: { basis: 'explicit administrator attestation' },
    }), copy('证明已记录', 'Attestation recorded'));
  }

  async function resolveClaims(): Promise<void> {
    const run = latestRun;
    if (!run) return;
    await act(async () => {
      await adminExchangeResolveClaims(run.id, run.generation);
      auditSnapshot = await adminExchangeAudit(run.id);
    }, copy('声明快照已解析', 'Claim snapshot resolved'));
  }

  async function publish(): Promise<void> {
    const run = latestRun;
    if (!run || !/^[0-9a-f]{64}$/.test(publishDigest)) return;
    await act(
      () => adminExchangePublish(run.id, publishDigest),
      copy('签名发布回执已记录', 'Signed publication receipt recorded'),
    );
  }

  async function requestDeletion(): Promise<void> {
    const projectId = selectedProjectId;
    const reason = deletionReason.trim();
    if (!projectId || !reason) return;

    const input: Parameters<typeof adminExchangeDelete>[1] = { scope: deletionScope, reason };
    if (deletionScope !== 'project') input.runId = latestRun?.id;
    if (deletionScope === 'artifact') input.artifactId = deletionArtifactId;
    await act(
      () => adminExchangeDelete(projectId, input),
      copy('删除请求已记录', 'Deletion requested'),
    );
  }
  onMount(load);
</script>

<svelte:head><title>Exchange replacement · Setjoin</title></svelte:head>

<section class="page" aria-labelledby="exchange-title">
  <header class="hero">
    <div>
      <p class="eyebrow">V1A · Assessment only</p>
      <h1 id="exchange-title">{locale === 'zh' ? 'Exchange 替代评估' : 'Exchange replacement assessment'}</h1>
      <p class="warning">{locale === 'zh' ? '仅用于评估——尚未证明替代就绪。未知、部分完成和过期证据不会被计为支持。' : 'Assessment only — replacement readiness not established. Unknown, partial, and stale evidence never count as support.'}</p>
    </div>
    <button class="locale" onclick={() => locale = locale === 'zh' ? 'en' : 'zh'}>{locale === 'zh' ? 'EN' : '中文'}</button>
  </header>

  <div class="selectors">
    <label>{locale === 'zh' ? '项目' : 'Project'}
      <select value={selectedProjectId ?? ''} onchange={(e) => selectProject(e.currentTarget.value)} disabled={projects.length === 0}>
        {#if projects.length === 0}<option value="">{locale === 'zh' ? '尚无项目' : 'No projects yet'}</option>{/if}
        {#each projects as project}<option value={project.id}>{project.name}</option>{/each}
      </select>
    </label>
    <div class="context"><span>{locale === 'zh' ? '当前运行' : 'Current run'}</span><strong>{latestRun ? `#${latestRun.id} · ${latestRun.state}` : '—'}</strong></div>
    <div class="context"><span>{locale === 'zh' ? '注册表' : 'Registry'}</span><strong>{registry ? `v${registry.registryVersion}` : '—'}</strong></div>
  </div>

  <nav class="tabs" aria-label={locale === 'zh' ? '评估视图' : 'Assessment views'}>
    {#each views as view}
      <button class:active={selectedView === view.id} aria-current={selectedView === view.id ? 'page' : undefined} onclick={() => selectedView = view.id}>{label(view)}</button>
    {/each}
  </nav>

  <p class="sr-only" aria-live="polite">{announced}</p>
  {#if actionError}<div class="state error" role="alert"><strong>{locale==='zh'?'操作被拒绝':'Action refused'}</strong><span>{actionError}</span></div>{/if}
  {#if loading}
    <div class="state" role="status">{locale === 'zh' ? '正在加载评估上下文…' : 'Loading assessment context…'}</div>
  {:else if error}
    <div class="state error" role="alert"><strong>{locale === 'zh' ? '无法加载' : 'Unable to load'}</strong><span>{error}</span><button onclick={load}>{locale === 'zh' ? '重试' : 'Retry'}</button></div>
  {:else if selectedView === 'overview'}
    <div class="grid">
      <article><h2>{locale === 'zh' ? '评估状态' : 'Assessment status'}</h2><p class="metric">{latestRun?.state ?? (locale === 'zh' ? '未开始' : 'Not started')}</p><p>{runs.length} {locale === 'zh' ? '个不可变运行' : 'immutable runs'}</p></article>
      <article><h2>{locale === 'zh' ? '映射覆盖' : 'Mapping coverage'}</h2><p class="metric">—</p><p>{locale === 'zh' ? '尚无经审核的映射快照' : 'No reviewed mapping snapshot'}</p></article>
      <article><h2>{locale === 'zh' ? '声明状态' : 'Claim state'}</h2><p class="metric">OFF</p><p>{locale === 'zh' ? '发布默认关闭，必须满足证据门槛' : 'Publishing is off until evidence gates pass'}</p></article>
    </div>
  {:else if selectedView === 'assessments'}
    <section class="panel"><div class="section-title"><h2>{locale === 'zh' ? '不可变运行' : 'Immutable runs'}</h2>{#if hasPermission($adminPermissions,'exchange.assessment.run')}<button disabled={actionBusy||!selectedProjectId} onclick={createRun}>{locale==='zh'?'新建运行':'Create run'}</button>{/if}</div>{#if runs.length === 0}<div class="state">{locale === 'zh' ? '尚无运行。具备运行权限的管理员可在这里或通过 CLI 创建。' : 'No runs. An administrator with run permission can create one here or through CLI.'}</div>{:else}<div class="table-wrap"><table><thead><tr><th>ID</th><th>{locale === 'zh' ? '状态' : 'State'}</th><th>{locale === 'zh' ? '支持单元' : 'Support cell'}</th><th>{locale === 'zh' ? '代次' : 'Generation'}</th><th>{locale === 'zh' ? '更新时间' : 'Updated'}</th></tr></thead><tbody>{#each runs as run}<tr><td>#{run.id}</td><td><span class="badge">{run.state}</span></td><td>{run.supportCellId}</td><td>{run.generation}</td><td>{run.updatedAt}</td></tr>{/each}</tbody></table></div>{/if}{#if hasPermission($adminPermissions,'exchange.assessment.run')}<div class="action-form"><h3>{locale==='zh'?'项目与运行控制':'Project and run controls'}</h3><label>{locale==='zh'?'域 ID':'Domain ID'}<input type="number" min="1" bind:value={projectDomainId}/></label><label>{locale==='zh'?'新项目名称':'New project name'}<input maxlength="256" bind:value={projectName}/></label><button disabled={actionBusy||projectDomainId<1||!projectName.trim()} onclick={createProject}>{locale==='zh'?'创建项目':'Create project'}</button>{#if latestRun}<label>{locale==='zh'?'下一状态':'Next state'}<select bind:value={nextRunState}><option>preflight</option><option>uploading</option><option>validating</option><option>processing</option><option>partial</option><option>complete</option><option>failed</option><option>cancelled</option></select></label><button disabled={actionBusy} onclick={transitionRun}>{locale==='zh'?'更新运行状态':'Update run state'}</button>{/if}</div>{/if}{#if hasPermission($adminPermissions,'exchange.assessment.attest') && latestRun}<div class="action-form"><h3>{locale==='zh'?'添加独立证明':'Add independent attestation'}</h3><label>{locale==='zh'?'类型':'Kind'}<select bind:value={attestationKind}><option value="completeness">completeness</option><option value="collection_zero">collection_zero</option><option value="handling">handling</option><option value="backup_expiry">backup_expiry</option></select></label><label>SHA-256<input bind:value={attestationDigest} maxlength="64" /></label><button disabled={actionBusy||!/^[0-9a-f]{64}$/.test(attestationDigest)} onclick={attest}>{locale==='zh'?'记录证明':'Record attestation'}</button></div>{/if}</section>
  {:else if selectedView === 'outcomes'}
    <section class="panel"><h2>{locale === 'zh' ? '注册表功能结果' : 'Registry-backed outcomes'}</h2><p>{registry?.capabilities.length ?? 0} {locale === 'zh' ? '项；未知不是零，不提供聚合兼容率。' : 'items; unknown is not zero and no aggregate compatibility score is shown.'}</p><div class="outcomes">{#each registry?.capabilities ?? [] as capability}<article><span class="badge">{capability.category}</span><h3>{capability.outcome[locale]}</h3><code>{capability.id}</code><dl><div><dt>{locale === 'zh' ? '映射上限' : 'Mapping ceiling'}</dt><dd>{capability.mappingMaximum}</dd></div><div><dt>{locale === 'zh' ? '声明上限' : 'Claim ceiling'}</dt><dd>{capability.claimMaximum}</dd></div></dl></article>{/each}</div></section>
  {:else if selectedView === 'mappings'}
    <section class="panel"><h2>{locale === 'zh' ? '映射审核队列' : 'Mapping review queue'}</h2><p>{locale === 'zh' ? '批量“全部接受”被禁止；每项决定需要原因、负责人和有效期。' : 'Bulk accept-all is forbidden; each decision needs a reason, owner, and expiry.'}</p>{#if hasPermission($adminPermissions,'exchange.assessment.decide')&&latestRun}<div class="action-form"><label>{locale==='zh'?'功能':'Capability'}<select bind:value={decisionCapability}><option value="">—</option>{#each registry?.capabilities??[] as capability}<option value={capability.id}>{capability.outcome[locale]}</option>{/each}</select></label><label>{locale==='zh'?'映射':'Mapping'}<select bind:value={decisionMapping}><option>native</option><option>transformed</option><option>alternative</option><option>none</option></select></label><label>{locale==='zh'?'决定':'Decision'}<select bind:value={decisionValue}><option>accepted</option><option>rejected</option><option>waived</option><option>pending</option></select></label><label>{locale==='zh'?'原因':'Reason'}<input bind:value={decisionReason} maxlength="2048" /></label><button disabled={actionBusy||!decisionCapability||!decisionReason.trim()} onclick={decide}>{locale==='zh'?'记录决定':'Record decision'}</button></div>{:else}<div class="state">{locale==='zh'?'没有决定权限或可用运行。':'No decision permission or available run.'}</div>{/if}</section>
  {:else if selectedView === 'documents'}
    <section class="panel"><h2>{locale === 'zh' ? '摘要与比较文档' : 'Summary and comparison documents'}</h2><p>{locale === 'zh' ? '文档必须由同一注册表和证据快照生成；服务器会生成、加密并签署发布回执。' : 'Documents derive from one registry and evidence snapshot; the server creates, encrypts, and signs the publication receipt.'}</p>{#if hasPermission($adminPermissions,'exchange.assessment.audit')&&latestRun}<button disabled={actionBusy} onclick={resolveClaims}>{locale==='zh'?'解析声明快照':'Resolve claim snapshot'}</button>{/if}{#if auditSnapshot}<p>{auditSnapshot.claims.length} claim snapshot(s) · {auditSnapshot.evidence.length} evidence row(s)</p>{/if}{#if hasPermission($adminPermissions,'exchange.assessment.publish')&&latestRun}<div class="action-form"><label>{locale==='zh'?'投影摘要':'Projection digest'}<input bind:value={publishDigest} maxlength="64" /></label><button disabled={actionBusy||!/^[0-9a-f]{64}$/.test(publishDigest)} onclick={publish}>{locale==='zh'?'发布':'Publish'}</button></div>{/if}</section>
  {:else}
    <section class="panel"><h2>{locale === 'zh' ? '权限与数据处理' : 'Permissions and data handling'}</h2><ul class="permissions">{#each permissionKeys as permission}<li><code>{permission}</code><span class:granted={hasPermission($adminPermissions, permission)}>{permissionStatus(permission)}</span></li>{/each}</ul><p>{selectedProjectLabel()}</p>{#if hasPermission($adminPermissions,'exchange.assessment.delete')&&selectedProject}<div class="action-form destructive"><h3>{locale==='zh'?'请求删除':'Request deletion'}</h3><label>{locale==='zh'?'范围':'Scope'}<select bind:value={deletionScope}><option value="artifact">artifact</option><option value="run">run</option><option value="project">project</option></select></label>{#if deletionScope==='artifact'}<label>{locale==='zh'?'制品 ID':'Artifact ID'}<input type="number" min="1" bind:value={deletionArtifactId}/></label>{/if}<label>{locale==='zh'?'原因':'Reason'}<input bind:value={deletionReason} maxlength="1024" /></label><button disabled={actionBusy||!deletionReason.trim()|| (deletionScope!=='project'&&!latestRun)||(deletionScope==='artifact'&&deletionArtifactId<1)} onclick={requestDeletion}>{locale==='zh'?'提交删除请求':'Submit deletion request'}</button></div>{/if}</section>
  {/if}
</section>

<style>
  .page{display:grid;gap:var(--space-5);padding:var(--space-6);max-width:1440px;margin:0 auto;color:var(--text-primary)}
  .hero{display:flex;justify-content:space-between;gap:var(--space-4);align-items:flex-start}.eyebrow{color:var(--accent-primary);font-weight:700;letter-spacing:.08em;text-transform:uppercase}.hero h1{margin:var(--space-1) 0;font-size:var(--text-2xl)}.warning{max-width:75ch;color:var(--text-secondary)}
  button,select,input{font:inherit}.locale,.tabs button,.state button,.panel button{min-height:44px;border:1px solid var(--border-default);border-radius:var(--radius-md);background:var(--surface-card);color:var(--text-primary);padding:var(--space-2) var(--space-3);cursor:pointer}.panel button:disabled{opacity:.55;cursor:not-allowed}.selectors{display:flex;flex-wrap:wrap;gap:var(--space-4);padding:var(--space-4);background:var(--surface-card);border:1px solid var(--border-default);border-radius:var(--radius-lg)}.selectors label,.context{display:grid;gap:var(--space-1)}select,input{min-height:44px;min-width:220px;border:1px solid var(--border-default);border-radius:var(--radius-md);background:var(--surface-card);color:var(--text-primary);padding:0 var(--space-3)}.context span{color:var(--text-secondary);font-size:var(--text-sm)}
  .tabs{display:flex;gap:var(--space-2);overflow-x:auto}.tabs button.active{background:var(--accent-primary);border-color:var(--accent-primary);color:var(--text-on-accent)}
  .grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:var(--space-4)}article,.panel,.state{background:var(--surface-card);border:1px solid var(--border-default);border-radius:var(--radius-lg);padding:var(--space-5)}h2,h3{margin-top:0}.metric{font-size:var(--text-2xl);font-weight:700}.state{display:grid;gap:var(--space-3);color:var(--text-secondary)}.state.error{border-color:var(--status-danger)}.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;min-width:700px}th,td{text-align:left;padding:var(--space-3);border-bottom:1px solid var(--border-subtle)}.badge{display:inline-block;padding:2px 8px;border-radius:999px;background:var(--surface-muted);font-size:var(--text-sm)}.outcomes{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:var(--space-3)}.outcomes article{padding:var(--space-4)}dl div{display:flex;justify-content:space-between;gap:var(--space-3)}dt{color:var(--text-secondary)}.permissions{list-style:none;padding:0;display:grid;gap:var(--space-2)}.permissions li{display:flex;justify-content:space-between;gap:var(--space-4);padding:var(--space-3);background:var(--surface-muted);border-radius:var(--radius-md)}.permissions span{color:var(--status-danger)}.permissions span.granted{color:var(--status-success)}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip-path: inset(50%);white-space:nowrap;border:0}
  .section-title{display:flex;justify-content:space-between;gap:var(--space-3);align-items:center}.action-form{display:flex;flex-wrap:wrap;gap:var(--space-3);align-items:end;margin-top:var(--space-5);padding-top:var(--space-4);border-top:1px solid var(--border-default)}.action-form label{display:grid;gap:var(--space-1);color:var(--text-secondary)}.action-form h3{width:100%}.action-form.destructive{border-color:var(--status-danger)}
  button:focus-visible,select:focus-visible{outline:none;box-shadow:var(--focus-ring)}

@media(max-width:900px){.grid{grid-template-columns:1fr}.page{padding:var(--space-4)}}

@media(max-width:600px){.hero{align-items:stretch}.selectors{display:grid}.tabs{display:grid;grid-template-columns:repeat(2,1fr)}}
</style>
