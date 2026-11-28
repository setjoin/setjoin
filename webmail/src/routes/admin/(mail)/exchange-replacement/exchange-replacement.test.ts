import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor } from '@testing-library/svelte/svelte5';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { jmapSession } from '$lib/stores/session';

const api = vi.hoisted(() => ({ registry: vi.fn(), projects: vi.fn(), runs: vi.fn(), createProject: vi.fn(), createRun: vi.fn(), transitionRun: vi.fn(), decision: vi.fn(), attest: vi.fn(), resolve: vi.fn(), audit: vi.fn(), publish: vi.fn(), delete: vi.fn() }));
vi.mock('$lib/admin/client', () => ({
  adminExchangeRegistry: api.registry,
  adminExchangeProjects: api.projects,
  adminExchangeRuns: api.runs,
  adminCreateExchangeProject: api.createProject,
  adminCreateExchangeRun: api.createRun, adminExchangeDecision: api.decision,
  adminExchangeTransitionRun: api.transitionRun,
  adminExchangeAttest: api.attest, adminExchangeResolveClaims: api.resolve,
  adminExchangeAudit: api.audit, adminExchangePublish: api.publish, adminExchangeDelete: api.delete,
}));
import Page from './+page.svelte';

const registry = {
  schemaVersion: 'setjoin.exchange.projection/v1', registryVersion: 1, catalogVersion: 1, sourceDigest: 'b'.repeat(64),
  capabilities: [{ id: 'EX-CALENDAR-VISIBILITY', category: 'calendar', outcome: { zh: '日历忙闲可见性', en: 'Calendar visibility' }, mappingMaximum: 'native', claimMaximum: 'experimental', phaseImpacts: [] }],
  supportCells: [{ id: 'EX2019-ONPREM-INITIAL', productFamily: 'Exchange 2019', topology: 'on_premises', admission: 'unassessed', digest: 'a'.repeat(64), collectorVersion: '1' }],
};
const project = { id: 9, domainId: 1, name: '华东 Exchange', state: 'active', retentionUntil: null, createdAt: '2026-08-23T00:00:00Z', updatedAt: '2026-08-23T00:00:00Z' };
const run = { id: 17, projectId: 9, generation: 2, state: 'partial', supportCellId: 'EX2019-ONPREM-INITIAL', supportCellDigest: 'a'.repeat(64), registryVersion: 1, registryDigest: 'b'.repeat(64), catalogVersion: 1, collectorVersion: '1', errorCode: null, createdAt: '2026-08-23T00:00:00Z', updatedAt: '2026-08-23T00:00:00Z', completedAt: null };

function grant(perms = ['exchange.assessment.read','exchange.assessment.audit']) {
  jmapSession.set({ accounts: {}, primaryAccounts: {}, capabilities: { 'urn:setjoin:params:jmap:mail': { admin: { consoles: ['mail'], permissions: perms } } } } as never);
}

describe('Exchange replacement unified admin page', () => {
  beforeEach(() => { resetStores(); vi.clearAllMocks(); api.registry.mockResolvedValue(registry); api.projects.mockResolvedValue([project]); api.runs.mockResolvedValue([run]); });

  it('keeps the V1A warning, three axes, six views and registry-driven outcomes visible', async () => {
    const rendered = await renderAsUser(Page, {}, { isAdmin: true }); grant();
    await waitFor(() => expect(screen.getByText('评估状态')).toBeInTheDocument());
    expect(screen.getByText(/仅用于评估/)).toBeInTheDocument();
    expect(screen.getByText('映射覆盖')).toBeInTheDocument();
    expect(screen.getByText('声明状态')).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: /概览|评估运行|功能结果|映射|文档|设置/ })).toHaveLength(6);
    await fireEvent.click(screen.getByRole('button', { name: '功能结果' }));
    expect(screen.getByText('日历忙闲可见性')).toBeInTheDocument();
    expect(screen.getByText('EX-CALENDAR-VISIBILITY')).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'EN' }));
    expect(screen.getByText('Calendar visibility')).toBeInTheDocument();
    rendered.unmount(); resetStores();
  });

  it('shows every permission independently without turning navigation into authorization', async () => {
    const rendered = await renderAsUser(Page, {}, { isAdmin: true }); grant(['exchange.assessment.read']);
    await waitFor(() => expect(screen.getByRole('button', { name: '设置' })).toBeInTheDocument());
    await fireEvent.click(screen.getByRole('button', { name: '设置' }));
    expect(screen.getByText('exchange.assessment.read')).toBeInTheDocument();
    expect(screen.getAllByText('已授予')).toHaveLength(1);
    expect(screen.getAllByText('未授予')).toHaveLength(6);
    rendered.unmount(); resetStores();
  });

  it('renders all 128 independent permission combinations exactly', async () => {
    const keys = ['read','run','decide','attest','audit','publish','delete'].map((name) => `exchange.assessment.${name}`);
    for (let mask = 0; mask < 1 << keys.length; mask += 1) {
      resetStores();
      const granted = keys.filter((_, index) => (mask & (1 << index)) !== 0);
      const rendered = await renderAsUser(Page, {}, { isAdmin: true });
      grant(granted);
      await waitFor(() => expect(screen.getByRole('button', { name: '设置' })).toBeInTheDocument());
      await fireEvent.click(screen.getByRole('button', { name: '设置' }));
      expect(screen.queryAllByText('已授予')).toHaveLength(granted.length);
      expect(screen.queryAllByText('未授予')).toHaveLength(keys.length - granted.length);
      rendered.unmount();
    }
    resetStores();
  }, 60_000);

  it('renders bounded error recovery', async () => {
    api.registry.mockRejectedValueOnce(new Error('registry unavailable'));
    const rendered = await renderAsUser(Page, {}, { isAdmin: true }); grant();
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('registry unavailable'));
    await fireEvent.click(screen.getByRole('button', { name: '重试' }));
    await waitFor(() => expect(screen.getByText('评估状态')).toBeInTheDocument());
    rendered.unmount(); resetStores();
  });

  it('executes every permitted assessment mutation with explicit inputs', async () => {
    const permissions = ['read','run','decide','attest','audit','publish','delete'].map((name) => `exchange.assessment.${name}`);
    const audit = { claims: [{}], attestations: [{}], evidence: [{}, {}], publications: [] };
    api.audit.mockResolvedValue(audit);
    const rendered = await renderAsUser(Page, {}, { isAdmin: true }); grant(permissions);
    await waitFor(() => expect(screen.getByRole('button', { name: '评估运行' })).toBeInTheDocument());

    await fireEvent.click(screen.getByRole('button', { name: '评估运行' }));
    await fireEvent.input(screen.getByLabelText('域 ID'), { target: { value: '7' } });
    await fireEvent.input(screen.getByLabelText('新项目名称'), { target: { value: '华南迁移' } });
    await fireEvent.click(screen.getByRole('button', { name: '创建项目' }));
    await waitFor(() => expect(api.createProject).toHaveBeenCalledWith({ domainId: 7, name: '华南迁移' }));

    await fireEvent.click(screen.getByRole('button', { name: '新建运行' }));
    await waitFor(() => expect(api.createRun).toHaveBeenCalledWith(9, expect.objectContaining({ supportCellId: 'EX2019-ONPREM-INITIAL' })));
    await fireEvent.change(screen.getByLabelText('下一状态'), { target: { value: 'complete' } });
    await fireEvent.click(screen.getByRole('button', { name: '更新运行状态' }));
    await waitFor(() => expect(api.transitionRun).toHaveBeenCalledWith(17, 2, 'complete'));

    await fireEvent.input(screen.getByLabelText('SHA-256'), { target: { value: 'c'.repeat(64) } });
    await fireEvent.click(screen.getByRole('button', { name: '记录证明' }));
    await waitFor(() => expect(api.attest).toHaveBeenCalledWith(17, expect.objectContaining({ kind: 'completeness', subjectDigest: 'c'.repeat(64) })));

    await fireEvent.click(screen.getByRole('button', { name: '映射' }));
    await fireEvent.change(screen.getByLabelText('功能'), { target: { value: 'EX-CALENDAR-VISIBILITY' } });
    await fireEvent.change(screen.getByLabelText('映射'), { target: { value: 'alternative' } });
    await fireEvent.change(screen.getByLabelText('决定'), { target: { value: 'waived' } });
    await fireEvent.input(screen.getByLabelText('原因'), { target: { value: '客户确认替代流程' } });
    await fireEvent.click(screen.getByRole('button', { name: '记录决定' }));
    await waitFor(() => expect(api.decision).toHaveBeenCalledWith(17, expect.objectContaining({ capabilityId: 'EX-CALENDAR-VISIBILITY', outcomeMapping: 'alternative', decision: 'waived' })));

    await fireEvent.click(screen.getByRole('button', { name: '文档' }));
    await fireEvent.click(screen.getByRole('button', { name: '解析声明快照' }));
    await waitFor(() => expect(api.resolve).toHaveBeenCalledWith(17, 2));
    expect(await screen.findByText('1 claim snapshot(s) · 2 evidence row(s)')).toBeInTheDocument();
    await fireEvent.input(screen.getByLabelText('投影摘要'), { target: { value: 'd'.repeat(64) } });
    await fireEvent.click(screen.getByRole('button', { name: '发布' }));
    await waitFor(() => expect(api.publish).toHaveBeenCalledWith(17, 'd'.repeat(64)));

    await fireEvent.click(screen.getByRole('button', { name: '设置' }));
    await fireEvent.change(screen.getByLabelText('范围'), { target: { value: 'artifact' } });
    await fireEvent.input(screen.getByLabelText('制品 ID'), { target: { value: '23' } });
    await fireEvent.input(screen.getByLabelText('原因'), { target: { value: '数据主体删除请求' } });
    await fireEvent.click(screen.getByRole('button', { name: '提交删除请求' }));
    await waitFor(() => expect(api.delete).toHaveBeenCalledWith(9, { scope: 'artifact', runId: 17, artifactId: 23, reason: '数据主体删除请求' }));

    await fireEvent.change(screen.getByLabelText('范围'), { target: { value: 'project' } });
    await fireEvent.input(screen.getByLabelText('原因'), { target: { value: '项目保留期结束' } });
    await fireEvent.click(screen.getByRole('button', { name: '提交删除请求' }));
    await waitFor(() => expect(api.delete).toHaveBeenCalledWith(9, { scope: 'project', runId: undefined, artifactId: undefined, reason: '项目保留期结束' }));
    rendered.unmount(); resetStores();
  });

  it('keeps empty projects and unavailable decisions explicit', async () => {
    api.projects.mockResolvedValue([]);
    api.runs.mockResolvedValue([]);
    const rendered = await renderAsUser(Page, {}, { isAdmin: true }); grant(['exchange.assessment.read']);
    await waitFor(() => expect(screen.getByRole('option', { name: '尚无项目' })).toBeInTheDocument());
    expect(screen.getByRole('combobox', { name: '项目' })).toBeDisabled();
    await fireEvent.click(screen.getByRole('button', { name: '评估运行' }));
    expect(screen.getByText(/尚无运行/)).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: '映射' }));
    expect(screen.getByText('没有决定权限或可用运行。')).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: '设置' }));
    expect(screen.getByText('未选择项目')).toBeInTheDocument();
    rendered.unmount(); resetStores();
  });
});
