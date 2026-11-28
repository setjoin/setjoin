import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/svelte';
import PrecedenceExplainer from './PrecedenceExplainer.svelte';
import type { OfflinePolicy } from '$lib/admin/client';

const base: OfflinePolicy = { id: 1, name: 'Default (global)', scope_type: 'global',
  scope_id: null, enabled: false, max_offline_days: 30, require_approval: true,
  wipe_on_logout: 'admin_default', priority: 0 };

describe('PrecedenceExplainer', () => {
  it('shows OFF org-wide when master off and no enabled layer', () => {
    const { getByText } = render(PrecedenceExplainer, { policies: [base], master: false });
    expect(getByText(/off org-wide/i)).toBeTruthy();
  });
  it('marks the highest enabled layer Effective', () => {
    const userPol: OfflinePolicy = { ...base, id: 2, name: 'u', scope_type: 'user', scope_id: 7, enabled: true, priority: 100 };
    const { getAllByText } = render(PrecedenceExplainer, { policies: [base, userPol], master: true });
    expect(getAllByText(/effective/i).length).toBeGreaterThan(0);
  });
  it('renders all four AND-gate pills', () => {
    const { getByText } = render(PrecedenceExplainer, { policies: [base], master: true });
    for (const p of [/org master/i, /policy enabled/i, /opted/i, /device approved/i]) expect(getByText(p)).toBeTruthy();
  });
});
