import { describe, it, expect, vi, beforeEach } from 'vitest';
import { get } from 'svelte/store';

vi.mock('$lib/jmap/client', () => ({
  contactGroupQuery: vi.fn().mockResolvedValue({ ids: ['1'] }),
  contactGroupGet: vi
    .fn()
    .mockResolvedValue([{ id: '1', name: 'Team', memberCount: 2, members: [] }]),
  contactGroupExpand: vi.fn().mockResolvedValue([{ name: 'A', email: 'a@x.test' }]),
  contactGroupSet: vi.fn().mockResolvedValue({ created: { k1: { id: '9' } } })
}));

import {
  contactGroups,
  loadGroups,
  createGroup,
  renameGroup,
  deleteGroup,
  setMembers,
  expandGroup,
  resetGroups
} from './contactGroups';
import * as client from '$lib/jmap/client';

describe('contactGroups store', () => {
  beforeEach(() => {
    resetGroups();
    vi.clearAllMocks();
  });

  it('loadGroups populates the store (query → get)', async () => {
    await loadGroups();
    expect(client.contactGroupQuery).toHaveBeenCalled();
    expect(client.contactGroupGet).toHaveBeenCalledWith(['1']);
    expect(get(contactGroups)).toHaveLength(1);
    expect(get(contactGroups)[0].name).toBe('Team');
  });

  it('loadGroups with no ids clears the store without a get call', async () => {
    (client.contactGroupQuery as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ ids: [] });
    await loadGroups();
    expect(client.contactGroupGet).not.toHaveBeenCalled();
    expect(get(contactGroups)).toHaveLength(0);
  });

  it('createGroup returns the new id and reloads', async () => {
    const id = await createGroup('New');
    expect(id).toBe('9');
    expect(client.contactGroupSet).toHaveBeenCalledWith({ k1: { name: 'New' } }, null, null);
  });

  it('renameGroup sends an update patch', async () => {
    await renameGroup('1', 'Renamed');
    expect(client.contactGroupSet).toHaveBeenCalledWith(null, { '1': { name: 'Renamed' } }, null);
  });

  it('deleteGroup sends a destroy', async () => {
    await deleteGroup('1');
    expect(client.contactGroupSet).toHaveBeenCalledWith(null, null, ['1']);
  });

  it('setMembers sends a members patch', async () => {
    await setMembers('1', [{ email: 'b@x.test' }], []);
    expect(client.contactGroupSet).toHaveBeenCalledWith(null, null, null, {
      groupId: '1',
      add: [{ email: 'b@x.test' }],
      remove: []
    });
  });

  it('expandGroup returns recipients', async () => {
    const out = await expandGroup('1');
    expect(out[0].email).toBe('a@x.test');
  });
});
