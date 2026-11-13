import { describe, it, expect } from 'vitest';
import {
  APP_IDS,
  explicitlyEnabledApps,
  isJmapMethodCall,
  JMAP_METHOD_NAME_LIST,
  type AppId,
  type EffectiveCapabilitiesPayload,
  type JmapMethodCall,
} from './jmap';

describe('JMAP wire validation', () => {
  it('keeps the runtime method list in sync with the JmapMethodName union', () => {
    // The union derives from the tuple, so this is a shape/ceiling guard:
    // every entry is a plausible JMAP name and there are no duplicates.
    const names = new Set<string>(JMAP_METHOD_NAME_LIST);
    expect(names.size).toBe(JMAP_METHOD_NAME_LIST.length);
    for (const name of JMAP_METHOD_NAME_LIST) expect(name).toMatch(/^[A-Za-z]+\/[a-zA-Z]+$/);
  });

  it('accepts a well-formed method call tuple from the wire', () => {
    const call: JmapMethodCall = ['Email/query', { mailboxIds: ['inbox'] }, 'c0'];
    expect(isJmapMethodCall(call)).toBe(true);
  });

  it('rejects blind-cast garbage: wrong name, arity, args or call id', () => {
    expect(isJmapMethodCall(['Bogus/method', {}, 'c0'])).toBe(false);
    expect(isJmapMethodCall(['Email/query', {}, ''])).toBe(false);
    expect(isJmapMethodCall(['Email/query', {}, 7])).toBe(false);
    expect(isJmapMethodCall(['Email/query', {}, 'c0', 'extra'])).toBe(false);
    expect(isJmapMethodCall(['Email/query', {},])).toBe(false);
    expect(isJmapMethodCall(['Email/query', null, 'c0'])).toBe(false);
    expect(isJmapMethodCall(['Email/query', 'args', 'c0'])).toBe(false);
    expect(isJmapMethodCall('Email/query')).toBe(false);
    expect(isJmapMethodCall(null)).toBe(false);
  });
});

describe('explicitlyEnabledApps (fail-closed capability derivation)', () => {
  const payload = (apps: Partial<Record<AppId, boolean>>): EffectiveCapabilitiesPayload => ({
    apps,
    features: { assist: false, bundles: false },
  });

  it('enables only apps the server explicitly asserts true', () => {
    expect(
      explicitlyEnabledApps(payload({ mail: true, drive: true, chat: false })),
    ).toEqual(['mail', 'drive']);
  });

  it('treats absent keys as disabled — the strict counterpart of the B8 default-allow window', () => {
    expect(explicitlyEnabledApps(payload({}))).toEqual([]);
    expect(explicitlyEnabledApps(payload({ mail: undefined, calendar: true }))).toEqual(['calendar']);
  });

  it('returns apps in canonical APP_IDS order', () => {
    expect(explicitlyEnabledApps(payload({ meet: true, mail: true, chat: true }))).toEqual([
      'mail',
      'chat',
      'meet',
    ]);
    expect(APP_IDS[0]).toBe('mail');
  });
});
