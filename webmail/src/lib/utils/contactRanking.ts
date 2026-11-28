import { user, registerAuthSessionTeardown, type AuthUser } from '$lib/stores/auth';

const STORAGE_KEY_PREFIX = 'setjoin-contact-frequencies';
// Pre-namespacing key: account-INDEPENDENT, i.e. exactly the cross-identity
// residue account scoping removes. Never read; evicted by purgeContactFrequencies.
const LEGACY_STORAGE_KEY = 'setjoin-contact-frequencies';

// An entry is either the legacy bare count (number), the {count, name} shape, or
// the bounded-retention {count, name, at} shape. load() tolerates all three so a
// pre-existing store keeps working; anything it cannot interpret is dropped
// rather than surfaced (attacker-controlled storage must not poison the cache).
type Entry = number | { count: number; name?: string; at?: number };

// Bounded retention (UTIL-CACHE-ATTACKER-POISON hardening): attacker-chosen
// display names must not persist indefinitely. Entries carry the instant they
// were last learned and are expired after RETENTION_MS unless re-reinforced by
// another send; the whole map is capped at MAX_ENTRIES (highest counts win), so
// neither a stale label nor a flood of learned entries can outlive its use.
const MAX_ENTRIES = 500;
const RETENTION_MS = 90 * 24 * 60 * 60 * 1000;

function nowMs(): number {
  return Date.now();
}

interface FrequencyMap {
  [email: string]: Entry;
}

// Account scoping: frequencies persist PER IDENTITY under
// `setjoin-contact-frequencies:<identity>`. While no authenticated identity is
// known, counts live only in this ephemeral in-page map and are never written to
// storage — unattributable contact history must not outlive the page.
let currentAccountId: string | null = null;
let ephemeralMap: FrequencyMap = {};

// Mirrors auth.ts authIdentity() (not exported there; kept in sync).
function accountIdentity(u: AuthUser | null): string | null {
  if (!u) return null;
  return u.userId != null ? `user:${u.userId}` : `email:${u.email.toLowerCase()}`;
}

function storageKey(): string | null {
  return currentAccountId ? `${STORAGE_KEY_PREFIX}:${currentAccountId}` : null;
}

/**
 * Bounded-retention sweep: drop uninterpretable entries, entries whose
 * `at` stamp (if any) predates the retention window, and everything beyond
 * MAX_ENTRIES (kept by descending count, then address — the same ranking the
 * suggestions surface). Applies to every read and every write, so a poisoned
 * or abandoned label ages out of the cache instead of persisting forever.
 */
function prune(map: FrequencyMap): FrequencyMap {
  const cutoff = nowMs() - RETENTION_MS;
  const survivors = Object.entries(map)
    .filter(([_, v]) => {
      if (typeof v === 'number') return Number.isFinite(v);
      if (v === null || typeof v !== 'object' || typeof v.count !== 'number' || !Number.isFinite(v.count)) return false;
      // Entries without an `at` stamp predate bounded retention: treat them as
      // already-expired (they re-learn on the next send to the address).
      return typeof v.at === 'number' && v.at >= cutoff;
    })
    .map(([email, v]) => ({ email, count: entryCount(v as Entry) }))
    .sort((a, b) => b.count - a.count || a.email.localeCompare(b.email))
    .slice(0, MAX_ENTRIES);
  const kept: FrequencyMap = {};
  for (const { email } of survivors) kept[email] = map[email];
  return kept;
}

function load(): FrequencyMap {
  const key = storageKey();
  if (!key) return prune(ephemeralMap);
  try {
    const raw = localStorage.getItem(key);
    return raw ? prune(JSON.parse(raw) as FrequencyMap) : {};
  } catch {
    return {};
  }
}

function save(map: FrequencyMap): void {
  const bounded = prune(map);
  const key = storageKey();
  if (!key) {
    // Usable for the rest of this page, but never persisted unattributed.
    ephemeralMap = bounded;
    return;
  }
  try {
    localStorage.setItem(key, JSON.stringify(bounded));
  } catch {
    // localStorage full or unavailable — silently degrade
  }
}

/**
 * Purge EVERY contact-frequency record: the current identity's namespace, every
 * other identity's namespace, the legacy account-independent key, and the
 * ephemeral in-page map. This is the auth-teardown contract (logout,
 * impersonation end, account switch) — no persisted contact history outlives the
 * identity that produced it, so the next profile user gets zero prior-identity
 * suggestions.
 */
export function purgeContactFrequencies(): void {
  ephemeralMap = {};
  try {
    const doomed: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k !== null && (k === LEGACY_STORAGE_KEY || k.startsWith(`${STORAGE_KEY_PREFIX}:`))) {
        doomed.push(k);
      }
    }
    for (const k of doomed) localStorage.removeItem(k);
  } catch {
    // storage unavailable — nothing persisted to purge
  }
}

function entryCount(e: Entry | undefined): number {
  if (e === undefined) return 0;
  return typeof e === 'number' ? e : e.count || 0;
}

function entryName(e: Entry | undefined): string {
  if (e === undefined || typeof e === 'number') return '';
  return e.name || '';
}

function normalizeEmail(email: string): string {
  return email.toLowerCase().trim();
}

/**
 * Record a send to the given email address. Increments the local frequency counter
 * and remembers the latest non-empty display name (used by the auto-complete cache).
 * Call this after every successful EmailSubmission.
 */
export function recordSend(email: string, name?: string): void {
  const norm = normalizeEmail(email);
  if (!norm) return;
  const map = load();
  const prev = map[norm];
  const count = entryCount(prev) + 1;
  const resolvedName = (name && name.trim()) || entryName(prev);
  // `at` restamps bounded retention on every reinforcement: a label survives
  // only while the user keeps sending to the address that learned it.
  map[norm] = resolvedName
    ? { count, name: resolvedName, at: nowMs() }
    : { count, at: nowMs() };
  save(map);
}

/**
 * Return the send count for a given email address.
 */
export function getSendCount(email: string): number {
  return entryCount(load()[normalizeEmail(email)]);
}

/**
 * Rank an array of email addresses by how frequently the user sends to them.
 * Addresses with higher send counts appear first. Ties are broken alphabetically.
 * Unknown addresses (count = 0) appear at the end.
 */
export function rankContacts(emails: string[]): string[] {
  const map = load();
  return [...emails].sort((a, b) => {
    const countA = entryCount(map[normalizeEmail(a)]);
    const countB = entryCount(map[normalizeEmail(b)]);
    if (countB !== countA) return countB - countA; // descending by count
    return a.localeCompare(b); // alphabetical tiebreaker
  });
}

/** A single auto-complete suggestion surfaced in the compose recipient field. */
export interface RecipientSuggestion {
  email: string;
  name: string;
  count: number;
}

/**
 * Return cached recipient suggestions matching the query (prefix/substring against
 * email OR display name), ranked by send frequency. An empty query returns the most
 * frequent recipients. Used by the compose recipient auto-complete alongside the GAL.
 */
export function suggestRecipients(query: string, limit = 5): RecipientSuggestion[] {
  const q = query.toLowerCase().trim();
  const map = load();
  return Object.entries(map)
    .map(([email, v]) => ({ email, name: entryName(v), count: entryCount(v) }))
    .filter((s) => !q || s.email.toLowerCase().includes(q) || s.name.toLowerCase().includes(q))
    .sort((a, b) => b.count - a.count || a.email.localeCompare(b.email))
    .slice(0, limit);
}

/**
 * Forget a cached recipient so it no longer appears in suggestions (the per-entry X
 * in the compose autocomplete).
 */
export function removeRecipient(email: string): void {
  const map = load();
  delete map[normalizeEmail(email)];
  save(map);
}

// --- auth teardown wiring ----------------------------------------------------

registerAuthSessionTeardown(purgeContactFrequencies);

user.subscribe((u) => {
  const next = accountIdentity(u);
  if (next === currentAccountId) return;
  currentAccountId = next;
  // Any identity transition — session acquisition, logout, impersonation start/
  // end, account switch — is teardown semantics for persisted contact history:
  // purge in full. On first acquisition this also evicts the legacy
  // account-independent key and any per-identity namespace a crashed prior
  // session left behind; subsequent sends re-accumulate under the new identity.
  purgeContactFrequencies();
});
