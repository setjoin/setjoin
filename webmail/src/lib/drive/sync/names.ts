// names.ts — G4 conflict/materialized-name rules (spec §0.2-G4, §4.4) + the
// LOCKED ignore set (spec §4.1). Pure functions; the existence predicate is
// injected so callers decide the namespace (disk dir listing, server children).
//
// P4 Task 16 re-exports the office-edit-extension consts from `../office.ts`
// (the single source of truth) so the Electron toolchain — which resolves
// `.js`-suffixed relative imports under this `sync/` dir, not the rest of
// `$lib/drive/` — can reach them without a separate copy (the same
// cross-package pattern this file's own consts already ride for FolderMirror).
export { OFFICE_EDIT_EXTS, isOfficeEditPath } from '../office.js';

/** Split a filename into [base, ext]. Conservative: a leading-dot dotfile
 *  (.gitignore) has NO extension; `archive.tar.gz` keeps only the last dot. */
export function splitExt(name: string): [string, string] {
	const i = name.lastIndexOf('.');
	return i <= 0 ? [name, ''] : [name.slice(0, i), name.slice(i)];
}

export function conflictSiblingName(name: string, deviceLabel: string, dateYmd: string): string {
	const [base, ext] = splitExt(name);
	return `${base} (conflict ${deviceLabel} ${dateYmd})${ext}`;
}

/** P4 Task 17 branch-sibling filename: an open non-main branch head
 *  materializes on disk as `<base> (branch <label>)<ext>` — callers dedupe
 *  via `dedupeName` (G4), same as `conflictSiblingName`. */
export function branchSiblingName(name: string, branchLabel: string): string {
	const [base, ext] = splitExt(name);
	return `${base} (branch ${branchLabel})${ext}`;
}

/** Append " -2", " -3", … before the extension until `existsCI` says free.
 *  Callers MUST pass a case-insensitive predicate (mirrors sync onto
 *  case-insensitive filesystems; the server index is lower(name)-unique). */
export function dedupeName(name: string, existsCI: (n: string) => boolean): string {
	if (!existsCI(name)) return name;
	const [base, ext] = splitExt(name);
	for (let n = 2; ; n++) {
		const candidate = `${base} -${n}${ext}`;
		if (!existsCI(candidate)) return candidate;
	}
}

/** LOCKED ignore set: *.tmp, ~$*, .DS_Store, .setjoin-tmp-* (case-insensitive).
 *  User-editable patterns are deferred (spec §13) — no config knob. */
export function isIgnoredName(name: string): boolean {
	const n = name.toLowerCase();
	return n.endsWith('.tmp') || n.startsWith('~$') || n === '.ds_store' || n.startsWith('.setjoin-tmp-');
}
