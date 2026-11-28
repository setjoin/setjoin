// Office document extensions that get soft auto-checkout on edit-open (Drive P4
// §5.4). Editing these in-place (webmail edit-open, or a mirror watcher upsert)
// acquires a soft lock so other members see "editing" presence; a save from a
// stale base auto-branches rather than clobbering. The list is the single
// source of truth — the sync engine re-exports it via sync/names.ts so the
// Electron toolchain resolves it (the P2 cross-package pattern).
export const OFFICE_EDIT_EXTS = [
	'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
	'odt', 'ods', 'odp', 'vsd', 'vsdx', 'dwg', 'dxf',
] as const;

// isOfficeEditPath reports whether a file name/path is an editable office type.
// Case-insensitive; the extension is the last dot-segment.
export function isOfficeEditPath(nameOrPath: string): boolean {
	const dot = nameOrPath.lastIndexOf('.');
	if (dot < 0) return false;
	const ext = nameOrPath.slice(dot + 1).toLowerCase();
	return (OFFICE_EDIT_EXTS as readonly string[]).includes(ext);
}
