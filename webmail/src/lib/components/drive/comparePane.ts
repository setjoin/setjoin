// CompareView's pane ladder (P4 Task 13, plan §11.1): a pure, unit-tested
// function so the render-mode decision isn't buried in component markup.
import { isOfficeEditPath } from '$lib/drive/office';

export type PaneMode = 'image' | 'text' | 'officeRendition' | 'metadataOnly';

/** ladder: image -> text -> officeRendition -> metadataOnly.
 *  SVG is deliberately excluded from 'image' — it can carry script/foreignObject
 *  (SecureViewer's precedent) and this view has no sandboxed-iframe pane, so it
 *  falls through to metadataOnly rather than risking a raw <img src=blob:>. */
export function paneMode(meta: { contentType?: string; previewStatus: string }, fileName: string): PaneMode {
	const ct = meta.contentType ?? '';
	if (ct.startsWith('image/') && ct !== 'image/svg+xml') return 'image';
	if (ct.startsWith('text/')) return 'text';
	if (isOfficeEditPath(fileName) && meta.previewStatus === 'ready') return 'officeRendition';
	return 'metadataOnly';
}

/** Both sides must resolve to the SAME renderable mode to show a side-by-side pane. */
export function comparePaneMode(
	left: { contentType?: string; previewStatus: string },
	right: { contentType?: string; previewStatus: string },
	fileName: string,
): PaneMode {
	const l = paneMode(left, fileName);
	const r = paneMode(right, fileName);
	return l === r ? l : 'metadataOnly';
}
