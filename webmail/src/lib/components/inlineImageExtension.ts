import { Image } from '@tiptap/extension-image';

/**
 * WAVE-5 #2 — the stock TipTap Image node plus one extra attribute (`uploadId`),
 * rendered as `data-upload-id`. It exists so an in-flight inline body image (a
 * paste/drag/toolbar-upload — see composeStore.stageInlineImage) can be found in
 * the live DOM: RichTextEditor's upload-progress overlay locates the <img> by
 * this attribute and tracks its position while the upload is in flight.
 *
 * Deliberately just one extra attribute, not a wrapper node with a live
 * status/progress: those change many times a second during an upload, and
 * updating a ProseMirror node's attrs is a document transaction — it would
 * pollute the undo history and require a "find node by custom attr" transaction
 * on every progress tick. Status/progress instead live purely in the (Svelte-
 * reactive) ComposeAttachment row; the node's attrs never change post-insert.
 * Everything else (src/alt/title/commands/schema/name) is the stock Image
 * extension — only `addAttributes` is overridden, merging the parent's in first.
 */
export const InlineImage = Image.extend({
	addAttributes() {
		return {
			...this.parent?.(),
			uploadId: {
				default: null,
				parseHTML: (el: HTMLElement) => el.getAttribute('data-upload-id'),
				renderHTML: (attrs: { uploadId?: string | null }) =>
					attrs.uploadId ? { 'data-upload-id': attrs.uploadId } : {},
			},
		};
	},
});
