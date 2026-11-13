import { Node } from '@tiptap/core';

/**
 * TipTap extension that renders template variables ({first_name}, {company})
 * as styled inline chips. They appear as visual tokens in the editor
 * but resolve to their text form in getText() for plain-text email fallback.
 *
 * Atom: true means the node is a single non-editable unit — users can
 * select and delete it as a whole but can't edit the text inside.
 */
export const TemplateVariable = Node.create({
	name: 'templateVariable',

	group: 'inline',
	inline: true,
	atom: true,

	addAttributes() {
		return {
			key: {
				default: null,
				parseHTML: (el) => el.getAttribute('data-template-var'),
			},
		};
	},

	parseHTML() {
		return [{ tag: 'span[data-template-var]' }];
	},

	renderHTML({ node }) {
		return [
			'span',
			{
				'data-template-var': node.attrs.key,
				class: 'template-var-chip',
				contenteditable: 'false',
			},
			`{${node.attrs.key}}`,
		];
	},

	renderText({ node }) {
		return `{${node.attrs.key}}`;
	},
});
