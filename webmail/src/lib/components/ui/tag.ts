/**
 * The 8 system tag hues, in picker order. Tags only ever use these —
 * never the accent indigo (Badge owns accent; Tag = user organization).
 * Each hue maps to the token triple --tag-{hue}-bg / -fg / -dot.
 */
export const TAG_COLORS = [
	'blue',
	'teal',
	'green',
	'amber',
	'orange',
	'rose',
	'purple',
	'gray'
] as const;

export type TagColor = (typeof TAG_COLORS)[number];

/**
 * Split a nested tag label ("Finance/Invoices") into breadcrumb segments.
 * Empty segments from stray slashes are dropped.
 */
export function splitTagPath(label: string): string[] {
	return label.split('/').filter((segment) => segment.length > 0);
}
