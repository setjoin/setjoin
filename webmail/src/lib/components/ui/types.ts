/**
 * Shared types for setjoin ui primitives (src/lib/components/ui).
 *
 * Size vocabulary (from the setjoin design system):
 *   sm = 26px (--control-height-sm), md = 32px (--control-height),
 *   lg = 40px (--control-height-lg, login/hero forms only).
 */

/** Button visual style. One primary per view. */
export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger';

/** Button height: sm=26px, md=32px (default), lg=40px (hero forms only). */
export type ButtonSize = 'sm' | 'md' | 'lg';

/** IconButton: ghost (default) for toolbars; outline for standalone placement. */
export type IconButtonVariant = 'ghost' | 'outline';

/** IconButton square edge: sm=26px for dense list rows, md=32px (default). */
export type IconButtonSize = 'sm' | 'md';

/** Text field height: md=32px (default), lg=40px for login/hero forms. */
export type FieldSize = 'md' | 'lg';

/** Normalized option for Select. */
export interface SelectOption {
	value: string;
	label: string;
}

/**
 * Accepts the Select `options` prop shorthand (plain strings) and returns
 * uniform {value,label} pairs. Strings become value === label.
 */
export function normalizeOptions(options: Array<string | SelectOption>): SelectOption[] {
	return options.map((o) => (typeof o === 'string' ? { value: o, label: o } : o));
}
