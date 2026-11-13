import { describe, it, expect } from 'vitest';
import * as ui from './index';

// Canonical M1 export list — one entry per primitive/constant from all four plan parts.
const expectedExports = [
	'Button',
	'IconButton',
	'Input',
	'Select',
	'Checkbox',
	'Switch',
	'Radio',
	'Textarea',
	'Tag',
	'TAG_COLORS',
	'Badge',
	'Avatar',
	'Card',
	'Tabs',
	'SidebarItem',
	'Menu',
	'Tooltip',
	'Resizer',
	'SplitPane',
	'Dialog',
	'Toast',
	'showToast',
	'Spinner',
	'Progress',
	'EmptyState',
	'Pagination',
	'DateTimePicker',
	'Table'
];

describe('ui barrel', () => {
	it.each(expectedExports)('exports %s', (name) => {
		expect((ui as Record<string, unknown>)[name], `missing export: ${name}`).toBeDefined();
	});
});
