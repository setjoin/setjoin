import { describe, it, expect, beforeEach } from 'vitest';
import { applyTheme, applyDensity } from './apply';

describe('applyTheme', () => {
	beforeEach(() => {
		localStorage.clear();
		delete document.documentElement.dataset.theme;
	});

	it("sets dataset.theme='dark' and persists 'dark' for mode 'dark'", () => {
		applyTheme('dark');
		expect(document.documentElement.dataset.theme).toBe('dark');
		expect(localStorage.getItem('sj-theme')).toBe('dark');
	});

	it("clears dataset.theme and persists 'light' for mode 'light'", () => {
		document.documentElement.dataset.theme = 'dark'; // simulate prior state
		applyTheme('light');
		expect(document.documentElement.dataset.theme).toBeUndefined();
		expect(localStorage.getItem('sj-theme')).toBe('light');
	});
});

describe('applyDensity', () => {
	beforeEach(() => {
		localStorage.clear();
		delete document.documentElement.dataset.density;
	});

	it("sets dataset.density='compact' and persists it", () => {
		applyDensity('compact');
		expect(document.documentElement.dataset.density).toBe('compact');
		expect(localStorage.getItem('density')).toBe('compact');
	});

	it('clears dataset.density for comfortable', () => {
		document.documentElement.dataset.density = 'compact';
		applyDensity('comfortable');
		expect(document.documentElement.dataset.density).toBeUndefined();
		expect(localStorage.getItem('density')).toBe('comfortable');
	});
});
