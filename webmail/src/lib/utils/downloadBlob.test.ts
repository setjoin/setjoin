import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { downloadBlob } from './downloadBlob';

describe('downloadBlob', () => {
	const createObjectURL = vi.fn(() => 'blob:x');
	const revokeObjectURL = vi.fn();
	let clickSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		createObjectURL.mockClear();
		revokeObjectURL.mockClear();
		URL.createObjectURL = createObjectURL as unknown as typeof URL.createObjectURL;
		URL.revokeObjectURL = revokeObjectURL;
		clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
	});

	afterEach(() => {
		clickSpy.mockRestore();
	});

	it('creates, clicks, and cleans up a temporary download anchor', () => {
		const blob = new Blob(['x']);
		let appended: HTMLAnchorElement | null = null;
		const appendSpy = vi.spyOn(document.body, 'appendChild').mockImplementation((node) => {
			appended = node as HTMLAnchorElement;
			return node;
		});

		downloadBlob(blob, 'a.csv');

		expect(createObjectURL).toHaveBeenCalledWith(blob);
		expect(appended).not.toBeNull();
		expect(appended!.download).toBe('a.csv');
		expect(appended!.href).toBe('blob:x');
		expect(clickSpy).toHaveBeenCalledTimes(1);
		expect(revokeObjectURL).toHaveBeenCalledWith('blob:x');
		expect(document.querySelector('a')).toBeNull();

		appendSpy.mockRestore();
	});
});
