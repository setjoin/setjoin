import { describe, it, expect } from 'vitest';
import { resolveReceiptAction } from './readReceipt';

describe('read-receipt policy', () => {
	it('never -> no send, no prompt', () => {
		expect(resolveReceiptAction('never', true)).toEqual({ send: false, prompt: false });
	});
	it('always -> auto send, no prompt', () => {
		expect(resolveReceiptAction('always', true)).toEqual({ send: true, prompt: false, consent: true });
	});
	it('ask -> prompt the user (no auto send)', () => {
		expect(resolveReceiptAction('ask', true)).toEqual({ send: false, prompt: true });
	});
	it('non-receipt message -> nothing', () => {
		expect(resolveReceiptAction('ask', false)).toEqual({ send: false, prompt: false });
	});
	it('non-receipt message -> nothing even when policy is always', () => {
		expect(resolveReceiptAction('always', false)).toEqual({ send: false, prompt: false });
	});
	it('non-receipt message -> nothing even when policy is never', () => {
		expect(resolveReceiptAction('never', false)).toEqual({ send: false, prompt: false });
	});
});
