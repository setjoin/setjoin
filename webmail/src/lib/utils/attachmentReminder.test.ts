import { describe, it, expect } from 'vitest';
import { mentionsAttachment } from './attachmentReminder';

describe('mentionsAttachment (Task 5)', () => {
	it('flags "see attached" with no files', () => {
		expect(mentionsAttachment('Report', 'Please see attached for details', 'en')).toBe(true);
	});
	it('flags "I have attached"', () => {
		expect(mentionsAttachment('', 'I have attached the slides', 'en')).toBe(true);
	});
	it('does not flag unrelated text', () => {
		expect(mentionsAttachment('Lunch', 'Are you free at noon?', 'en')).toBe(false);
	});
	it('flags Chinese 附件', () => {
		expect(mentionsAttachment('', '请见附件', 'zh')).toBe(true);
	});
	it('flags German anbei', () => {
		expect(mentionsAttachment('', 'Den Bericht finden Sie anbei', 'de')).toBe(true);
	});
	it('ignores "attachment" inside a URL token', () => {
		expect(mentionsAttachment('', 'visit https://x.test/attachments/page', 'en')).toBe(false);
	});
});
