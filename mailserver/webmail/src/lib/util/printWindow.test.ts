import { describe, it, expect } from 'vitest';
import { escapeHtml } from './printWindow';

// Guards the XSS-escaping primitive shared by the mail + calendar print paths did
// not regress when it moved out of printMessage.ts / printAgenda.ts.
describe('escapeHtml', () => {
	it('escapes &, <, >, and " so injected markup cannot execute', () => {
		expect(escapeHtml('<img src=x onerror=alert(1)>&"quote"')).toBe(
			'&lt;img src=x onerror=alert(1)&gt;&amp;&quot;quote&quot;',
		);
	});

	it('escapes single quotes so single-quoted attribute contexts stay inert', () => {
		expect(escapeHtml("'; DROP TABLE x; '")).toBe(
			'&#39;; DROP TABLE x; &#39;',
		);
		expect(escapeHtml("'<img src=x onerror=alert(1)>'")).toBe(
			'&#39;&lt;img src=x onerror=alert(1)&gt;&#39;',
		);
	});
});
