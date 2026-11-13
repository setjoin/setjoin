// Compose-template ("Quick Parts") JMAP client — thin wrappers over
// EmailTemplate/{list,set,delete}.
//
// The gateway resolves the mailbox id from the auth context (never the request)
// and the reducer carries the ownership predicate. This module only shapes the
// call and surfaces the method-level error envelope as a thrown Error. IDs come
// back as strings from the reducer; we re-String() defensively.

import { jmapCall, getAccountId } from './client';
import type { JmapMethodResponse, EmailTemplate } from '$lib/types/jmap';

/** Throw if the gateway returned a method-level error envelope (name "error"). */
function assertOk(resp: JmapMethodResponse): JmapMethodResponse {
	if (resp && typeof resp.type === 'string') {
		throw new Error(resp.description || resp.type);
	}
	return resp;
}

/** Normalize a raw template row (ids may be numbers server-side). */
function normalize(row: EmailTemplate): EmailTemplate {
	return {
		id: String(row.id),
		name: row.name,
		subject: row.subject ?? '',
		bodyHtml: row.bodyHtml ?? '',
	};
}

/** List the account's compose templates, ordered by name. */
export async function emailTemplateList(): Promise<EmailTemplate[]> {
	const accountId = await getAccountId();
	const data = await jmapCall([['EmailTemplate/list', { accountId }, '0']]);
	const resp = assertOk(data.methodResponses[0][1] as JmapMethodResponse);
	return ((resp.list as EmailTemplate[]) ?? []).map(normalize);
}

/**
 * Create or (upsert-by-name) update a template. Returns the created/updated row.
 * An empty name throws (reducer BZ040 → invalidArguments).
 */
export async function emailTemplateSet(
	name: string,
	subject: string,
	bodyHtml: string
): Promise<EmailTemplate> {
	const accountId = await getAccountId();
	const data = await jmapCall([['EmailTemplate/set', { accountId, name, subject, bodyHtml }, '0']]);
	const resp = assertOk(data.methodResponses[0][1] as JmapMethodResponse);
	return normalize(resp.created as unknown as EmailTemplate);
}

/** Delete a template by id. */
export async function emailTemplateDelete(id: string): Promise<void> {
	const accountId = await getAccountId();
	const data = await jmapCall([['EmailTemplate/delete', { accountId, id: String(id) }, '0']]);
	assertOk(data.methodResponses[0][1] as JmapMethodResponse);
}
