// Generated minimal service-worker dictionary. Keep this file data-only: the
// worker must never import the browser locale store or complete product catalogs.
export const PUSH_DICTIONARY = {
	en: {
		'chat.push.mentionPrefix': 'Mentioned you: ',
		'chat.list.unknownDm': 'Direct message',
	},
	de: {
		'chat.push.mentionPrefix': 'Hat dich erwähnt: ',
		'chat.list.unknownDm': 'Direktnachricht',
	},
	zh: {
		'chat.push.mentionPrefix': '提到了你：',
		'chat.list.unknownDm': '私信',
	},
} as const;

export type PushLocale = keyof typeof PUSH_DICTIONARY;
export type PushKey = keyof (typeof PUSH_DICTIONARY)['en'];

export function pushText(locale: PushLocale, key: PushKey): string {
	return PUSH_DICTIONARY[locale][key];
}
