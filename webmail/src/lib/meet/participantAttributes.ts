const EXTERNAL_ATTRIBUTE = 'setjoin.external';

/** Reads only the immutable-at-join, server-authored LiveKit attribute. */
export function isExternalParticipant(
	participant: { attributes?: Record<string, string> } | undefined,
): boolean {
	return participant?.attributes?.[EXTERNAL_ATTRIBUTE] === 'true';
}
