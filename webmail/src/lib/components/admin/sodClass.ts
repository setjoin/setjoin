import type { TagColor } from '$lib/components/ui/tag';

export type SodClass = 'system' | 'security' | 'audit' | null;

export interface SodClassBadgeProps {
	color: TagColor;
	label: string;
}

export function sodClassBadge(sodClass: string | null | undefined): SodClassBadgeProps {
	switch (sodClass) {
		case 'system':
			return { color: 'blue', label: '系统' };
		case 'security':
			return { color: 'rose', label: '安全' };
		case 'audit':
			return { color: 'teal', label: '审计' };
		default:
			return { color: 'gray', label: '未分类' };
	}
}

export function isCrossClass(
	candidateClass: string | null | undefined,
	targetClass: string | null | undefined
): boolean {
	if (!candidateClass || !targetClass) return false;
	return candidateClass !== targetClass;
}
