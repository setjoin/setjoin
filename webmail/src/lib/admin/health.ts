import { adminFetch } from './transport';

export interface HealthCheck {
	check_name: string;
	status: string;
	value?: number;
	threshold?: number;
	details: string;
	checked_at: string;
}

export interface HealthResponse {
	status: string;
	checks: HealthCheck[];
}

export async function adminHealth(): Promise<HealthResponse> {
	const response = await adminFetch('/admin/health');
	return (await response.json()) as HealthResponse;
}
