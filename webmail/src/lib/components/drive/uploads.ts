// Shared upload-tray item shape — DriveApp owns the array, UploadProgress renders it.
export interface UploadItem {
	id: string;
	name: string;
	sent: number;
	total: number;
	status: 'uploading' | 'done' | 'error';
	errorMessage?: string;
}
