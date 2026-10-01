import { handleScanRequest } from '../src/scan-request.ts';
import { allowedOrigins, preflight } from '../src/security/cors.ts';

export function OPTIONS(request: Request): Response {
	return preflight(request.headers.get('origin'), allowedOrigins());
}

export function POST(request: Request): Promise<Response> {
	return handleScanRequest(request);
}
