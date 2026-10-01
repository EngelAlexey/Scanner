import { parseTarget } from '../src/net/target.ts';
import { scanHeaders } from '../src/scan.ts';
import { scanningEnabled } from '../src/security/availability.ts';
import { allowedOrigins, corsHeaders, isAllowedOrigin, preflight } from '../src/security/cors.ts';
import { json } from '../src/security/response-headers.ts';

const MAX_BODY_BYTES = 4096;
const UNREACHABLE_ERRORS = new Set(['timeout', 'connection_failed', 'dns_error', 'headers_too_large']);

export function OPTIONS(request: Request): Response {
	return preflight(request.headers.get('origin'), allowedOrigins());
}

async function readUrl(request: Request): Promise<string | undefined> {
	const text = await request.text();
	if (text.length > MAX_BODY_BYTES) {
		return undefined;
	}
	try {
		const body: unknown = JSON.parse(text);
		if (typeof body === 'object' && body !== null && 'url' in body && typeof body.url === 'string') {
			return body.url;
		}
	} catch {
		return undefined;
	}
	return undefined;
}

export async function POST(request: Request): Promise<Response> {
	const origin = request.headers.get('origin');
	const allowed = allowedOrigins();
	const cors = corsHeaders(origin, allowed);
	if (origin !== null && !isAllowedOrigin(origin, allowed)) {
		return json({ error: 'origin_not_allowed' }, 403, cors);
	}
	if (!scanningEnabled()) {
		return json({ error: 'disabled' }, 503, cors);
	}
	const url = await readUrl(request);
	const target = parseTarget(url ?? '');
	if (!target.ok) {
		return json({ error: target.error }, target.error === 'invalid_url' ? 400 : 422, cors);
	}
	const result = await scanHeaders(target.info);
	if (!result.ok) {
		const body = result.detail === undefined ? { error: result.error } : { error: result.error, detail: result.detail };
		return json(body, UNREACHABLE_ERRORS.has(result.error) ? 502 : 422, cors);
	}
	return json(result.scan, 200, cors);
}
