import { SECURITY_HEADERS } from './response-headers.ts';

const DEVELOPMENT_ORIGINS = ['http://localhost:4321'];
const PREFLIGHT_MAX_AGE_SECONDS = '7200';

export function allowedOrigins(env: NodeJS.ProcessEnv = process.env): readonly string[] {
	const configured = (env.ALLOWED_ORIGINS ?? '')
		.split(',')
		.map((origin) => origin.trim())
		.filter((origin) => origin !== '');
	return env.VERCEL_ENV === 'production' ? configured : [...configured, ...DEVELOPMENT_ORIGINS];
}

export function isAllowedOrigin(origin: string | null, allowed: readonly string[]): boolean {
	return origin !== null && allowed.includes(origin);
}

export function corsHeaders(origin: string | null, allowed: readonly string[]): Record<string, string> {
	if (origin === null || !isAllowedOrigin(origin, allowed)) {
		return { 'Vary': 'Origin' };
	}
	return { 'Access-Control-Allow-Origin': origin, 'Vary': 'Origin' };
}

export function preflight(origin: string | null, allowed: readonly string[]): Response {
	if (!isAllowedOrigin(origin, allowed)) {
		return new Response(null, { status: 403, headers: { ...SECURITY_HEADERS, 'Vary': 'Origin' } });
	}
	return new Response(null, {
		status: 204,
		headers: {
			...SECURITY_HEADERS,
			...corsHeaders(origin, allowed),
			'Access-Control-Allow-Methods': 'GET, POST',
			'Access-Control-Allow-Headers': 'content-type',
			'Access-Control-Max-Age': PREFLIGHT_MAX_AGE_SECONDS
		}
	});
}
