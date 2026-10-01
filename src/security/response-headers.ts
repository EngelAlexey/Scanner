export const SECURITY_HEADERS: Readonly<Record<string, string>> = {
	'Cache-Control': 'no-store',
	'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
	'Referrer-Policy': 'no-referrer',
	'X-Content-Type-Options': 'nosniff',
	'X-Robots-Tag': 'noindex, nofollow'
};

export function json(body: unknown, status = 200, headers: Readonly<Record<string, string>> = {}): Response {
	return Response.json(body, { status, headers: { ...SECURITY_HEADERS, ...headers } });
}
