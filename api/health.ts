// Deployment check: answers without touching the database or the network.
export function GET(): Response {
	const version = process.env.VERCEL_GIT_COMMIT_SHA?.slice(0, 7) ?? 'dev';
	return Response.json(
		{ ok: true, version },
		{
			headers: {
				'Cache-Control': 'no-store',
				'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
				'Referrer-Policy': 'no-referrer',
				'X-Content-Type-Options': 'nosniff',
				'X-Robots-Tag': 'noindex, nofollow'
			}
		}
	);
}
