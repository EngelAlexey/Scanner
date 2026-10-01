import { json } from '../src/security/response-headers.ts';

export function GET(): Response {
	return json({ ok: true, version: process.env.VERCEL_GIT_COMMIT_SHA?.slice(0, 7) ?? 'dev' });
}
