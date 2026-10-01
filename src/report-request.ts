import { ipAddress } from '@vercel/functions/headers';
import { normalizeClientIp } from './security/client-ip.ts';
import { json } from './security/response-headers.ts';
import { sqlClient } from './store/sql.ts';
import { isReportId, sqlReportStore, type ReportStore } from './store/reports.ts';

export const REPORT_READS_PER_MINUTE = 60;

const MINUTE_MS = 60_000;
const PUBLIC_CORS = { 'Access-Control-Allow-Origin': '*' };
const CACHED = { 'Cache-Control': 'public, max-age=60, s-maxage=3600' };

export type ReadLimiter = {
	allow(key: string, now: Date): boolean;
};

export type ReportRequestDeps = {
	readonly env: NodeJS.ProcessEnv;
	readonly now: () => Date;
	readonly reports: (env: NodeJS.ProcessEnv) => ReportStore | undefined;
	readonly limiter: ReadLimiter;
};

export function memoryReadLimiter(limit = REPORT_READS_PER_MINUTE): ReadLimiter {
	const windows = new Map<string, { start: number; count: number }>();
	return {
		allow(key, now) {
			const start = Math.floor(now.getTime() / MINUTE_MS) * MINUTE_MS;
			const current = windows.get(key);
			if (current === undefined || current.start !== start) {
				if (windows.size > 10_000) {
					windows.clear();
				}
				windows.set(key, { start, count: 1 });
				return true;
			}
			current.count++;
			return current.count <= limit;
		}
	};
}

export const defaultDeps: ReportRequestDeps = {
	env: process.env,
	now: () => new Date(),
	reports: (env) => (env.DATABASE_URL === undefined || env.DATABASE_URL === '' ? undefined : sqlReportStore(sqlClient(env.DATABASE_URL))),
	limiter: memoryReadLimiter()
};

function reply(body: unknown, status: number, headers: Record<string, string> = {}): Response {
	return json(body, status, { ...PUBLIC_CORS, ...headers });
}

export async function handleReportRequest(request: Request, deps: ReportRequestDeps = defaultDeps): Promise<Response> {
	const id = new URL(request.url).pathname.split('/').pop() ?? '';
	if (!isReportId(id)) {
		return reply({ error: 'not_found' }, 404);
	}
	const now = deps.now();
	const client = normalizeClientIp(ipAddress(request) ?? '') ?? 'unknown';
	if (!deps.limiter.allow(client, now)) {
		return reply({ error: 'rate_limited' }, 429, { 'Retry-After': '60' });
	}
	const store = deps.reports(deps.env);
	if (store === undefined) {
		return reply({ error: 'unavailable' }, 503);
	}
	try {
		const report = await store.get(id, now);
		return report === undefined ? reply({ error: 'not_found' }, 404) : reply(report, 200, CACHED);
	} catch {
		return reply({ error: 'unavailable' }, 503);
	}
}
