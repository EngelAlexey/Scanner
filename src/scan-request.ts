import { readConfig, type ScanConfig } from './config.ts';
import { resolveHost, type Resolution } from './net/resolver.ts';
import { parseTarget, type HostInfo } from './net/target.ts';
import { scanSite, type SiteScanResult } from './scan.ts';
import { scanningEnabled } from './security/availability.ts';
import { readClientIp } from './security/client-ip.ts';
import { allowedOrigins, corsHeaders, isAllowedOrigin } from './security/cors.ts';
import { json } from './security/response-headers.ts';
import { verifyTurnstile, type TurnstileResult } from './security/turnstile.ts';
import { consumeQuota, memoryRateLimitStore, sqlRateLimitStore, type QuotaResult, type RateLimitStore } from './store/rate-limits.ts';
import { sqlClient } from './store/sql.ts';

const MAX_BODY_BYTES = 4096;
const UNREACHABLE_ERRORS = new Set(['timeout', 'connection_failed', 'dns_error', 'headers_too_large']);

export type ScanRequestDeps = {
	readonly env: NodeJS.ProcessEnv;
	readonly now: () => Date;
	readonly store: (config: ScanConfig) => RateLimitStore;
	readonly verify: (token: string, remoteIp: string, config: ScanConfig) => Promise<TurnstileResult>;
	readonly resolve: (host: string) => Promise<Resolution>;
	readonly scan: (target: HostInfo, resolution: Extract<Resolution, { ok: true }>) => Promise<SiteScanResult>;
};

type ScanBody = {
	readonly url: string;
	readonly token: string;
};

let localStore: RateLimitStore | undefined;

export const defaultDeps: ScanRequestDeps = {
	env: process.env,
	now: () => new Date(),
	store: (config) =>
		config.databaseUrl === undefined ? (localStore ??= memoryRateLimitStore()) : sqlRateLimitStore(sqlClient(config.databaseUrl)),
	verify: (token, remoteIp, config) => verifyTurnstile(token, remoteIp, config.turnstile),
	resolve: (host) => resolveHost(host),
	scan: (target, resolution) => scanSite(target, resolution)
};

async function readBody(request: Request): Promise<ScanBody | undefined> {
	if (Number(request.headers.get('content-length') ?? 0) > MAX_BODY_BYTES) {
		return undefined;
	}
	const text = await request.text();
	if (text.length > MAX_BODY_BYTES) {
		return undefined;
	}
	try {
		const body: unknown = JSON.parse(text);
		if (typeof body !== 'object' || body === null || !('url' in body) || typeof body.url !== 'string') {
			return undefined;
		}
		const token = 'token' in body && typeof body.token === 'string' ? body.token : '';
		return { url: body.url, token };
	} catch {
		return undefined;
	}
}

async function spendQuota(store: () => RateLimitStore, ipHash: string, now: Date): Promise<QuotaResult | undefined> {
	try {
		return await consumeQuota(store(), ipHash, now);
	} catch {
		return undefined;
	}
}

export async function handleScanRequest(request: Request, deps: ScanRequestDeps = defaultDeps): Promise<Response> {
	const origin = request.headers.get('origin');
	const allowed = allowedOrigins(deps.env);
	const cors = corsHeaders(origin, allowed);
	const reply = (body: unknown, status: number, headers: Record<string, string> = {}): Response =>
		json(body, status, { ...cors, ...headers });

	if (origin !== null && !isAllowedOrigin(origin, allowed)) {
		return reply({ error: 'origin_not_allowed' }, 403);
	}
	if (!scanningEnabled(deps.env)) {
		return reply({ error: 'disabled' }, 503);
	}
	const configured = readConfig(deps.env);
	if (!configured.ok) {
		return reply({ error: 'unavailable' }, 503);
	}
	const { config } = configured;

	const body = await readBody(request);
	const target = parseTarget(body?.url ?? '');
	if (!target.ok) {
		return reply({ error: target.error }, target.error === 'invalid_url' ? 400 : 422);
	}

	const now = deps.now();
	const client = readClientIp(request, config.ipHashSecret, now);
	if (!client.ok) {
		return reply({ error: 'invalid_request' }, 400);
	}

	const verdict = await deps.verify(body?.token ?? '', client.address, config);
	if (!verdict.ok) {
		return reply({ error: verdict.error }, verdict.error === 'turnstile_failed' ? 403 : 503);
	}

	const resolution = await deps.resolve(target.info.host);
	if (!resolution.ok) {
		return reply({ error: resolution.error }, resolution.error === 'dns_error' ? 502 : 422);
	}

	const quota = await spendQuota(() => deps.store(config), client.hash, now);
	if (quota === undefined) {
		return reply({ error: 'unavailable' }, 503);
	}
	if (!quota.ok) {
		return reply({ error: quota.error, retryAfter: quota.retryAfter }, quota.error === 'rate_limited' ? 429 : 503, {
			'Retry-After': String(quota.retryAfter)
		});
	}

	const result = await deps.scan(target.info, resolution);
	if (!result.ok) {
		return reply({ error: result.error }, UNREACHABLE_ERRORS.has(result.error) ? 502 : 422);
	}
	return reply(result.scan, 200);
}
