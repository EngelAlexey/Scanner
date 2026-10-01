import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import type { Resolution } from '../src/net/resolver.ts';
import type { SiteScanResult } from '../src/scan.ts';
import { SCORING_VERSION } from '../src/grade.ts';
import { handleScanRequest, type ScanRequestDeps } from '../src/scan-request.ts';
import type { TurnstileResult } from '../src/security/turnstile.ts';
import { DAILY_LIMIT, memoryRateLimitStore, type RateLimitStore } from '../src/store/rate-limits.ts';
import { memoryReportStore, type ReportStore } from '../src/store/reports.ts';

const LOCAL_ORIGIN = 'http://localhost:4321';
const AT = new Date('2026-10-05T12:15:00Z');

type Harness = {
	readonly deps: ScanRequestDeps;
	readonly store: ReturnType<typeof memoryRateLimitStore>;
	readonly reports: ReturnType<typeof memoryReportStore>;
	readonly calls: { verify: number; resolve: number; scan: number };
};

function harness(overrides: Partial<ScanRequestDeps> = {}, verdict: TurnstileResult = { ok: true }): Harness {
	const store = memoryRateLimitStore();
	const reports = memoryReportStore();
	const calls = { verify: 0, resolve: 0, scan: 0 };
	let ids = 0;
	const resolution: Resolution = { ok: true, ipv4: ['93.184.215.14'], ipv6: [] };
	const scanned: SiteScanResult = {
		ok: true,
		scan: {
			host: 'ok.fixture-scan.dev',
			displayHost: 'ok.fixture-scan.dev',
			finalUrl: 'https://ok.fixture-scan.dev/',
			status: 200,
			hops: [],
			headers: {},
			sections: {
				connection: { status: 'ok', findings: [], passed: [], notes: [] },
				headers: { status: 'ok', findings: [], passed: [], notes: [] },
				cookies: { status: 'ok', findings: [], passed: [], notes: [] },
				content: { status: 'ok', findings: [], passed: [], notes: [] },
				email: { status: 'ok', findings: [], passed: [], notes: [] }
			},
			score: 100,
			grade: 'A',
			partial: false,
			urgent: [],
			scoringVersion: SCORING_VERSION
		}
	};
	const deps: ScanRequestDeps = {
		env: { VERCEL_REGION: 'dev1' },
		now: () => AT,
		store: () => store,
		verify: async (token) => {
			calls.verify++;
			return token === 'good' ? verdict : { ok: false, error: 'turnstile_failed' };
		},
		resolve: async () => {
			calls.resolve++;
			return resolution;
		},
		scan: async (target) => {
			calls.scan++;
			return scanned.ok ? { ok: true, scan: { ...scanned.scan, host: target.host, displayHost: target.displayHost } } : scanned;
		},
		reports: () => reports,
		newId: () => `report-id-${String(++ids).padStart(12, '0')}`,
		...overrides
	};
	return { deps, store, reports, calls };
}

type Send = { readonly url?: string; readonly token?: string; readonly ip?: string | null; readonly origin?: string | null; readonly body?: string };

function send(deps: ScanRequestDeps, options: Send = {}): Promise<Response> {
	const headers: Record<string, string> = { 'content-type': 'application/json' };
	const origin = options.origin === undefined ? LOCAL_ORIGIN : options.origin;
	if (origin !== null) {
		headers['origin'] = origin;
	}
	const ip = options.ip === undefined ? '203.0.113.7' : options.ip;
	if (ip !== null) {
		headers['x-real-ip'] = ip;
	}
	const body = options.body ?? JSON.stringify({ url: options.url ?? 'ok.fixture-scan.dev', token: options.token ?? 'good' });
	return handleScanRequest(new Request('http://localhost:3000/v1/scans', { method: 'POST', headers, body }), deps);
}

async function errorOf(response: Response): Promise<unknown> {
	return ((await response.json()) as { error?: unknown }).error;
}

describe('handleScanRequest', () => {
	test('scans and answers with CORS for the allowed origin', async () => {
		const { deps, calls } = harness();
		const response = await send(deps);
		assert.equal(response.status, 200);
		assert.equal(response.headers.get('access-control-allow-origin'), LOCAL_ORIGIN);
		assert.equal(response.headers.get('cache-control'), 'no-store');
		assert.equal(calls.scan, 1);
	});

	test('the sixth scan from the same IP in one hour gets 429', async () => {
		const { deps, calls } = harness();
		for (let i = 0; i < 5; i++) {
			assert.equal((await send(deps, { url: `site${i}.fixture-scan.dev` })).status, 200);
		}
		const sixth = await send(deps, { url: 'site5.fixture-scan.dev' });
		assert.equal(sixth.status, 429);
		assert.equal(sixth.headers.get('retry-after'), String(45 * 60));
		assert.deepEqual(await sixth.json(), { error: 'rate_limited', retryAfter: 45 * 60 });
		assert.equal(calls.scan, 5);
	});

	test('addresses in the same IPv6 /64 share the limit', async () => {
		const { deps } = harness();
		for (let i = 1; i <= 5; i++) {
			await send(deps, { ip: `2001:db8:1:2::${i}`, url: `site${i}.fixture-scan.dev` });
		}
		assert.equal((await send(deps, { ip: '2001:db8:1:2:ffff::1', url: 'site6.fixture-scan.dev' })).status, 429);
		assert.equal((await send(deps, { ip: '2001:db8:1:3::1', url: 'site7.fixture-scan.dev' })).status, 200);
	});

	test('the daily limit stops everyone with 503', async () => {
		const { deps, store } = harness();
		store.windows.set('day@2026-10-05T00:00:00.000Z', DAILY_LIMIT);
		const response = await send(deps);
		assert.equal(response.status, 503);
		assert.equal(await errorOf(response), 'daily_limit');
	});

	for (const token of ['', 'fake', 'repeated']) {
		test(`a request with token ${JSON.stringify(token)} gets 403 and spends no quota`, async () => {
			const { deps, store, calls } = harness();
			const response = await send(deps, { token });
			assert.equal(response.status, 403);
			assert.equal(await errorOf(response), 'turnstile_failed');
			assert.equal(store.windows.size, 0);
			assert.equal(calls.resolve, 0);
			assert.equal(calls.scan, 0);
		});
	}

	test('a request without a body token gets 403', async () => {
		const { deps, calls } = harness();
		const response = await send(deps, { body: JSON.stringify({ url: 'ok.fixture-scan.dev' }) });
		assert.equal(response.status, 403);
		assert.equal(calls.scan, 0);
	});

	test('Turnstile outages fail closed with 503', async () => {
		const { deps, calls } = harness({}, { ok: false, error: 'turnstile_unavailable' });
		const response = await send(deps);
		assert.equal(response.status, 503);
		assert.equal(await errorOf(response), 'turnstile_unavailable');
		assert.equal(calls.scan, 0);
	});

	test('an invalid or internal address is refused before the token is checked', async () => {
		const { deps, calls } = harness();
		const internal = await send(deps, { url: 'localhost' });
		assert.equal(internal.status, 422);
		assert.equal(await errorOf(internal), 'blocked_address');
		for (const url of ['not a domain', 'http://ok.fixture-scan.dev:8080/']) {
			const response = await send(deps, { url });
			assert.equal(response.status, 400);
			assert.equal(await errorOf(response), 'invalid_url');
		}
		assert.equal(calls.verify, 0);
	});

	test('a malformed body gets 400', async () => {
		const { deps } = harness();
		assert.equal((await send(deps, { body: '{"url": 42}' })).status, 400);
		assert.equal((await send(deps, { body: 'not json' })).status, 400);
		assert.equal((await send(deps, { body: JSON.stringify({ url: 'ok.fixture-scan.dev', pad: 'x'.repeat(5000) }) })).status, 400);
	});

	test('a domain that resolves to a private address spends no quota', async () => {
		const blocked: Resolution = { ok: false, error: 'blocked_address' };
		const { deps, store, calls } = harness({ resolve: async () => blocked });
		const response = await send(deps);
		assert.equal(response.status, 422);
		assert.equal(await errorOf(response), 'blocked_address');
		assert.equal(store.windows.size, 0);
		assert.equal(calls.scan, 0);
	});

	test('another origin gets 403 without CORS headers', async () => {
		const { deps, calls } = harness();
		const response = await send(deps, { origin: 'https://evil.example' });
		assert.equal(response.status, 403);
		assert.equal(response.headers.get('access-control-allow-origin'), null);
		assert.equal(calls.verify, 0);
	});

	test('a request without x-real-ip gets 400', async () => {
		const { deps, calls } = harness();
		const response = await send(deps, { ip: null });
		assert.equal(response.status, 400);
		assert.equal(calls.verify, 0);
	});

	test('a deployment without SCANNER_ENABLED answers 503 disabled', async () => {
		const { deps, calls } = harness({ env: { VERCEL: '1', VERCEL_ENV: 'production', VERCEL_REGION: 'iad1' } });
		const response = await send(deps, { origin: null });
		assert.equal(response.status, 503);
		assert.equal(await errorOf(response), 'disabled');
		assert.equal(calls.verify, 0);
	});

	test('an enabled deployment with missing settings answers 503 unavailable', async () => {
		const env = { VERCEL: '1', VERCEL_ENV: 'production', VERCEL_REGION: 'iad1', SCANNER_ENABLED: 'true' };
		const { deps, calls } = harness({ env });
		const response = await send(deps, { origin: null });
		assert.equal(response.status, 503);
		assert.equal(await errorOf(response), 'unavailable');
		assert.equal(calls.verify, 0);
	});

	test('a broken rate limit store fails closed', async () => {
		const broken: RateLimitStore = {
			hit: async () => {
				throw new Error('database unreachable');
			}
		};
		const { deps, calls } = harness({ store: () => broken });
		const response = await send(deps);
		assert.equal(response.status, 503);
		assert.equal(await errorOf(response), 'unavailable');
		assert.equal(calls.scan, 0);
	});
});

describe('handleScanRequest reports', () => {
	type Body = Record<string, unknown> & { id: string | null; reused: boolean; createdAt: string; rescanAt: string; expiresAt: string };

	async function bodyOf(response: Response): Promise<Body> {
		return (await response.json()) as Body;
	}

	test('stores the report and answers with its id and dates', async () => {
		const { deps, reports } = harness();
		const body = await bodyOf(await send(deps));
		assert.equal(body.id, 'report-id-000000000001');
		assert.equal(body.reused, false);
		assert.equal(body.createdAt, '2026-10-05T12:15:00.000Z');
		assert.equal(body.rescanAt, '2026-10-05T13:15:00.000Z');
		assert.equal(body.expiresAt, '2026-11-04T12:15:00.000Z');
		assert.ok(reports.reports.has('report-id-000000000001'));
	});

	test('reuses a recent report of the same host without scanning or spending quota', async () => {
		const { deps, store, calls } = harness();
		await send(deps);
		const hits = [...store.windows.values()];
		const second = await bodyOf(await send(deps, { ip: '198.51.100.9' }));
		assert.equal(second.reused, true);
		assert.equal(second.id, 'report-id-000000000001');
		assert.equal(calls.scan, 1);
		assert.deepEqual([...store.windows.values()].slice(0, hits.length), hits);
		assert.equal(store.windows.size, hits.length);
	});

	test('scans again once the reuse window is over', async () => {
		let now = new Date('2026-10-05T12:15:00Z');
		const { deps, calls } = harness({ now: () => now });
		await send(deps);
		now = new Date('2026-10-05T13:15:01Z');
		const later = await bodyOf(await send(deps));
		assert.equal(later.reused, false);
		assert.equal(calls.scan, 2);
	});

	test('reuses a partial report for 5 minutes only', async () => {
		let now = new Date('2026-10-05T12:15:00Z');
		const partial: ScanRequestDeps['scan'] = async (target) => ({
			ok: true,
			scan: {
				host: target.host,
				displayHost: target.displayHost,
				finalUrl: null,
				status: null,
				hops: [],
				headers: {},
				sections: {
					connection: { status: 'ok', findings: [], passed: [], notes: [] },
					headers: { status: 'blocked', findings: [], passed: [], notes: [] },
					cookies: { status: 'blocked', findings: [], passed: [], notes: [] },
					content: { status: 'blocked', findings: [], passed: [], notes: [] },
					email: { status: 'ok', findings: [], passed: [], notes: [] }
				},
				score: 100,
				grade: 'A',
				partial: true,
				urgent: [],
				scoringVersion: SCORING_VERSION
			}
		});
		const { deps } = harness({ now: () => now, scan: partial });
		const first = await bodyOf(await send(deps));
		assert.equal(first.rescanAt, '2026-10-05T12:20:00.000Z');
		now = new Date('2026-10-05T12:19:00Z');
		assert.equal((await bodyOf(await send(deps))).reused, true);
		now = new Date('2026-10-05T12:20:01Z');
		assert.equal((await bodyOf(await send(deps))).reused, false);
	});

	test('does not reuse a report scored with other rules', async () => {
		const { deps, reports, calls } = harness();
		await send(deps);
		const stored = reports.reports.get('report-id-000000000001');
		assert.ok(stored);
		reports.reports.set(stored.id, { ...stored, scoringVersion: '0.9.0' });
		assert.equal((await bodyOf(await send(deps))).reused, false);
		assert.equal(calls.scan, 2);
	});

	test('answers with the result and no id when the report cannot be stored', async () => {
		const broken: ReportStore = {
			insert: async () => {
				throw new Error('database unreachable');
			},
			findReusable: async () => undefined,
			get: async () => undefined
		};
		const { deps } = harness({ reports: () => broken });
		const response = await send(deps);
		assert.equal(response.status, 200);
		const body = await bodyOf(response);
		assert.equal(body.id, null);
		assert.equal(body['grade'], 'A');
	});
});
