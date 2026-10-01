import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { SCORING_VERSION } from '../src/grade.ts';
import { handleReportRequest, memoryReadLimiter, type ReportRequestDeps } from '../src/report-request.ts';
import type { SiteScan } from '../src/scan.ts';
import type { SqlClient } from '../src/store/sql.ts';
import { buildReport, isReportId, MAX_REPORT_BYTES, memoryReportStore, newReportId, sqlReportStore, type Report, type ReportStore } from '../src/store/reports.ts';

const AT = new Date('2026-10-05T12:00:00Z');
const VERSIONS = { commit: 'abc1234', node: '24.19.0', openssl: '3.5.7' };

function scan(overrides: Partial<SiteScan> = {}): SiteScan {
	const empty = { status: 'ok' as const, findings: [], passed: [], notes: [] };
	return {
		host: 'shop-test.dev',
		displayHost: 'shop-test.dev',
		finalUrl: 'https://shop-test.dev/',
		status: 200,
		hops: [],
		headers: {},
		sections: { connection: empty, headers: empty, cookies: empty, content: empty, email: empty },
		score: 100,
		grade: 'A',
		partial: false,
		urgent: [],
		scoringVersion: SCORING_VERSION,
		...overrides
	};
}

describe('report ids', () => {
	test('are 22 base64url characters from 16 random bytes', () => {
		const ids = new Set(Array.from({ length: 50 }, newReportId));
		assert.equal(ids.size, 50);
		for (const id of ids) {
			assert.ok(isReportId(id), id);
		}
	});

	for (const value of ['', 'short', 'x'.repeat(23), 'has spaces in it 123456', '../../etc/passwd000000']) {
		test(`rejects ${JSON.stringify(value)}`, () => {
			assert.equal(isReportId(value), false);
		});
	}
});

describe('buildReport', () => {
	test('dates the reuse window and the expiry', () => {
		const report = buildReport(scan(), 'id', AT, VERSIONS);
		assert.equal(report.createdAt, '2026-10-05T12:00:00.000Z');
		assert.equal(report.rescanAt, '2026-10-05T13:00:00.000Z');
		assert.equal(report.expiresAt, '2026-11-04T12:00:00.000Z');
		assert.equal(buildReport(scan({ partial: true }), 'id', AT, VERSIONS).rescanAt, '2026-10-05T12:05:00.000Z');
	});

	test('drops evidence and headers to stay under 8 KB', () => {
		const long = 'x'.repeat(120);
		const findings = Array.from({ length: 20 }, () => ({ code: 'cookie-no-secure' as const, evidence: { cookies: [long, long, long, long, long] } }));
		const big = scan({ sections: { ...scan().sections, cookies: { status: 'ok', findings, passed: [], notes: [] } } });
		const report = buildReport(big, 'id', AT, VERSIONS);
		assert.ok(Buffer.byteLength(JSON.stringify(report)) <= MAX_REPORT_BYTES);
		assert.deepEqual(report.sections.cookies.findings[0], { code: 'cookie-no-secure' });
	});
});

describe('memoryReportStore', () => {
	test('hides expired reports', async () => {
		const store = memoryReportStore();
		const report = buildReport(scan(), 'a'.repeat(22), AT, VERSIONS);
		await store.insert(report);
		assert.deepEqual(await store.get(report.id, AT), report);
		assert.equal(await store.get(report.id, new Date('2026-11-04T12:00:01Z')), undefined);
	});
});

describe('sqlReportStore', () => {
	test('stores the report as JSON and filters expired rows in SQL', async () => {
		const queries: { text: string; values: unknown[] }[] = [];
		const fake = (async (strings: TemplateStringsArray, ...values: unknown[]) => {
			queries.push({ text: strings.join('?'), values });
			return [];
		}) as unknown as SqlClient;
		const store = sqlReportStore(fake);
		const report = buildReport(scan(), 'b'.repeat(22), AT, VERSIONS);
		await store.insert(report);
		await store.get(report.id, AT);
		await store.findReusable('shop-test.dev', SCORING_VERSION, AT);
		assert.match(queries[0]?.text ?? '', /insert into reports/);
		assert.equal(JSON.parse(String(queries[0]?.values[3])).id, report.id);
		assert.match(queries[1]?.text ?? '', /expires_at > \?/);
		assert.match(queries[2]?.text ?? '', /rescanAt/);
	});
});

describe('handleReportRequest', () => {
	function deps(store: ReportStore | undefined, overrides: Partial<ReportRequestDeps> = {}): ReportRequestDeps {
		return { env: {}, now: () => AT, reports: () => store, limiter: memoryReadLimiter(), ...overrides };
	}

	function get(id: string, ip = '203.0.113.7'): Request {
		return new Request(`https://api.example.test/v1/reports/${id}`, { headers: { 'x-real-ip': ip } });
	}

	test('serves a stored report with public caching and open CORS', async () => {
		const store = memoryReportStore();
		const report = buildReport(scan(), 'c'.repeat(22), AT, VERSIONS);
		await store.insert(report);
		const response = await handleReportRequest(get(report.id), deps(store));
		assert.equal(response.status, 200);
		assert.equal(response.headers.get('cache-control'), 'public, max-age=60, s-maxage=3600');
		assert.equal(response.headers.get('access-control-allow-origin'), '*');
		assert.equal(response.headers.get('x-robots-tag'), 'noindex, nofollow');
		assert.equal(((await response.json()) as Report).id, report.id);
	});

	test('answers 404 without caching for a missing or expired report', async () => {
		const response = await handleReportRequest(get('d'.repeat(22)), deps(memoryReportStore()));
		assert.equal(response.status, 404);
		assert.equal(response.headers.get('cache-control'), 'no-store');
	});

	test('answers 404 for a malformed id without touching the database', async () => {
		let asked = 0;
		const counting: ReportStore = { ...memoryReportStore(), get: async () => (asked++, undefined) };
		for (const id of ['short', 'x'.repeat(30), '%2e%2e']) {
			assert.equal((await handleReportRequest(get(id), deps(counting))).status, 404);
		}
		assert.equal(asked, 0);
	});

	test('limits reads per IP and minute', async () => {
		const limited = deps(memoryReportStore(), { limiter: memoryReadLimiter(2) });
		const id = 'e'.repeat(22);
		assert.equal((await handleReportRequest(get(id), limited)).status, 404);
		assert.equal((await handleReportRequest(get(id), limited)).status, 404);
		const third = await handleReportRequest(get(id), limited);
		assert.equal(third.status, 429);
		assert.equal(third.headers.get('retry-after'), '60');
		assert.equal((await handleReportRequest(get(id, '198.51.100.1'), limited)).status, 404);
	});

	test('fails closed when the database is missing or down', async () => {
		const id = 'f'.repeat(22);
		assert.equal((await handleReportRequest(get(id), deps(undefined))).status, 503);
		const broken: ReportStore = { ...memoryReportStore(), get: async () => Promise.reject(new Error('down')) };
		assert.equal((await handleReportRequest(get(id), deps(broken))).status, 503);
	});
});
