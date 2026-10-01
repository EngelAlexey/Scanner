import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createServer as createHttpsServer, type Server as HttpsServer } from 'node:https';
import type { AddressInfo } from 'node:net';
import type { HostInfo } from '../src/net/target.ts';
import { scanSite } from '../src/scan.ts';
import { fakeDns, type FakeRecords } from './helpers/fake-dns.ts';
import { fixture, TEST_CA } from './helpers/tls-fixtures.ts';
import { testAddressPolicy } from './helpers/test-policy.ts';

const SITE = 'fixture-scan.dev';
const NOW = new Date('2026-10-05T12:00:00Z');
const PAGE = '<!doctype html><html><head><title>ok</title></head><body><form action="/login"></form></body></html>';
const SECURE_HEADERS = {
	'Content-Type': 'text/html; charset=utf-8',
	'Strict-Transport-Security': 'max-age=63072000',
	'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
	'X-Content-Type-Options': 'nosniff',
	'Referrer-Policy': 'strict-origin-when-cross-origin',
	'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
	'Set-Cookie': 'PHPSESSID=x; Secure; HttpOnly; SameSite=Lax'
};

let secure: HttpsServer;
let plain: Server;
let httpsPort = 0;
let httpPort = 0;

function hostOf(request: IncomingMessage): string {
	return (request.headers.host ?? '').split(':')[0] ?? '';
}

function handleHttps(request: IncomingMessage, response: ServerResponse): void {
	const host = hostOf(request);
	if (request.url === '/.well-known/security.txt') {
		response.writeHead(200, { 'Content-Type': 'text/plain' });
		response.end('Contact: mailto:security@fixture-scan.dev\nExpires: 2030-01-01T00:00:00.000Z\n');
		return;
	}
	if (host === `offsite.${SITE}`) {
		response.writeHead(302, { Location: `https://other-site.dev:${httpsPort}/` });
		response.end();
		return;
	}
	if (host === `blocked.${SITE}`) {
		response.writeHead(403, { 'Content-Type': 'text/html', 'Server': 'cloudflare', 'cf-mitigated': 'challenge' });
		response.end('<title>Just a moment...</title>');
		return;
	}
	response.writeHead(200, SECURE_HEADERS);
	response.end(PAGE);
}

function handleHttp(request: IncomingMessage, response: ServerResponse): void {
	response.writeHead(301, { Location: `https://${hostOf(request)}:${httpsPort}/` });
	response.end();
}

const email: Readonly<Record<string, FakeRecords>> = {
	[SITE]: { txt: ['v=spf1 -all'], mx: [{ exchange: `mx.${SITE}`, priority: 10 }], caa: [{ critical: 0, issue: 'letsencrypt.org' }] },
	[`_dmarc.${SITE}`]: { txt: ['v=DMARC1; p=reject'] }
};

function target(label: string): HostInfo {
	const host = `${label}.${SITE}`;
	return { host, displayHost: host, siteDomain: SITE, emailDomain: SITE, privateSuffix: false };
}

function scan(label: string, ipv4: readonly string[] = ['127.0.0.1'], ports = { https: httpsPort, http: httpPort }) {
	return scanSite(target(label), { ok: true, ipv4, ipv6: ipv4.length === 0 ? ['2001:db8::1'] : [] }, {
		policy: testAddressPolicy([ports.https, ports.http]),
		dns: fakeDns(email),
		ports,
		tlsCa: [TEST_CA],
		now: NOW
	});
}

before(async () => {
	secure = createHttpsServer({ key: fixture('leaf.key'), cert: fixture('ok.pem') + fixture('intermediate.pem') }, handleHttps);
	plain = createServer(handleHttp);
	await new Promise<void>((resolve) => secure.listen(0, '127.0.0.1', resolve));
	await new Promise<void>((resolve) => plain.listen(0, '127.0.0.1', resolve));
	httpsPort = (secure.address() as AddressInfo).port;
	httpPort = (plain.address() as AddressInfo).port;
});

after(() => {
	secure.closeAllConnections();
	secure.close();
	plain.closeAllConnections();
	plain.close();
});

describe('scanSite', () => {
	test('reviews the five sections of a well configured site', async () => {
		const result = await scan('ok');
		assert.ok(result.ok);
		const { sections } = result.scan;
		for (const section of Object.values(sections)) {
			assert.equal(section.status, 'ok');
		}
		assert.deepEqual(sections.connection.findings, []);
		assert.deepEqual(sections.connection.passed, ['https', 'tls13', 'certificate', 'cert-chain', 'cert-expiry', 'tls-legacy', 'http-redirect', 'hsts']);
		assert.deepEqual(sections.headers.findings, []);
		assert.deepEqual(sections.cookies.passed, ['cookies']);
		assert.deepEqual(sections.content.passed, ['forms', 'mixed-content', 'sri', 'security-txt']);
		assert.deepEqual(sections.email.passed, ['spf', 'dmarc', 'caa']);
		assert.equal(result.scan.finalUrl, `https://ok.${SITE}:${httpsPort}/`);
	});

	test('leaves the web sections unreviewed when the home page redirects to another site', async () => {
		const result = await scan('offsite');
		assert.ok(result.ok);
		const { sections } = result.scan;
		assert.equal(sections.headers.status, 'error');
		assert.deepEqual(sections.headers.notes, ['redirects-offsite:other-site.dev']);
		assert.equal(sections.cookies.status, 'error');
		assert.equal(sections.content.status, 'error');
		assert.equal(sections.connection.status, 'ok');
		assert.equal(sections.email.status, 'ok');
	});

	test('marks the web sections as blocked by a firewall and still scores the connection', async () => {
		const result = await scan('blocked');
		assert.ok(result.ok);
		const { sections } = result.scan;
		assert.equal(result.scan.blockedBy, 'cloudflare');
		assert.equal(sections.headers.status, 'blocked');
		assert.equal(sections.cookies.status, 'blocked');
		assert.equal(sections.content.status, 'blocked');
		assert.equal(sections.connection.status, 'ok');
		assert.ok(!sections.connection.passed.includes('hsts'));
		assert.ok(!sections.connection.findings.some((finding) => finding.code === 'hsts-missing'));
	});

	test('reports an unreachable site when nothing answers on 443 or 80', async () => {
		const closed = createServer();
		await new Promise<void>((resolve) => closed.listen(0, '127.0.0.1', resolve));
		const port = (closed.address() as AddressInfo).port;
		await new Promise<void>((resolve) => closed.close(() => resolve()));
		const result = await scan('ok', ['127.0.0.1'], { https: port, http: port });
		assert.deepEqual(result, { ok: false, error: 'connection_failed' });
	});

	test('notes an IPv6-only site once and still checks its email', async () => {
		const result = await scan('ok', []);
		assert.ok(result.ok);
		const notes = Object.values(result.scan.sections).flatMap((section) => section.notes);
		assert.deepEqual(notes.filter((note) => note === 'ipv6-only'), ['ipv6-only']);
		assert.equal(result.scan.sections.connection.status, 'error');
		assert.equal(result.scan.sections.email.status, 'ok');
	});

	test('a DNS server that never answers only leaves the email section unreviewed', async () => {
		const silent = { ...fakeDns(email), resolveTxt: () => new Promise<never>(() => undefined), resolveMx: () => new Promise<never>(() => undefined), resolveCaa: () => new Promise<never>(() => undefined) };
		const startedAt = performance.now();
		const result = await scanSite(target('ok'), { ok: true, ipv4: ['127.0.0.1'], ipv6: [] }, {
			policy: testAddressPolicy([httpsPort, httpPort]),
			dns: silent,
			ports: { https: httpsPort, http: httpPort },
			tlsCa: [TEST_CA],
			now: NOW,
			budgetMs: 1500
		});
		assert.ok(performance.now() - startedAt < 3000);
		assert.ok(result.ok);
		assert.equal(result.scan.sections.email.status, 'error');
		for (const id of ['connection', 'headers', 'cookies', 'content'] as const) {
			assert.equal(result.scan.sections[id].status, 'ok', id);
		}
		assert.equal(result.scan.partial, true);
	});

	test('gives exactly the same report when the same site is scanned twice', async () => {
		const first = await scan('ok');
		const second = await scan('ok');
		assert.ok(first.ok && second.ok);
		assert.deepEqual(second.scan, first.scan);
		assert.equal(first.scan.score, 100);
		assert.equal(first.scan.grade, 'A');
	});
});
