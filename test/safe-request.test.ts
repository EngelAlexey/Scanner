import { after, before, beforeEach, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { gzipSync } from 'node:zlib';
import type { DnsClient } from '../src/net/resolver.ts';
import { DEFAULT_MAX_BYTES, safeFetch } from '../src/net/safe-request.ts';
import { fakeDns } from './helpers/fake-dns.ts';
import { testAddressPolicy } from './helpers/test-policy.ts';

type Hit = { readonly host: string; readonly path: string };

let server: Server;
let port = 0;
const hits: Hit[] = [];

function redirect(response: ServerResponse, location: string): void {
	response.writeHead(302, { Location: location });
	response.end();
}

function handle(request: IncomingMessage, response: ServerResponse): void {
	const host = request.headers.host ?? '';
	const path = request.url ?? '/';
	hits.push({ host, path });
	const chain = /^\/chain\/(\d+)$/.exec(path);
	if (chain !== null) {
		redirect(response, `/chain/${Number(chain[1]) + 1}`);
		return;
	}
	switch (path) {
		case '/':
			response.writeHead(200, { 'Content-Type': 'text/plain', 'X-Content-Type-Options': 'nosniff' });
			response.end('ok');
			return;
		case '/to-self':
			redirect(response, '/');
			return;
		case '/to-www':
			redirect(response, `http://www.fixture-scan.dev:${port}/`);
			return;
		case '/to-private':
			redirect(response, `http://private.fixture-scan.dev:${port}/`);
			return;
		case '/to-ip':
			redirect(response, `http://127.0.0.1:${port}/`);
			return;
		case '/to-port':
			redirect(response, 'http://ok.fixture-scan.dev:8443/');
			return;
		case '/to-offsite':
			redirect(response, `http://other-site.dev:${port}/`);
			return;
		case '/loop-a':
			redirect(response, '/loop-b');
			return;
		case '/loop-b':
			redirect(response, '/loop-a');
			return;
		case '/big':
			response.writeHead(200, { 'Content-Type': 'text/html' });
			response.end(Buffer.alloc(5 * 1024 * 1024, 'a'));
			return;
		case '/bomb':
			response.writeHead(200, { 'Content-Type': 'text/html', 'Content-Encoding': 'gzip' });
			response.end(gzipSync(Buffer.alloc(10 * 1024 * 1024)));
			return;
		case '/slow':
			return;
		default:
			response.writeHead(404);
			response.end();
	}
}

const zone = {
	'ok.fixture-scan.dev': { a: ['127.0.0.1'] },
	'www.fixture-scan.dev': { a: ['127.0.0.1'] },
	'private.fixture-scan.dev': { a: ['10.0.0.1'] },
	'other-site.dev': { a: ['127.0.0.1'] }
};

function fetchPath(path: string, options: { dns?: DnsClient; timeoutMs?: number } = {}) {
	return safeFetch(new URL(`http://ok.fixture-scan.dev:${port}${path}`), {
		policy: testAddressPolicy(port),
		dns: options.dns ?? fakeDns(zone),
		...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs })
	});
}

before(async () => {
	server = createServer(handle);
	await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
	port = (server.address() as AddressInfo).port;
});

after(() => {
	server.closeAllConnections();
	server.close();
});

beforeEach(() => {
	hits.length = 0;
});

describe('safeFetch', () => {
	test('connects to the validated address and sends the original host', async () => {
		const result = await fetchPath('/');
		assert.ok(result.ok);
		assert.equal(result.page.status, 200);
		assert.deepEqual(result.page.headers['x-content-type-options'], ['nosniff']);
		assert.deepEqual(hits, [{ host: `ok.fixture-scan.dev:${port}`, path: '/' }]);
	});

	test('resolves each host once, so a DNS change mid-scan has no effect', async () => {
		let answers = 0;
		const rebinding: DnsClient = {
			resolve4: async () => (answers++ === 0 ? ['127.0.0.1'] : ['10.0.0.1']),
			resolve6: async () => {
				const error: NodeJS.ErrnoException = new Error('ENODATA');
				error.code = 'ENODATA';
				throw error;
			}
		};
		const result = await fetchPath('/to-self', { dns: rebinding });
		assert.ok(result.ok);
		assert.equal(answers, 1);
		assert.equal(hits.length, 2);
	});

	test('follows a redirect inside the same site', async () => {
		const result = await fetchPath('/to-www');
		assert.ok(result.ok);
		assert.equal(result.page.url, `http://www.fixture-scan.dev:${port}/`);
		assert.equal(result.page.hops.length, 1);
	});

	test('stops after 5 redirects, so the server sees 6 requests', async () => {
		const result = await fetchPath('/chain/1');
		assert.equal(result.ok ? 'ok' : result.error, 'too_many_redirects');
		assert.equal(hits.length, 6);
	});

	test('stops at a loop', async () => {
		const result = await fetchPath('/loop-a');
		assert.equal(result.ok ? 'ok' : result.error, 'redirect_loop');
	});

	for (const [path, error] of [
		['/to-private', 'redirect_blocked'],
		['/to-ip', 'redirect_blocked'],
		['/to-port', 'redirect_blocked'],
		['/to-offsite', 'redirect_offsite']
	] as const) {
		test(`stops at ${path} with ${error} before connecting to the target`, async () => {
			const result = await fetchPath(path);
			assert.equal(result.ok ? 'ok' : result.error, error);
			assert.equal(hits.length, 1);
		});
	}

	test('refuses a start host that resolves to a private address', async () => {
		const result = await safeFetch(new URL(`http://private.fixture-scan.dev:${port}/`), {
			policy: testAddressPolicy(port),
			dns: fakeDns(zone)
		});
		assert.equal(result.ok ? 'ok' : result.error, 'blocked_address');
		assert.equal(hits.length, 0);
	});

	test('keeps exactly the first 2 MB of a large page', async () => {
		const result = await fetchPath('/big');
		assert.ok(result.ok);
		assert.equal(result.page.truncated, true);
		assert.equal(result.page.body.length, DEFAULT_MAX_BYTES);
	});

	test('cuts a gzip bomb at 2 MB after decompression', async () => {
		const result = await fetchPath('/bomb');
		assert.ok(result.ok);
		assert.equal(result.page.truncated, true);
		assert.equal(result.page.body.length, DEFAULT_MAX_BYTES);
	});

	test('gives up on a server that never answers', async () => {
		const result = await fetchPath('/slow', { timeoutMs: 300 });
		assert.equal(result.ok ? 'ok' : result.error, 'timeout');
	});
});
