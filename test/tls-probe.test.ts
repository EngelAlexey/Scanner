import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type AddressInfo, type Server } from 'node:net';
import { probeTls } from '../src/net/tls-probe.ts';
import { startTlsServer, TEST_CA, type TlsServer, type TlsServerOptions } from './helpers/tls-fixtures.ts';

const HOST = 'ok.fixture-scan.dev';
const servers = new Map<string, TlsServer>();
let silent: Server;
let silentPort = 0;

const SCENARIOS: Readonly<Record<string, TlsServerOptions>> = {
	complete: { certificate: 'ok.pem' },
	leafOnly: { certificate: 'ok.pem', chain: false },
	expired: { certificate: 'expired.pem' },
	wrongName: { certificate: 'wrong-name.pem' },
	noSan: { certificate: 'no-san.pem' },
	selfSigned: { certificate: 'self-signed.pem', chain: false },
	tls12Only: { certificate: 'ok.pem', maxVersion: 'TLSv1.2' },
	legacy: { certificate: 'ok.pem', minVersion: 'TLSv1', ciphers: 'DEFAULT:@SECLEVEL=0' }
};

function probe(scenario: string, timeoutMs?: number) {
	const server = servers.get(scenario);
	assert.ok(server);
	return probeTls(HOST, '127.0.0.1', { port: server.port, ca: [TEST_CA], ...(timeoutMs === undefined ? {} : { timeoutMs }) });
}

before(async () => {
	for (const [name, options] of Object.entries(SCENARIOS)) {
		servers.set(name, await startTlsServer(options));
	}
	silent = createServer(() => undefined);
	await new Promise<void>((resolve) => silent.listen(0, '127.0.0.1', resolve));
	silentPort = (silent.address() as AddressInfo).port;
});

after(async () => {
	await Promise.all([...servers.values()].map((server) => server.close()));
	silent.close();
});

describe('probeTls', () => {
	test('reads a valid chain negotiated over TLS 1.3', async () => {
		const result = await probe('complete');
		assert.ok(result.handshake.ok);
		assert.equal(result.handshake.protocol, 'TLSv1.3');
		assert.equal(result.handshake.authorizationError, null);
		assert.equal(result.handshake.identityError, null);
		assert.deepEqual(result.handshake.certificate.dnsNames, ['ok.fixture-scan.dev', 'www.fixture-scan.dev']);
		assert.equal(result.handshake.certificate.validTo, '2126-01-01T00:00:00.000Z');
		assert.equal(result.tls10, 'rejected');
		assert.equal(result.tls11, 'rejected');
	});

	for (const [scenario, error] of [
		['leafOnly', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE'],
		['expired', 'CERT_HAS_EXPIRED'],
		['selfSigned', 'DEPTH_ZERO_SELF_SIGNED_CERT']
	] as const) {
		test(`reports ${error} for the ${scenario} certificate`, async () => {
			const result = await probe(scenario);
			assert.ok(result.handshake.ok);
			assert.equal(result.handshake.authorizationError, error);
		});
	}

	test('reports a name mismatch on a valid chain', async () => {
		const result = await probe('wrongName');
		assert.ok(result.handshake.ok);
		assert.equal(result.handshake.authorizationError, 'ERR_TLS_CERT_ALTNAME_INVALID');
		assert.equal(result.handshake.identityError, 'ERR_TLS_CERT_ALTNAME_INVALID');
	});

	test('checks the name itself when the chain already failed', async () => {
		const expiredElsewhere = await startTlsServer({ certificate: 'expired.pem' });
		const result = await probeTls('www.fixture-scan.dev', '127.0.0.1', { port: expiredElsewhere.port, ca: [TEST_CA] });
		await expiredElsewhere.close();
		assert.ok(result.handshake.ok);
		assert.equal(result.handshake.authorizationError, 'CERT_HAS_EXPIRED');
		assert.equal(result.handshake.identityError, 'ERR_TLS_CERT_ALTNAME_INVALID');
	});

	test('treats a certificate without DNS names as a mismatch', async () => {
		const result = await probe('noSan');
		assert.ok(result.handshake.ok);
		assert.equal(result.handshake.identityError, 'NO_DNS_SUBJECT_ALT_NAME');
	});

	test('reports the negotiated TLS 1.2', async () => {
		const result = await probe('tls12Only');
		assert.ok(result.handshake.ok);
		assert.equal(result.handshake.protocol, 'TLSv1.2');
	});

	test('detects a server that accepts TLS 1.0 and TLS 1.1', async () => {
		const result = await probe('legacy');
		assert.equal(result.tls10, 'accepted');
		assert.equal(result.tls11, 'accepted');
	});

	test('reports a closed port as refused', async () => {
		const closed = await startTlsServer({ certificate: 'ok.pem' });
		await closed.close();
		const result = await probeTls(HOST, '127.0.0.1', { port: closed.port, ca: [TEST_CA] });
		assert.deepEqual(result.handshake, { ok: false, error: 'refused' });
		assert.equal(result.tls10, 'rejected');
	});

	test('gives up on a server that never answers and leaves the versions unknown', async () => {
		const result = await probeTls(HOST, '127.0.0.1', { port: silentPort, timeoutMs: 300 });
		assert.deepEqual(result.handshake, { ok: false, error: 'timeout' });
		assert.equal(result.tls10, 'unknown');
		assert.equal(result.tls11, 'unknown');
	});

	test('refuses to send an IP address as servername', async () => {
		await assert.rejects(probeTls('127.0.0.1', '127.0.0.1', { port: silentPort, timeoutMs: 300 }));
	});
});
