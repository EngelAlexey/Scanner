import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { checkHsts, checkHttpRedirect, checkTls } from '../src/checks/connection.ts';
import type { TlsProbe } from '../src/net/tls-probe.ts';
import type { CheckResult } from '../src/contract/types.ts';

function outcome(result: CheckResult): string {
	return result.findings[0]?.code ?? result.passed[0] ?? 'none';
}

describe('checkHsts', () => {
	for (const [values, expected] of [
		[['max-age=63072000'], 'hsts'],
		[['max-age=31536000; includeSubDomains; preload'], 'hsts'],
		[['max-age="31536000"'], 'hsts'],
		[['MAX-AGE=31536000'], 'hsts'],
		[['max-age=86400'], 'hsts-short'],
		[['max-age=0'], 'hsts-missing'],
		[['max-age=abc'], 'hsts-missing'],
		[['includeSubDomains'], 'hsts-missing'],
		[['max-age=1; max-age=2'], 'hsts-missing'],
		[['max-age=bad', 'max-age=31536000'], 'hsts-missing']
	] as const) {
		test(`${values.join(' | ')} -> ${expected}`, () => {
			assert.equal(outcome(checkHsts({ 'strict-transport-security': values }, true)), expected);
		});
	}

	test('a missing header is hsts-missing', () => {
		assert.equal(outcome(checkHsts({}, true)), 'hsts-missing');
	});

	test('the header does not count over http', () => {
		assert.equal(outcome(checkHsts({ 'strict-transport-security': ['max-age=63072000'] }, false)), 'hsts-missing');
	});

	test('a short max-age is reported as evidence', () => {
		const result = checkHsts({ 'strict-transport-security': ['max-age=86400'] }, true);
		assert.deepEqual(result.findings[0]?.evidence, { maxAge: 86400 });
	});
});

describe('checkTls', () => {
	const NOW = new Date('2026-10-05T12:00:00Z');
	const certificate = { dnsNames: ['example.com'], validFrom: '2026-01-01T00:00:00.000Z', validTo: '2027-01-01T00:00:00.000Z', issuer: 'Test CA' };
	const good: TlsProbe = {
		handshake: { ok: true, protocol: 'TLSv1.3', authorizationError: null, identityError: null, certificate },
		tls10: 'rejected',
		tls11: 'rejected'
	};
	const withHandshake = (changes: Partial<Extract<TlsProbe['handshake'], { ok: true }>>): TlsProbe => ({
		...good,
		handshake: { ...(good.handshake as Extract<TlsProbe['handshake'], { ok: true }>), ...changes }
	});
	const codes = (probe: TlsProbe): string[] => checkTls(probe, NOW).findings.map((finding) => finding.code);

	test('passes every check for a modern server with a valid certificate', () => {
		const result = checkTls(good, NOW);
		assert.deepEqual(result.findings, []);
		assert.deepEqual(result.passed, ['https', 'tls13', 'certificate', 'cert-chain', 'cert-expiry', 'tls-legacy']);
	});

	test('reports no HTTPS when the TLS 1.2+ handshake fails, even if TLS 1.0 works', () => {
		const probe: TlsProbe = { handshake: { ok: false, error: 'failed' }, tls10: 'accepted', tls11: 'rejected' };
		assert.deepEqual(codes(probe), ['https-unavailable', 'tls-legacy']);
	});

	for (const [error, code] of [
		['CERT_HAS_EXPIRED', 'cert-expired'],
		['DEPTH_ZERO_SELF_SIGNED_CERT', 'cert-untrusted'],
		['UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'cert-untrusted'],
		['UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'cert-chain-incomplete'],
		['ERR_TLS_CERT_ALTNAME_INVALID', 'cert-name-mismatch']
	] as const) {
		test(`maps ${error} to ${code}`, () => {
			assert.ok(codes(withHandshake({ authorizationError: error })).includes(code));
		});
	}

	test('reports every certificate problem at once', () => {
		const probe = withHandshake({
			authorizationError: 'DEPTH_ZERO_SELF_SIGNED_CERT',
			identityError: 'ERR_TLS_CERT_ALTNAME_INVALID',
			certificate: { ...certificate, validTo: '2026-09-01T00:00:00.000Z' }
		});
		assert.deepEqual(codes(probe), ['cert-expired', 'cert-name-mismatch', 'cert-untrusted']);
	});

	test('dates the expiry windows from the certificate', () => {
		const in20Days = withHandshake({ certificate: { ...certificate, validTo: '2026-10-25T12:00:00.000Z' } });
		const in5Days = withHandshake({ certificate: { ...certificate, validTo: '2026-10-10T12:00:00.000Z' } });
		assert.deepEqual(checkTls(in20Days, NOW).findings, [{ code: 'cert-expires-30d', evidence: { expires: '2026-10-25' } }]);
		assert.deepEqual(checkTls(in5Days, NOW).findings, [{ code: 'cert-expires-7d', evidence: { expires: '2026-10-10' } }]);
	});

	test('treats a certificate that is not valid yet as expired', () => {
		assert.deepEqual(codes(withHandshake({ certificate: { ...certificate, validFrom: '2026-11-01T00:00:00.000Z' } })), ['cert-expired']);
	});

	test('neither passes nor fails a certificate with an unknown error code', () => {
		const result = checkTls(withHandshake({ authorizationError: 'SOMETHING_NEW' }), NOW);
		assert.deepEqual(result.findings, []);
		assert.ok(!result.passed.includes('certificate'));
		assert.ok(!result.passed.includes('cert-chain'));
	});

	test('reports TLS 1.2 as the negotiated version', () => {
		assert.deepEqual(checkTls(withHandshake({ protocol: 'TLSv1.2' }), NOW).findings, [{ code: 'tls13-missing', evidence: { protocol: 'TLS 1.2' } }]);
	});

	test('lists the legacy versions accepted', () => {
		const result = checkTls({ ...good, tls10: 'accepted', tls11: 'accepted' }, NOW);
		assert.deepEqual(result.findings, [{ code: 'tls-legacy', evidence: { versions: ['TLS 1.0', 'TLS 1.1'] } }]);
	});

	test('never passes the legacy check when a probe could not run', () => {
		const result = checkTls({ ...good, tls10: 'unknown' }, NOW);
		assert.deepEqual(result.findings, []);
		assert.ok(!result.passed.includes('tls-legacy'));
	});
});

describe('checkHttpRedirect', () => {
	const page = { url: 'http://example.com/', status: 200, headers: {}, body: Buffer.alloc(0), truncated: false, bodyReadable: true, hops: [], cookies: [] };

	test('passes a redirect to HTTPS', () => {
		const result = checkHttpRedirect({ ok: true, page: { ...page, status: 301, stop: { reason: 'https', location: 'https://example.com/' } } });
		assert.deepEqual(result, { findings: [], passed: ['http-redirect'], notes: [] });
	});

	test('fails a page served over HTTP', () => {
		const result = checkHttpRedirect({ ok: true, page });
		assert.deepEqual(result.findings, [{ code: 'http-no-redirect', evidence: { url: 'http://example.com/' } }]);
	});

	test('fails a redirect to another site over HTTP', () => {
		const result = checkHttpRedirect({ ok: true, page: { ...page, status: 302, stop: { reason: 'offsite', location: 'http://other.example/' } } });
		assert.deepEqual(result.findings, [{ code: 'http-no-redirect', evidence: { url: 'http://other.example/' } }]);
	});

	for (const error of ['connection_failed', 'timeout'] as const) {
		test(`passes with a note when port 80 gives ${error}`, () => {
			assert.deepEqual(checkHttpRedirect({ ok: false, error, hops: [] }), { findings: [], passed: ['http-redirect'], notes: ['http-not-served'] });
		});
	}

	test('neither passes nor fails a broken redirect chain', () => {
		assert.deepEqual(checkHttpRedirect({ ok: false, error: 'redirect_loop', hops: [] }), { findings: [], passed: [], notes: [] });
	});
});
