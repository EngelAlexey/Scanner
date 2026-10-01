import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { hashClientIp, normalizeClientIp, readClientIp } from '../src/security/client-ip.ts';

const SECRET = 'a-test-secret-that-is-long-enough-1234';
const NOON = new Date('2026-10-05T12:10:00Z');
const NOON_LATER = new Date('2026-10-05T12:59:59Z');
const ONE_PM = new Date('2026-10-05T13:00:00Z');

describe('normalizeClientIp', () => {
	for (const [input, expected] of [
		['203.0.113.7', '203.0.113.7'],
		[' 203.0.113.7 ', '203.0.113.7'],
		['::ffff:203.0.113.7', '203.0.113.7'],
		['2001:db8:1:2:3:4:5:6', '2001:db8:1:2::/64'],
		['2001:db8:1:2::ffff', '2001:db8:1:2::/64'],
		['::1', '::/64']
	] as const) {
		test(`reads ${input} as ${expected}`, () => {
			assert.equal(normalizeClientIp(input), expected);
		});
	}

	for (const input of ['', 'localhost', '0x7f.1', '2130706433', '203.0.113', '203.0.113.7, 198.51.100.1']) {
		test(`rejects ${JSON.stringify(input)}`, () => {
			assert.equal(normalizeClientIp(input), undefined);
		});
	}
});

describe('hashClientIp', () => {
	test('gives the same hash within one hour', () => {
		assert.equal(hashClientIp('203.0.113.7', SECRET, NOON), hashClientIp('203.0.113.7', SECRET, NOON_LATER));
	});

	test('gives unrelated hashes in two different hours', () => {
		assert.notEqual(hashClientIp('203.0.113.7', SECRET, NOON), hashClientIp('203.0.113.7', SECRET, ONE_PM));
	});

	test('depends on the secret', () => {
		assert.notEqual(hashClientIp('203.0.113.7', SECRET, NOON), hashClientIp('203.0.113.7', `${SECRET}x`, NOON));
	});
});

describe('readClientIp', () => {
	const request = (ip?: string): Request =>
		new Request('https://api.example.test/v1/scans', { method: 'POST', headers: ip === undefined ? {} : { 'x-real-ip': ip } });

	test('two addresses in the same IPv6 /64 share one hash', () => {
		const first = readClientIp(request('2001:db8:1:2::1'), SECRET, NOON);
		const second = readClientIp(request('2001:db8:1:2:aaaa::9'), SECRET, NOON);
		assert.ok(first.ok && second.ok);
		assert.equal(first.hash, second.hash);
	});

	test('keeps the raw address for Turnstile', () => {
		const client = readClientIp(request('203.0.113.7'), SECRET, NOON);
		assert.ok(client.ok);
		assert.equal(client.address, '203.0.113.7');
	});

	test('fails without x-real-ip', () => {
		assert.equal(readClientIp(request(), SECRET, NOON).ok, false);
	});

	test('fails with a malformed x-real-ip', () => {
		assert.equal(readClientIp(request('not-an-ip'), SECRET, NOON).ok, false);
	});
});
