import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveHost } from '../src/net/resolver.ts';
import { fakeDns } from './helpers/fake-dns.ts';

describe('resolveHost', () => {
	test('returns public addresses sorted by value', async () => {
		const dns = fakeDns({ 'site.dev': { a: ['8.8.8.8', '1.1.1.1'], aaaa: ['2606:4700:4700::1111'] } });
		const result = await resolveHost('site.dev', { dns });
		assert.deepEqual(result, { ok: true, ipv4: ['1.1.1.1', '8.8.8.8'], ipv6: ['2606:4700:4700::1111'] });
	});

	test('accepts a host with only IPv6 addresses', async () => {
		const dns = fakeDns({ 'site.dev': { aaaa: ['2606:4700:4700::1111'] } });
		const result = await resolveHost('site.dev', { dns });
		assert.deepEqual(result, { ok: true, ipv4: [], ipv6: ['2606:4700:4700::1111'] });
	});

	test('caps the address list at 16', async () => {
		const many = Array.from({ length: 20 }, (_, index) => `8.8.8.${index + 1}`);
		const dns = fakeDns({ 'site.dev': { a: many } });
		const result = await resolveHost('site.dev', { dns });
		assert.ok(result.ok);
		assert.equal(result.ipv4.length, 16);
	});

	for (const [label, records] of [
		['a private IPv4 address', { a: ['10.0.0.1'] }],
		['a public address mixed with loopback', { a: ['8.8.8.8', '127.0.0.1'] }],
		['an IPv6 loopback address', { a: ['8.8.8.8'], aaaa: ['::1'] }],
		['an IPv4-mapped private address', { aaaa: ['::ffff:10.0.0.1'] }],
		['a NAT64 address', { aaaa: ['64:ff9b::a00:1'] }],
		['a 6to4 address', { aaaa: ['2002:a00:1::'] }],
		['cloud metadata', { a: ['169.254.169.254'] }]
	] as const) {
		test(`blocks a domain that resolves to ${label}`, async () => {
			const dns = fakeDns({ 'site.dev': records });
			assert.deepEqual(await resolveHost('site.dev', { dns }), { ok: false, error: 'blocked_address' });
		});
	}

	test('reports a domain that does not exist', async () => {
		const dns = fakeDns({});
		assert.deepEqual(await resolveHost('missing.dev', { dns }), { ok: false, error: 'domain_not_found' });
	});

	test('reports a domain without address records', async () => {
		const dns = fakeDns({ 'site.dev': {} });
		assert.deepEqual(await resolveHost('site.dev', { dns }), { ok: false, error: 'domain_not_found' });
	});

	test('fails closed when the resolver cannot answer', async () => {
		const dns = fakeDns({ 'site.dev': { error: 'ESERVFAIL' } });
		assert.deepEqual(await resolveHost('site.dev', { dns }), { ok: false, error: 'dns_error' });
	});
});
