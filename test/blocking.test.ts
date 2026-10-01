import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { detectBlock, type BlockProvider } from '../src/net/blocking.ts';
import type { HeaderMap } from '../src/contract/types.ts';

function check(status: number, headers: HeaderMap, body = ''): BlockProvider | null {
	return detectBlock({ status, headers, body: Buffer.from(body) });
}

describe('detectBlock', () => {
	const cases: readonly [string, number, HeaderMap, string, BlockProvider][] = [
		['a Cloudflare challenge header', 403, { 'cf-mitigated': ['challenge'], 'server': ['cloudflare'] }, '', 'cloudflare'],
		['a Cloudflare challenge page', 503, { server: ['cloudflare'] }, '<title>Just a moment...</title>', 'cloudflare'],
		['a Cloudflare block page', 403, { server: ['cloudflare'] }, '<title>Attention Required! | Cloudflare</title>', 'cloudflare'],
		['an AWS WAF action', 202, { 'x-amzn-waf-action': ['challenge'] }, '', 'aws-waf'],
		['a CloudFront 403', 403, { 'server': ['CloudFront'], 'x-cache': ['Error from cloudfront'] }, '', 'cloudfront'],
		['an Akamai 403', 403, { server: ['AkamaiGHost'] }, '<H1>Access Denied</H1>', 'akamai'],
		['an Imperva block', 403, { 'x-iinfo': ['10-123-0 0CNN RT(1 0) q(0 -1 -1 -1) r(0 -1)'] }, '', 'imperva'],
		['an Imperva incident page', 503, { 'x-iinfo': ['10-123-0'] }, 'Incapsula incident ID: 123', 'imperva'],
		['a Sucuri block', 403, { 'x-sucuri-block': ['1'] }, '', 'sucuri'],
		['a DataDome block', 403, { 'x-datadome': ['protected'] }, '', 'datadome'],
		['any 429', 429, {}, '', 'rate-limit']
	];

	for (const [label, status, headers, body, provider] of cases) {
		test(`flags ${label}`, () => {
			assert.equal(check(status, headers, body), provider);
		});
	}

	const passes: readonly [string, number, HeaderMap, string][] = [
		['a normal page behind Cloudflare', 200, { server: ['cloudflare'], 'cf-ray': ['8f00-IAD'] }, '<title>Home</title>'],
		['a Cloudflare 403 without a challenge page', 403, { server: ['cloudflare'] }, '<title>Forbidden</title>'],
		['a page behind Imperva', 200, { 'x-iinfo': ['10-123-0'] }, '<title>Home</title>'],
		['a page behind DataDome', 200, { 'x-datadome': ['protected'] }, ''],
		['a plain 403 from the origin', 403, { server: ['nginx'] }, 'Forbidden'],
		['a plain 503 from the origin', 503, { server: ['nginx'] }, 'Maintenance']
	];

	for (const [label, status, headers, body] of passes) {
		test(`takes ${label} as the real answer`, () => {
			assert.equal(check(status, headers, body), null);
		});
	}
});
