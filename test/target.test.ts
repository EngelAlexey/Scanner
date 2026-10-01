import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { parseTarget, type TargetError } from '../src/net/target.ts';

const ACCEPTED: readonly (readonly [string, string])[] = [
	['alexherrera.dev', 'alexherrera.dev'],
	['  ALEXHERRERA.DEV  ', 'alexherrera.dev'],
	['https://www.alexherrera.dev/es?x=1#top', 'www.alexherrera.dev'],
	['http://alexherrera.dev:80/', 'alexherrera.dev'],
	['https://alexherrera.dev:443', 'alexherrera.dev'],
	['alexherrera.dev.', 'alexherrera.dev'],
	['español.com', 'xn--espaol-zwa.com']
];

const REJECTED: readonly (readonly [string, TargetError])[] = [
	['', 'invalid_url'],
	['   ', 'invalid_url'],
	['x'.repeat(2049), 'invalid_url'],
	['ftp://alexherrera.dev', 'invalid_url'],
	['https://user:pw@alexherrera.dev', 'invalid_url'],
	['alexherrera.dev:8080', 'invalid_url'],
	['https://alexherrera.dev:8443', 'invalid_url'],
	['127.0.0.1', 'invalid_url'],
	['2130706433', 'invalid_url'],
	['0x7f.1', 'invalid_url'],
	['0177.0.0.1', 'invalid_url'],
	['127.1', 'invalid_url'],
	['１２７．０．０．１', 'invalid_url'],
	['https://%31%32%37.0.0.1/', 'invalid_url'],
	['[::1]', 'invalid_url'],
	['[::ffff:127.0.0.1]', 'invalid_url'],
	['co.uk', 'invalid_url'],
	['-bad-.com', 'invalid_url'],
	['under_score.com', 'invalid_url'],
	[`${'a'.repeat(64)}.com`, 'invalid_url'],
	['localhost', 'blocked_address'],
	['LOCALHOST.', 'blocked_address'],
	['foo.localhost', 'blocked_address'],
	['printer.local', 'blocked_address'],
	['su-dominio.example', 'blocked_address'],
	['foo.internal', 'blocked_address'],
	['home.arpa', 'blocked_address'],
	['intranet', 'blocked_address'],
	['foo.lan', 'blocked_address']
];

describe('parseTarget', () => {
	for (const [input, host] of ACCEPTED) {
		test(`accepts ${JSON.stringify(input)} as ${host}`, () => {
			const result = parseTarget(input);
			assert.ok(result.ok, `rejected with ${result.ok ? '' : result.error}`);
			assert.equal(result.info.host, host);
		});
	}
	for (const [input, error] of REJECTED) {
		test(`rejects ${JSON.stringify(input.length > 40 ? `${input.slice(0, 40)}...` : input)} with ${error}`, () => {
			const result = parseTarget(input);
			assert.equal(result.ok, false);
			assert.equal(result.ok ? undefined : result.error, error);
		});
	}

	test('keeps the Unicode form for display', () => {
		const result = parseTarget('español.com');
		assert.ok(result.ok);
		assert.equal(result.info.displayHost, 'español.com');
	});

	test('a subdomain shares the site and email domain of its parent', () => {
		const result = parseTarget('www.bbc.co.uk');
		assert.ok(result.ok);
		assert.equal(result.info.siteDomain, 'bbc.co.uk');
		assert.equal(result.info.emailDomain, 'bbc.co.uk');
		assert.equal(result.info.privateSuffix, false);
	});

	test('a host under a private suffix is its own site and has no email domain of its own', () => {
		const result = parseTarget('scanner-lyart-five.vercel.app');
		assert.ok(result.ok);
		assert.equal(result.info.siteDomain, 'scanner-lyart-five.vercel.app');
		assert.equal(result.info.emailDomain, 'vercel.app');
		assert.equal(result.info.privateSuffix, true);
	});
});
