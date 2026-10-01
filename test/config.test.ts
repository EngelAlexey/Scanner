import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { readConfig, TURNSTILE_TEST_SECRET } from '../src/config.ts';

const SECRET = 'x'.repeat(32);
const DEPLOYED = { VERCEL: '1', VERCEL_ENV: 'production', VERCEL_REGION: 'iad1' };

describe('readConfig', () => {
	test('vercel dev runs with the Turnstile test key and memory limits', () => {
		const result = readConfig({ VERCEL_REGION: 'dev1' });
		assert.ok(result.ok);
		assert.equal(result.config.turnstile.secret, TURNSTILE_TEST_SECRET);
		assert.deepEqual(result.config.turnstile.hostnames, ['example.com']);
		assert.equal(result.config.turnstile.action, null);
		assert.equal(result.config.databaseUrl, undefined);
		assert.ok(result.config.ipHashSecret.length >= 32);
	});

	test('a deployment lists every missing setting', () => {
		const result = readConfig(DEPLOYED);
		assert.deepEqual(result, {
			ok: false,
			problems: ['IP_HASH_SECRET', 'TURNSTILE_SECRET_KEY', 'TURNSTILE_HOSTNAMES', 'DATABASE_URL']
		});
	});

	test('a deployment refuses a Turnstile test key', () => {
		const result = readConfig({
			...DEPLOYED,
			IP_HASH_SECRET: SECRET,
			TURNSTILE_SECRET_KEY: TURNSTILE_TEST_SECRET,
			DATABASE_URL: 'postgres://db'
		});
		assert.ok(!result.ok && result.problems.includes('TURNSTILE_SECRET_KEY'));
	});

	test('a deployment refuses a short IP hash secret', () => {
		const result = readConfig({
			...DEPLOYED,
			IP_HASH_SECRET: 'short',
			TURNSTILE_SECRET_KEY: 'real',
			TURNSTILE_HOSTNAMES: 'www.alexherrera.dev',
			DATABASE_URL: 'postgres://db'
		});
		assert.deepEqual(result, { ok: false, problems: ['IP_HASH_SECRET'] });
	});

	test('a complete deployment checks the scan action and its hostnames', () => {
		const result = readConfig({
			...DEPLOYED,
			IP_HASH_SECRET: SECRET,
			TURNSTILE_SECRET_KEY: 'real',
			TURNSTILE_HOSTNAMES: ' WWW.alexherrera.dev , alexherrera.dev,',
			DATABASE_URL: 'postgres://db'
		});
		assert.ok(result.ok);
		assert.deepEqual(result.config.turnstile, {
			secret: 'real',
			hostnames: ['www.alexherrera.dev', 'alexherrera.dev'],
			action: 'scan'
		});
		assert.equal(result.config.local, false);
	});
});
