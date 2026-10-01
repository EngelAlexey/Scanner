import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { isCronRequest } from '../src/security/cron.ts';
import { cleanup } from '../src/store/cleanup.ts';
import type { SqlClient } from '../src/store/sql.ts';

const SECRET = 's'.repeat(32);

function cronRequest(authorization?: string): Request {
	return new Request('https://api.example.test/api/cron/cleanup', {
		headers: authorization === undefined ? {} : { authorization }
	});
}

describe('isCronRequest', () => {
	test('accepts the configured bearer secret', () => {
		assert.equal(isCronRequest(cronRequest(`Bearer ${SECRET}`), { CRON_SECRET: SECRET }), true);
	});

	test('refuses a missing or wrong secret', () => {
		assert.equal(isCronRequest(cronRequest(), { CRON_SECRET: SECRET }), false);
		assert.equal(isCronRequest(cronRequest(`Bearer ${SECRET}x`), { CRON_SECRET: SECRET }), false);
		assert.equal(isCronRequest(cronRequest(`Bearer ${'t'.repeat(32)}`), { CRON_SECRET: SECRET }), false);
	});

	test('fails closed without a long enough secret', () => {
		assert.equal(isCronRequest(cronRequest('Bearer '), {}), false);
		assert.equal(isCronRequest(cronRequest('Bearer short'), { CRON_SECRET: 'short' }), false);
	});
});

describe('cleanup', () => {
	test('deletes rate limit windows older than 48 hours and expired reports', async () => {
		const queries: { text: string; values: unknown[] }[] = [];
		const fake = (async (strings: TemplateStringsArray, ...values: unknown[]) => {
			queries.push({ text: strings.join('?'), values });
			return [{ count: queries.length }];
		}) as unknown as SqlClient;
		const result = await cleanup(fake, new Date('2026-10-05T04:00:00Z'));
		assert.deepEqual(result, { rateLimits: 1, reports: 2 });
		assert.match(queries[0]?.text ?? '', /delete from rate_limits where window_start < \?/);
		assert.deepEqual(queries[0]?.values, ['2026-10-03T04:00:00.000Z']);
		assert.match(queries[1]?.text ?? '', /delete from reports where expires_at < \?/);
		assert.deepEqual(queries[1]?.values, ['2026-10-05T04:00:00.000Z']);
	});
});
