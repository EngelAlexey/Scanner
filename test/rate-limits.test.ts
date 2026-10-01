import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { consumeQuota, DAILY_LIMIT, IP_LIMIT_PER_HOUR, memoryRateLimitStore } from '../src/store/rate-limits.ts';

const AT = new Date('2026-10-05T12:15:00Z');

describe('consumeQuota', () => {
	test(`allows ${IP_LIMIT_PER_HOUR} scans per hour and refuses the next one until the hour ends`, async () => {
		const store = memoryRateLimitStore();
		for (let i = 0; i < IP_LIMIT_PER_HOUR; i++) {
			assert.deepEqual(await consumeQuota(store, 'hash', AT), { ok: true });
		}
		assert.deepEqual(await consumeQuota(store, 'hash', AT), { ok: false, error: 'rate_limited', retryAfter: 45 * 60 });
	});

	test('starts again in the next hour', async () => {
		const store = memoryRateLimitStore();
		for (let i = 0; i <= IP_LIMIT_PER_HOUR; i++) {
			await consumeQuota(store, 'hash', AT);
		}
		assert.deepEqual(await consumeQuota(store, 'hash', new Date('2026-10-05T13:00:01Z')), { ok: true });
	});

	test('counts each visitor separately', async () => {
		const store = memoryRateLimitStore();
		for (let i = 0; i < IP_LIMIT_PER_HOUR; i++) {
			await consumeQuota(store, 'first', AT);
		}
		assert.deepEqual(await consumeQuota(store, 'second', AT), { ok: true });
	});

	test(`stops every visitor after ${DAILY_LIMIT} scans in a UTC day`, async () => {
		const store = memoryRateLimitStore();
		store.windows.set('day@2026-10-05T00:00:00.000Z', DAILY_LIMIT);
		assert.deepEqual(await consumeQuota(store, 'hash', AT), {
			ok: false,
			error: 'daily_limit',
			retryAfter: 11 * 3600 + 45 * 60
		});
	});

	test('never asks to wait less than a second', async () => {
		const store = memoryRateLimitStore();
		const lastMoment = new Date('2026-10-05T12:59:59.999Z');
		for (let i = 0; i < IP_LIMIT_PER_HOUR; i++) {
			await consumeQuota(store, 'hash', lastMoment);
		}
		const result = await consumeQuota(store, 'hash', lastMoment);
		assert.ok(!result.ok && result.retryAfter === 1);
	});
});
