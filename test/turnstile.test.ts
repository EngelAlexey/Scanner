import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import type { TurnstileConfig } from '../src/config.ts';
import { SITEVERIFY_URL, verifyTurnstile } from '../src/security/turnstile.ts';

const NOW = new Date('2026-10-05T12:00:00Z');
const CONFIG: TurnstileConfig = { secret: 'real-secret', hostnames: ['www.alexherrera.dev'], action: 'scan' };

type Call = { readonly url: string; readonly body: URLSearchParams };

function siteverify(answer: unknown, status = 200): { fetch: typeof fetch; calls: Call[] } {
	const calls: Call[] = [];
	const fake = (async (url: string | URL | Request, init?: RequestInit) => {
		calls.push({ url: String(url), body: new URLSearchParams(String(init?.body ?? '')) });
		return new Response(JSON.stringify(answer), { status });
	}) as typeof fetch;
	return { fetch: fake, calls };
}

const valid = {
	'success': true,
	'error-codes': [],
	'hostname': 'www.alexherrera.dev',
	'action': 'scan',
	'challenge_ts': '2026-10-05T11:59:00Z'
};

describe('verifyTurnstile', () => {
	test('accepts a fresh token for the right host and action', async () => {
		const { fetch, calls } = siteverify(valid);
		assert.deepEqual(await verifyTurnstile('token', '203.0.113.7', CONFIG, { fetch, now: NOW }), { ok: true });
		assert.equal(calls[0]?.url, SITEVERIFY_URL);
		assert.equal(calls[0]?.body.get('secret'), 'real-secret');
		assert.equal(calls[0]?.body.get('response'), 'token');
		assert.equal(calls[0]?.body.get('remoteip'), '203.0.113.7');
	});

	for (const [label, answer] of [
		['another hostname', { ...valid, hostname: 'evil.example' }],
		['another action', { ...valid, action: 'login' }],
		['no action', { ...valid, action: undefined }],
		['a challenge older than 300 s', { ...valid, challenge_ts: '2026-10-05T11:54:59Z' }],
		['no challenge time', { ...valid, challenge_ts: undefined }],
		['a fake token', { 'success': false, 'error-codes': ['invalid-input-response'] }],
		['a repeated token', { 'success': false, 'error-codes': ['timeout-or-duplicate'] }]
	] as const) {
		test(`rejects ${label}`, async () => {
			const { fetch } = siteverify(answer);
			assert.deepEqual(await verifyTurnstile('token', '203.0.113.7', CONFIG, { fetch, now: NOW }), {
				ok: false,
				error: 'turnstile_failed'
			});
		});
	}

	test('skips the action check when the config has none', async () => {
		const { fetch } = siteverify({ ...valid, action: undefined, hostname: 'example.com' });
		const local: TurnstileConfig = { secret: 'test', hostnames: ['example.com'], action: null };
		assert.deepEqual(await verifyTurnstile('token', '::1', local, { fetch, now: NOW }), { ok: true });
	});

	for (const token of ['', 'x'.repeat(2049)]) {
		test(`rejects a token of ${token.length} characters without calling Cloudflare`, async () => {
			const { fetch, calls } = siteverify(valid);
			const result = await verifyTurnstile(token, '203.0.113.7', CONFIG, { fetch, now: NOW });
			assert.deepEqual(result, { ok: false, error: 'turnstile_failed' });
			assert.equal(calls.length, 0);
		});
	}

	test('fails closed when Cloudflare reports an internal error', async () => {
		const { fetch } = siteverify({ 'success': false, 'error-codes': ['internal-error'] });
		const result = await verifyTurnstile('token', '203.0.113.7', CONFIG, { fetch, now: NOW });
		assert.deepEqual(result, { ok: false, error: 'turnstile_unavailable' });
	});

	test('fails closed when Cloudflare answers with an error status', async () => {
		const { fetch } = siteverify({}, 502);
		const result = await verifyTurnstile('token', '203.0.113.7', CONFIG, { fetch, now: NOW });
		assert.deepEqual(result, { ok: false, error: 'turnstile_unavailable' });
	});

	test('fails closed when Cloudflare cannot be reached', async () => {
		const unreachable = (async () => {
			throw new TypeError('fetch failed');
		}) as typeof fetch;
		const result = await verifyTurnstile('token', '203.0.113.7', CONFIG, { fetch: unreachable, now: NOW });
		assert.deepEqual(result, { ok: false, error: 'turnstile_unavailable' });
	});
});
