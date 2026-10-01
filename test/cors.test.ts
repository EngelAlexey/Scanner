import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { allowedOrigins, corsHeaders, preflight } from '../src/security/cors.ts';

describe('allowedOrigins', () => {
	test('production uses only the configured origins', () => {
		const origins = allowedOrigins({ VERCEL_ENV: 'production', ALLOWED_ORIGINS: 'https://www.alexherrera.dev' });
		assert.deepEqual(origins, ['https://www.alexherrera.dev']);
	});

	test('development also allows the local portfolio', () => {
		const origins = allowedOrigins({ VERCEL_ENV: 'development' });
		assert.deepEqual(origins, ['http://localhost:4321']);
	});

	test('trims and skips empty entries', () => {
		const origins = allowedOrigins({ VERCEL_ENV: 'production', ALLOWED_ORIGINS: ' https://a.dev , ,https://b.dev ' });
		assert.deepEqual(origins, ['https://a.dev', 'https://b.dev']);
	});
});

describe('corsHeaders', () => {
	const allowed = ['https://www.alexherrera.dev'];

	test('echoes an allowed origin', () => {
		assert.deepEqual(corsHeaders('https://www.alexherrera.dev', allowed), {
			'Access-Control-Allow-Origin': 'https://www.alexherrera.dev',
			'Vary': 'Origin'
		});
	});

	test('never echoes a foreign origin', () => {
		assert.deepEqual(corsHeaders('https://evil.example', allowed), { 'Vary': 'Origin' });
		assert.deepEqual(corsHeaders(null, allowed), { 'Vary': 'Origin' });
	});
});

describe('preflight', () => {
	const allowed = ['https://www.alexherrera.dev'];

	test('answers an allowed origin with 204 and a two-hour cache', () => {
		const response = preflight('https://www.alexherrera.dev', allowed);
		assert.equal(response.status, 204);
		assert.equal(response.headers.get('access-control-allow-origin'), 'https://www.alexherrera.dev');
		assert.equal(response.headers.get('access-control-max-age'), '7200');
		assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
	});

	test('refuses a foreign origin', () => {
		const response = preflight('https://evil.example', allowed);
		assert.equal(response.status, 403);
		assert.equal(response.headers.get('access-control-allow-origin'), null);
	});
});
