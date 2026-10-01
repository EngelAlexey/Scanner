import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { scanningEnabled } from '../src/security/availability.ts';

describe('scanningEnabled', () => {
	test('vercel dev is enabled', () => {
		assert.equal(scanningEnabled({ VERCEL_REGION: 'dev1' }), true);
	});

	test('deployments are disabled without the flag', () => {
		assert.equal(scanningEnabled({ VERCEL: '1', VERCEL_ENV: 'production', VERCEL_REGION: 'iad1' }), false);
		assert.equal(scanningEnabled({ VERCEL: '1', VERCEL_ENV: 'preview', VERCEL_REGION: 'iad1' }), false);
	});

	test('an unknown environment fails closed', () => {
		assert.equal(scanningEnabled({}), false);
		assert.equal(scanningEnabled({ VERCEL_ENV: 'development' }), false);
	});

	test('the flag must be exactly true', () => {
		assert.equal(scanningEnabled({ VERCEL_ENV: 'production', SCANNER_ENABLED: 'true' }), true);
		assert.equal(scanningEnabled({ VERCEL_ENV: 'production', SCANNER_ENABLED: 'TRUE' }), false);
		assert.equal(scanningEnabled({ VERCEL_ENV: 'production', SCANNER_ENABLED: '1' }), false);
		assert.equal(scanningEnabled({ VERCEL_ENV: 'preview', SCANNER_ENABLED: 'false' }), false);
	});
});
