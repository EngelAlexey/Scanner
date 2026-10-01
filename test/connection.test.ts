import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { checkHsts } from '../src/checks/connection.ts';
import type { CheckResult } from '../src/contract/types.ts';

function outcome(result: CheckResult): string {
	return result.findings[0]?.code ?? result.passed[0] ?? 'none';
}

describe('checkHsts', () => {
	for (const [values, expected] of [
		[['max-age=63072000'], 'hsts'],
		[['max-age=31536000; includeSubDomains; preload'], 'hsts'],
		[['max-age="31536000"'], 'hsts'],
		[['MAX-AGE=31536000'], 'hsts'],
		[['max-age=86400'], 'hsts-short'],
		[['max-age=0'], 'hsts-missing'],
		[['max-age=abc'], 'hsts-missing'],
		[['includeSubDomains'], 'hsts-missing'],
		[['max-age=1; max-age=2'], 'hsts-missing'],
		[['max-age=bad', 'max-age=31536000'], 'hsts-missing']
	] as const) {
		test(`${values.join(' | ')} -> ${expected}`, () => {
			assert.equal(outcome(checkHsts({ 'strict-transport-security': values }, true)), expected);
		});
	}

	test('a missing header is hsts-missing', () => {
		assert.equal(outcome(checkHsts({}, true)), 'hsts-missing');
	});

	test('the header does not count over http', () => {
		assert.equal(outcome(checkHsts({ 'strict-transport-security': ['max-age=63072000'] }, false)), 'hsts-missing');
	});

	test('a short max-age is reported as evidence', () => {
		const result = checkHsts({ 'strict-transport-security': ['max-age=86400'] }, true);
		assert.deepEqual(result.findings[0]?.evidence, { maxAge: 86400 });
	});
});
