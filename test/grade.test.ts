import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import type { FindingCode, SectionId } from '../src/contract/codes.ts';
import type { SectionResult } from '../src/contract/types.ts';
import { gradeFor, score } from '../src/grade.ts';

type Sections = Record<SectionId, SectionResult>;

function sections(codes: Partial<Record<SectionId, readonly FindingCode[]>>, statuses: Partial<Record<SectionId, SectionResult['status']>> = {}): Sections {
	const build = (id: SectionId): SectionResult => ({
		status: statuses[id] ?? 'ok',
		findings: (codes[id] ?? []).map((code) => ({ code })),
		passed: [],
		notes: []
	});
	return { connection: build('connection'), headers: build('headers'), cookies: build('cookies'), content: build('content'), email: build('email') };
}

describe('gradeFor', () => {
	for (const [points, grade] of [[100, 'A'], [90, 'A'], [89, 'B'], [80, 'B'], [79, 'C'], [70, 'C'], [69, 'D'], [60, 'D'], [59, 'F'], [0, 'F']] as const) {
		test(`${points} points is ${grade}`, () => {
			assert.equal(gradeFor(points, false), grade);
		});
	}

	test('a critical finding caps the grade at D', () => {
		assert.equal(gradeFor(95, true), 'D');
		assert.equal(gradeFor(55, true), 'F');
	});
});

describe('score', () => {
	test('reproduces the calibration of alexherrera.dev from the plan', () => {
		const result = score(sections({ headers: ['csp-missing', 'permissions-policy-missing'], email: ['spf-missing', 'dmarc-missing', 'caa-missing'] }));
		assert.deepEqual(result, { score: 57, grade: 'F', partial: false, urgent: ['spf-missing', 'dmarc-missing'] });
	});

	test('gives the same result whatever the order of the findings', () => {
		const forward = score(sections({ connection: ['hsts-missing', 'tls13-missing'], headers: ['csp-missing', 'nosniff-missing'] }));
		const backward = score(sections({ headers: ['nosniff-missing', 'csp-missing'], connection: ['tls13-missing', 'hsts-missing'] }));
		assert.deepEqual(forward, backward);
	});

	test('counts a repeated code once', () => {
		const result = score(sections({ cookies: ['cookie-no-secure'], content: [] }));
		const twice = score({ ...sections({}), cookies: { status: 'ok', findings: [{ code: 'cookie-no-secure' }, { code: 'cookie-no-secure' }], passed: [], notes: [] } });
		assert.equal(twice.score, result.score);
	});

	test('does not score unreviewed sections and marks the report partial for errors and blocks', () => {
		assert.equal(score(sections({}, { headers: 'blocked' })).partial, true);
		assert.equal(score(sections({}, { content: 'error' })).partial, true);
		assert.equal(score(sections({}, { email: 'not_applicable' })).partial, false);
		assert.equal(score(sections({ email: ['spf-missing'] }, { email: 'not_applicable' })).score, 100);
	});

	test('orders urgent findings by urgency, severity and catalogue position', () => {
		const result = score(sections({ connection: ['hsts-missing', 'https-unavailable'], headers: ['csp-missing'], email: ['dmarc-missing'] }), new Set(['csp-missing']));
		assert.deepEqual(result.urgent, ['csp-missing', 'https-unavailable', 'hsts-missing', 'dmarc-missing']);
	});

	test('never goes below zero points', () => {
		assert.equal(score(sections({ connection: ['https-unavailable', 'cert-expired', 'cert-untrusted'], content: ['form-insecure-action'] })).score, 0);
	});
});
