import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { checkHeaders } from '../src/checks/headers.ts';
import type { CheckResult, HeaderMap } from '../src/contract/types.ts';

function codes(result: CheckResult): string[] {
	return result.findings.map((finding) => finding.code);
}

const ALEXHERRERA_2026_09_30: HeaderMap = {
	'strict-transport-security': ['max-age=63072000'],
	'x-frame-options': ['DENY'],
	'x-content-type-options': ['nosniff'],
	'referrer-policy': ['strict-origin-when-cross-origin'],
	'server': ['Vercel']
};

const SECURE_BASE: HeaderMap = {
	'content-security-policy': ["default-src 'self'"],
	'x-frame-options': ['DENY'],
	'x-content-type-options': ['nosniff'],
	'referrer-policy': ['no-referrer'],
	'permissions-policy': ['camera=(), microphone=(), geolocation=()']
};

function withHeaders(overrides: Record<string, readonly string[] | undefined>): HeaderMap {
	const headers: Record<string, readonly string[]> = { ...SECURE_BASE };
	for (const [name, values] of Object.entries(overrides)) {
		if (values === undefined) {
			delete headers[name];
		} else {
			headers[name] = values;
		}
	}
	return headers;
}

describe('checkHeaders', () => {
	test('alexherrera.dev as measured on 2026-09-30', () => {
		const result = checkHeaders(ALEXHERRERA_2026_09_30);
		assert.deepEqual(codes(result), ['csp-missing', 'permissions-policy-missing']);
		assert.deepEqual(result.passed, ['framing', 'nosniff', 'referrer-policy', 'version']);
	});

	test('a complete configuration passes every header check', () => {
		const result = checkHeaders(SECURE_BASE);
		assert.deepEqual(codes(result), []);
		assert.deepEqual(result.passed, ['csp', 'framing', 'nosniff', 'referrer-policy', 'permissions-policy', 'version']);
	});
});

describe('content security policy', () => {
	for (const [policy, expected] of [
		["script-src 'self' 'unsafe-inline'", 'csp-unsafe'],
		["script-src 'self' 'unsafe-inline' 'nonce-abc123'", null],
		["script-src 'self' 'sha256-AAAA'", null],
		['script-src https:', 'csp-unsafe'],
		['script-src *', 'csp-unsafe'],
		["script-src 'strict-dynamic' 'nonce-abc123' https:", null],
		["frame-ancestors 'none'", 'csp-unsafe'],
		["default-src *, script-src 'self'", null],
		["default-src 'self'; script-src data:", 'csp-unsafe']
	] as const) {
		test(`${policy} -> ${expected ?? 'pass'}`, () => {
			const result = checkHeaders(withHeaders({ 'content-security-policy': [policy] }));
			assert.equal(codes(result).includes('csp-unsafe'), expected === 'csp-unsafe');
			assert.equal(result.passed.includes('csp'), expected === null);
		});
	}

	test('a report-only policy does not count and is noted', () => {
		const result = checkHeaders(
			withHeaders({ 'content-security-policy': undefined, 'content-security-policy-report-only': ["default-src 'self'"] })
		);
		assert.ok(codes(result).includes('csp-missing'));
		assert.deepEqual(result.notes, ['csp-report-only']);
	});

	test('a meta policy counts as enforced', () => {
		const result = checkHeaders(withHeaders({ 'content-security-policy': undefined }), { metaCsp: ["default-src 'self'"] });
		assert.ok(result.passed.includes('csp'));
	});
});

describe('frame protection', () => {
	for (const [label, overrides, protectedFrame] of [
		['X-Frame-Options SAMEORIGIN', { 'x-frame-options': ['SAMEORIGIN'] }, true],
		['X-Frame-Options ALLOW-FROM', { 'x-frame-options': ['ALLOW-FROM https://x.dev'] }, false],
		['conflicting values that include deny', { 'x-frame-options': ['deny, sameorigin'] }, true],
		['unknown values only', { 'x-frame-options': ['foo, bar'] }, false],
		['frame-ancestors * overrides X-Frame-Options DENY', { 'content-security-policy': ["default-src 'self'; frame-ancestors *"] }, false],
		["frame-ancestors 'self' without X-Frame-Options", { 'content-security-policy': ["default-src 'self'; frame-ancestors 'self'"], 'x-frame-options': undefined }, true],
		['no protection at all', { 'x-frame-options': undefined }, false]
	] as const) {
		test(`${label} -> ${protectedFrame ? 'pass' : 'framing-allowed'}`, () => {
			const result = checkHeaders(withHeaders(overrides));
			assert.equal(result.passed.includes('framing'), protectedFrame);
			assert.equal(codes(result).includes('framing-allowed'), !protectedFrame);
		});
	}
});

describe('X-Content-Type-Options', () => {
	for (const [value, passes] of [
		['nosniff', true],
		['NOSNIFF', true],
		['nosniff, other', true],
		['other, nosniff', false]
	] as const) {
		test(`${value} -> ${passes ? 'pass' : 'nosniff-missing'}`, () => {
			const result = checkHeaders(withHeaders({ 'x-content-type-options': [value] }));
			assert.equal(result.passed.includes('nosniff'), passes);
		});
	}
});

describe('Referrer-Policy', () => {
	for (const [values, passes] of [
		[['unsafe-url'], false],
		[['unsafe-url, strict-origin'], true],
		[['strict-origin, unsafe-url'], false],
		[['no-referrer-when-downgrade'], false],
		[['bogus'], true],
		[['origin-when-cross-origin, strict-origin-when-cross-origin'], true]
	] as const) {
		test(`${values.join(' | ')} -> ${passes ? 'pass' : 'referrer-policy-missing'}`, () => {
			const result = checkHeaders(withHeaders({ 'referrer-policy': values }));
			assert.equal(result.passed.includes('referrer-policy'), passes);
		});
	}

	test('a missing policy passes, because browsers default to strict-origin-when-cross-origin', () => {
		const result = checkHeaders(withHeaders({ 'referrer-policy': undefined }));
		assert.ok(result.passed.includes('referrer-policy'));
	});

	test('a meta referrer overrides the header', () => {
		const result = checkHeaders(withHeaders({ 'referrer-policy': ['unsafe-url'] }), { metaReferrer: 'no-referrer' });
		assert.ok(result.passed.includes('referrer-policy'));
	});
});

describe('Permissions-Policy', () => {
	test('restricting camera, microphone and geolocation passes', () => {
		const result = checkHeaders(
			withHeaders({ 'permissions-policy': ['camera=(self "https://a.dev"), microphone=(), geolocation=(self)'] })
		);
		assert.ok(result.passed.includes('permissions-policy'));
	});

	test('lists the features left open', () => {
		const result = checkHeaders(withHeaders({ 'permissions-policy': ['camera=(), microphone=*'] }));
		const finding = result.findings.find((item) => item.code === 'permissions-policy-missing');
		assert.deepEqual(finding?.evidence, { features: ['microphone', 'geolocation'] });
	});

	test('an unparseable header counts as missing', () => {
		const result = checkHeaders(withHeaders({ 'permissions-policy': ['camera none'] }));
		const finding = result.findings.find((item) => item.code === 'permissions-policy-missing');
		assert.deepEqual(finding?.evidence, { reason: 'unparseable' });
	});
});

describe('version disclosure', () => {
	for (const [name, value, discloses] of [
		['server', 'nginx/1.18.0', true],
		['server', 'nginx', false],
		['server', 'cloudflare', false],
		['server', 'Microsoft-IIS/10.0', true],
		['server', 'ATS/9.2.15', true],
		['x-powered-by', 'PHP/7.4.3', true],
		['x-powered-by', 'Express', false],
		['x-aspnet-version', '4.0.30319', true]
	] as const) {
		test(`${name}: ${value} -> ${discloses ? 'version-disclosure' : 'pass'}`, () => {
			const result = checkHeaders(withHeaders({ [name]: [value] }));
			assert.equal(codes(result).includes('version-disclosure'), discloses);
		});
	}

	test('evidence is capped at 120 characters', () => {
		const result = checkHeaders(withHeaders({ 'server': [`nginx/1.18.0 ${'x'.repeat(300)}`] }));
		const finding = result.findings.find((item) => item.code === 'version-disclosure');
		const headers = finding?.evidence?.['headers'] as readonly string[];
		assert.equal(headers[0]?.length, 120);
	});
});
