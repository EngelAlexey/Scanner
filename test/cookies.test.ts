import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { checkCookies, isSessionCookie, parseSetCookie } from '../src/checks/cookies.ts';

const NOW = new Date('2026-10-05T12:00:00Z');
const HOST = 'www.shop-test.dev';

function check(...headers: string[]) {
	return checkCookies(
		headers.map((header) => ({ host: HOST, header })),
		NOW
	);
}

describe('isSessionCookie', () => {
	for (const name of ['PHPSESSID', 'JSESSIONID', 'ASP.NET_SessionId', 'connect.sid', 'laravel_session', '_myapp_session', `wordpress_logged_in_${'a'.repeat(32)}`, `SESS${'b'.repeat(32)}`, 'auth_token', 'jwt']) {
		test(`treats ${name} as a session cookie`, () => {
			assert.equal(isSessionCookie(name), true);
		});
	}

	for (const name of ['XSRF-TOKEN', 'csrftoken', '_ga', '_ga_ABC123', '_gid', '__cf_bm', 'AWSALB', 'visid_incap_123', 'OptanonConsent', 'didomi_token', 'theme', 'lang']) {
		test(`does not treat ${name} as a session cookie`, () => {
			assert.equal(isSessionCookie(name), false);
		});
	}
});

describe('parseSetCookie', () => {
	test('reads the attributes regardless of case', () => {
		assert.deepEqual(parseSetCookie('sid=abc; SECURE; httponly; SameSite=LAX; Path=/app', HOST, NOW), {
			name: 'sid',
			domain: HOST,
			path: '/app',
			secure: true,
			httpOnly: true,
			sameSite: 'lax',
			deleted: false
		});
	});

	test('ignores a cookie for another domain or for a public suffix', () => {
		assert.equal(parseSetCookie('a=1; Domain=other.dev', HOST, NOW), undefined);
		assert.equal(parseSetCookie('a=1; Domain=dev', HOST, NOW), undefined);
		assert.equal(parseSetCookie('a=1; Domain=.shop-test.dev', HOST, NOW)?.domain, 'shop-test.dev');
	});

	test('marks a cookie that is being deleted', () => {
		assert.equal(parseSetCookie('a=; Max-Age=0', HOST, NOW)?.deleted, true);
		assert.equal(parseSetCookie('a=; Expires=Thu, 01 Jan 1970 00:00:00 GMT', HOST, NOW)?.deleted, true);
		assert.equal(parseSetCookie('a=1; Max-Age=60; Expires=Thu, 01 Jan 1970 00:00:00 GMT', HOST, NOW)?.deleted, false);
	});

	test('ignores a header without a name', () => {
		assert.equal(parseSetCookie('novalue', HOST, NOW), undefined);
		assert.equal(parseSetCookie('=value', HOST, NOW), undefined);
	});
});

describe('checkCookies', () => {
	test('passes well configured cookies, and passes a site without cookies', () => {
		assert.deepEqual(check('PHPSESSID=x; Secure; HttpOnly; SameSite=Lax', 'theme=dark; Secure; HttpOnly; SameSite=Strict'), {
			findings: [],
			passed: ['cookies'],
			notes: []
		});
		assert.deepEqual(check(), { findings: [], passed: ['cookies'], notes: [] });
	});

	test('rates session cookies higher than other cookies', () => {
		const result = check('PHPSESSID=x; SameSite=Lax', 'theme=dark; SameSite=Lax');
		assert.deepEqual(result.findings, [
			{ code: 'session-cookie-no-secure', evidence: { cookies: ['PHPSESSID'] } },
			{ code: 'session-cookie-no-httponly', evidence: { cookies: ['PHPSESSID'] } },
			{ code: 'cookie-no-secure', evidence: { cookies: ['theme'] } },
			{ code: 'cookie-no-httponly', evidence: { cookies: ['theme'] } }
		]);
	});

	test('reports session cookies with missing or invalid SameSite and lists each cookie once', () => {
		const result = check('session_a=1; Secure; HttpOnly', 'auth_b=2; Secure; HttpOnly; SameSite=Maybe', 'session_a=3; Secure; HttpOnly', 'theme=1; Secure; HttpOnly');
		assert.deepEqual(result.findings, [{ code: 'cookie-no-samesite', evidence: { cookies: ['auth_b', 'session_a'] } }]);
	});

	test('notes SameSite=None without Secure, which the browser rejects', () => {
		const result = check('tracker=1; SameSite=None');
		assert.deepEqual(result, { findings: [], passed: ['cookies'], notes: ['cookie-samesite-none-rejected'] });
	});

	test('skips cookies that are being deleted and keeps the last duplicate', () => {
		assert.deepEqual(check('PHPSESSID=; Max-Age=0').findings, []);
		assert.deepEqual(check('theme=1', 'theme=2; Secure; HttpOnly; SameSite=Lax').findings, []);
	});

	test('never stores cookie values in the evidence', () => {
		const text = JSON.stringify(check('PHPSESSID=very-secret-value'));
		assert.ok(!text.includes('very-secret-value'));
	});
});
