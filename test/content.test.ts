import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { checkPageContent, checkSecurityTxt, decodeBody, extractPage } from '../src/checks/content.ts';
import type { HeaderMap } from '../src/contract/types.ts';
import type { FetchedPage, FetchResult } from '../src/net/safe-request.ts';

const URL_HTTPS = 'https://www.shop-test.dev/';
const NOW = new Date('2026-10-05T12:00:00Z');

function page(html: string, headers: HeaderMap = {}, truncated = false): FetchedPage {
	return {
		url: URL_HTTPS,
		status: 200,
		headers: { 'content-type': ['text/html; charset=utf-8'], ...headers },
		body: Buffer.from(html),
		truncated,
		bodyReadable: true,
		hops: [],
		cookies: []
	};
}

function check(html: string, headers: HeaderMap = {}) {
	const fetched = page(html, headers);
	return checkPageContent(fetched, extractPage(html, fetched.url));
}

describe('extractPage', () => {
	test('resolves URLs against the page and its base element', () => {
		const facts = extractPage('<head><base href="https://cdn.shop-test.dev/assets/"></head><body><img src="logo.png"><form action="/login"></form></body>', URL_HTTPS);
		assert.deepEqual(facts.passiveResources, ['https://cdn.shop-test.dev/assets/logo.png']);
		assert.deepEqual(facts.formActions, ['https://cdn.shop-test.dev/login']);
	});

	test('reads CSP from a meta element in the head only', () => {
		const facts = extractPage(
			'<head><meta http-equiv="Content-Security-Policy" content="script-src \'self\'"></head><body><meta http-equiv="content-security-policy" content="default-src *"></body>',
			URL_HTTPS
		);
		assert.deepEqual(facts.metaCsp, ["script-src 'self'"]);
	});

	test('keeps the last referrer meta element', () => {
		const facts = extractPage('<meta name="referrer" content="unsafe-url"><meta name="Referrer" content="no-referrer">', URL_HTTPS);
		assert.equal(facts.metaReferrer, 'no-referrer');
	});

	test('ignores scripts inside a template', () => {
		const facts = extractPage('<template><script src="http://evil.dev/a.js"></script></template>', URL_HTTPS);
		assert.deepEqual(facts.activeResources, []);
	});
});

describe('checkPageContent', () => {
	test('passes a page with secure forms, resources and pinned scripts with integrity', () => {
		const html = '<form action="/login"></form><script src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js" integrity="sha384-abc"></script>';
		assert.deepEqual(check(html), { findings: [], passed: ['forms', 'mixed-content', 'sri'], notes: [] });
	});

	test('reports a form or a submit button that posts over HTTP', () => {
		const result = check('<form action="http://www.shop-test.dev/login"></form><form><button formaction="http://pay.dev/x"></button></form>');
		assert.deepEqual(result.findings, [{ code: 'form-insecure-action', evidence: { actions: ['http://pay.dev/x', 'http://www.shop-test.dev/login'] } }]);
	});

	test('reports active mixed content and notes passive mixed content', () => {
		const result = check('<script src="http://cdn.dev/a.js"></script><link rel="preload stylesheet" href="http://cdn.dev/a.css"><img src="http://cdn.dev/a.png">');
		assert.deepEqual(result.findings, [{ code: 'mixed-content', evidence: { resources: ['http://cdn.dev/a.css', 'http://cdn.dev/a.js'] } }]);
		assert.deepEqual(result.notes, ['mixed-content-passive']);
	});

	test('accepts mixed content when the CSP upgrades insecure requests', () => {
		const html = '<script src="http://cdn.dev/a.js"></script>';
		assert.deepEqual(check(html, { 'content-security-policy': ['upgrade-insecure-requests'] }).findings, []);
		assert.deepEqual(check(`<head><meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests"></head>${html}`).findings, []);
	});

	for (const src of [
		'https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js',
		'https://unpkg.com/@scope/pkg@1.2.3/dist/index.js',
		'https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js',
		'https://code.jquery.com/jquery-3.7.1.min.js'
	]) {
		test(`reports ${new URL(src).hostname} without integrity`, () => {
			assert.deepEqual(check(`<script src="${src}"></script>`).findings, [{ code: 'sri-missing', evidence: { scripts: [src] } }]);
		});
	}

	for (const src of ['https://cdn.jsdelivr.net/npm/lodash@4/lodash.min.js', 'https://unpkg.com/react@latest/umd/react.js', 'https://www.googletagmanager.com/gtag/js?id=G-1', 'https://challenges.cloudflare.com/turnstile/v0/api.js']) {
		test(`does not require integrity for ${src}`, () => {
			assert.deepEqual(check(`<script src="${src}"></script>`).findings, []);
		});
	}

	test('notes a truncated page', () => {
		const fetched = page('<p>hi</p>', {}, true);
		assert.deepEqual(checkPageContent(fetched, extractPage('<p>hi</p>', fetched.url)).notes, ['content-truncated']);
	});
});

describe('decodeBody', () => {
	test('uses the declared charset', () => {
		assert.equal(decodeBody(Buffer.from([0x63, 0x61, 0x66, 0xe9]), 'text/html; charset=windows-1252'), 'café');
	});

	test('falls back to UTF-8 for an unknown charset', () => {
		assert.equal(decodeBody(Buffer.from('café'), 'text/html; charset=nonsense'), 'café');
	});
});

describe('checkSecurityTxt', () => {
	const file = (body: string, contentType = 'text/plain; charset=utf-8', status = 200): FetchResult => ({
		ok: true,
		page: { ...page(body), url: `${URL_HTTPS}.well-known/security.txt`, status, headers: { 'content-type': [contentType] } }
	});

	test('passes a file with a contact and a future expiry', () => {
		const result = checkSecurityTxt(file('Contact: mailto:security@shop-test.dev\nExpires: 2027-01-01T00:00:00.000Z\n'), NOW);
		assert.deepEqual(result, { findings: [], passed: ['security-txt'], notes: [] });
	});

	for (const [label, result] of [
		['a missing file', file('', 'text/html', 404)],
		['an HTML page served with 200', file('<html>Not here</html>', 'text/html')],
		['a file without Contact', file('Expires: 2027-01-01T00:00:00.000Z\n')],
		['an expired file', file('Contact: mailto:a@b.dev\nExpires: 2025-01-01T00:00:00.000Z\n')],
		['a failed request', { ok: false, error: 'timeout', hops: [] } as FetchResult]
	] as const) {
		test(`reports ${label}`, () => {
			assert.deepEqual(checkSecurityTxt(result, NOW).findings, [{ code: 'security-txt-missing' }]);
		});
	}
});
