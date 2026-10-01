import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { checkEmail } from '../src/checks/email.ts';
import type { SectionResult } from '../src/contract/types.ts';
import type { HostInfo } from '../src/net/target.ts';
import { fakeDns, type FakeRecords } from './helpers/fake-dns.ts';

const DOMAIN = 'mail-test.dev';
const TARGET: HostInfo = { host: `www.${DOMAIN}`, displayHost: `www.${DOMAIN}`, siteDomain: DOMAIN, emailDomain: DOMAIN, privateSuffix: false };
const GOOD_DMARC = { txt: ['v=DMARC1; p=reject; rua=mailto:reports@mail-test.dev'] };
const MAIL = { mx: [{ exchange: 'mx.mail-test.dev', priority: 10 }], caa: [{ critical: 0, issue: 'letsencrypt.org' }] };

function zone(spf: FakeRecords['txt'], extra: Readonly<Record<string, FakeRecords>> = {}): Record<string, FakeRecords> {
	return {
		[DOMAIN]: { ...MAIL, ...(spf === undefined ? {} : { txt: spf }) },
		[`_dmarc.${DOMAIN}`]: GOOD_DMARC,
		...extra
	};
}

async function scan(records: Readonly<Record<string, FakeRecords>>, target: HostInfo = TARGET): Promise<SectionResult> {
	return checkEmail(target, fakeDns(records));
}

function codes(result: SectionResult): string[] {
	return result.findings.map((finding) => finding.code);
}

describe('checkEmail: SPF', () => {
	test('passes a strict record that includes a provider', async () => {
		const result = await scan(zone(['v=spf1 include:_spf.provider.dev -all'], { '_spf.provider.dev': { txt: ['v=spf1 ip4:192.0.2.0/24 -all'] } }));
		assert.deepEqual(codes(result), []);
		assert.deepEqual(result.passed, ['spf', 'dmarc', 'caa']);
	});

	test('passes a soft fail record', async () => {
		assert.deepEqual(codes(await scan(zone(['v=spf1 ip4:192.0.2.1 ~all']))), []);
	});

	test('reports a domain without SPF', async () => {
		assert.deepEqual(codes(await scan(zone(['google-site-verification=abc']))), ['spf-missing']);
	});

	for (const record of ['v=spf1 +all', 'v=spf1 all', 'v=spf1 ?all', 'v=spf1 ip4:192.0.2.1', 'v=spf1 ip4:0.0.0.0/0 -all']) {
		test(`reports "${record}" as permissive`, async () => {
			const result = await scan(zone([record]));
			assert.deepEqual(result.findings, [{ code: 'spf-permissive', evidence: { record } }]);
		});
	}

	test('reports an include that lets everyone through as permissive', async () => {
		const result = await scan(zone(['v=spf1 include:open.dev -all'], { 'open.dev': { txt: ['v=spf1 +all'] } }));
		assert.deepEqual(codes(result), ['spf-permissive']);
	});

	test('follows redirect when there is no all', async () => {
		const strict = await scan(zone(['v=spf1 redirect=_spf.provider.dev'], { '_spf.provider.dev': { txt: ['v=spf1 -all'] } }));
		const open = await scan(zone(['v=spf1 redirect=_spf.provider.dev'], { '_spf.provider.dev': { txt: ['v=spf1 ?all'] } }));
		assert.deepEqual(codes(strict), []);
		assert.deepEqual(codes(open), ['spf-permissive']);
	});

	test('joins the strings of one TXT record without a separator', async () => {
		const result = await scan(zone([['v=spf1 include:_spf.prov', 'ider.dev -all']], { '_spf.provider.dev': { txt: ['v=spf1 -all'] } }));
		assert.deepEqual(codes(result), []);
	});

	test('reports more than 10 DNS lookups as invalid', async () => {
		const includes = Array.from({ length: 11 }, (_, index) => `include:i${index}.dev`).join(' ');
		const extra = Object.fromEntries(Array.from({ length: 11 }, (_, index) => [`i${index}.dev`, { txt: ['v=spf1 -all'] }]));
		assert.deepEqual(codes(await scan(zone([`v=spf1 ${includes} -all`], extra))), ['spf-invalid']);
	});

	test('reports more than 2 void lookups as invalid', async () => {
		assert.deepEqual(codes(await scan(zone(['v=spf1 a:gone1.dev a:gone2.dev a:gone3.dev -all']))), ['spf-invalid']);
	});

	test('accepts 2 void lookups', async () => {
		assert.deepEqual(codes(await scan(zone(['v=spf1 a:gone1.dev mx:gone2.dev -all']))), []);
	});

	for (const [label, records, extra] of [
		['two SPF records', ['v=spf1 -all', 'v=spf1 ~all'], {}],
		['an unknown mechanism', ['v=spf1 foo:bar.dev -all'], {}],
		['a malformed address', ['v=spf1 ip4:999.1.1.1 -all'], {}],
		['an include without SPF', ['v=spf1 include:nospf.dev -all'], { 'nospf.dev': { txt: ['hello'] } }],
		['an include loop', ['v=spf1 include:loop.dev -all'], { 'loop.dev': { txt: [`v=spf1 include:${DOMAIN} -all`] } }],
		['a repeated redirect', ['v=spf1 redirect=a.dev redirect=b.dev'], {}]
	] as const) {
		test(`reports ${label} as invalid`, async () => {
			assert.deepEqual(codes(await scan(zone([...records], extra))), ['spf-invalid']);
		});
	}

	test('notes the deprecated ptr mechanism', async () => {
		const result = await scan(zone(['v=spf1 ptr -all']));
		assert.deepEqual(codes(result), []);
		assert.ok(result.notes.includes('spf-ptr-deprecated'));
	});

	test('counts a macro include without resolving it', async () => {
		const dns = fakeDns(zone(['v=spf1 include:%{i}._spf.provider.dev -all']));
		const result = await checkEmail(TARGET, dns);
		assert.deepEqual(codes(result), []);
		assert.ok(!dns.queries.some((query) => query.includes('%')));
	});
});

describe('checkEmail: DMARC', () => {
	const withDmarc = (txt: readonly string[]) => ({ ...zone(['v=spf1 -all']), [`_dmarc.${DOMAIN}`]: { txt } });

	for (const [label, txt, code] of [
		['no record', ['some other text'], 'dmarc-missing'],
		['two records', ['v=DMARC1; p=reject', 'v=DMARC1; p=none'], 'dmarc-missing'],
		['p=none', ['v=DMARC1; p=none; rua=mailto:a@mail-test.dev'], 'dmarc-policy-none'],
		['no p tag', ['v=DMARC1; rua=mailto:a@mail-test.dev'], 'dmarc-policy-none'],
		['quarantine in testing mode', ['v=DMARC1; p=quarantine; t=y'], 'dmarc-policy-none']
	] as const) {
		test(`reports ${label}`, async () => {
			assert.deepEqual(codes(await scan(withDmarc([...txt]))), [code]);
		});
	}

	test('passes quarantine and reject', async () => {
		assert.deepEqual(codes(await scan(withDmarc(['v=DMARC1; p=quarantine']))), []);
		assert.deepEqual(codes(await scan(withDmarc(['v=DMARC1;p=reject']))), []);
	});

	test('notes testing mode and partial enforcement', async () => {
		const testing = await scan(withDmarc(['v=DMARC1; p=reject; t=y']));
		const partial = await scan(withDmarc(['v=DMARC1; p=reject; pct=50']));
		assert.deepEqual(codes(testing), []);
		assert.ok(testing.notes.includes('dmarc-testing'));
		assert.ok(partial.notes.includes('dmarc-testing'));
	});

	test('reports a domain without a _dmarc name', async () => {
		const records = zone(['v=spf1 -all']);
		delete records[`_dmarc.${DOMAIN}`];
		assert.deepEqual(codes(await scan(records)), ['dmarc-missing']);
	});
});

describe('checkEmail: MX, CAA and scope', () => {
	test('notes a domain that receives no email and keeps the SPF and DMARC findings', async () => {
		const records = zone(undefined);
		records[DOMAIN] = { caa: MAIL.caa };
		const result = await scan(records);
		assert.ok(result.notes.includes('no-mx'));
		assert.deepEqual(codes(result), ['spf-missing']);
	});

	test('treats a null MX as no email', async () => {
		const records = zone(['v=spf1 -all']);
		records[DOMAIN] = { ...records[DOMAIN], mx: [{ exchange: '', priority: 0 }] };
		assert.ok((await scan(records)).notes.includes('no-mx'));
	});

	test('finds CAA on a parent domain', async () => {
		const result = await scan(zone(['v=spf1 -all']));
		assert.ok(result.passed.includes('caa'));
	});

	test('reports a tree without CAA', async () => {
		const records = zone(['v=spf1 -all']);
		records[DOMAIN] = { mx: MAIL.mx, txt: ['v=spf1 -all'] };
		assert.deepEqual(codes(await scan(records)), ['caa-missing']);
	});

	test('does not apply to a host under a platform suffix', async () => {
		const result = await scan({}, { ...TARGET, host: 'demo.vercel.app', emailDomain: 'demo.vercel.app', privateSuffix: true });
		assert.deepEqual(result, { status: 'not_applicable', findings: [], passed: [], notes: [] });
	});

	test('returns an error when every lookup fails', async () => {
		const result = await scan({ [DOMAIN]: { error: 'ESERVFAIL' }, [`_dmarc.${DOMAIN}`]: { error: 'ESERVFAIL' }, [`www.${DOMAIN}`]: { error: 'ESERVFAIL' } });
		assert.equal(result.status, 'error');
	});

	test('keeps the other checks when one lookup fails', async () => {
		const records = zone(['v=spf1 -all']);
		records[`_dmarc.${DOMAIN}`] = { error: 'ESERVFAIL' };
		const result = await scan(records);
		assert.equal(result.status, 'ok');
		assert.deepEqual(result.passed, ['spf', 'caa']);
	});

	test('stops at the deadline', async () => {
		const slow = fakeDns(zone(['v=spf1 -all']));
		const hanging = { ...slow, resolveTxt: () => new Promise<string[][]>(() => undefined), resolveMx: () => new Promise<never>(() => undefined), resolveCaa: () => new Promise<never>(() => undefined) };
		const result = await checkEmail(TARGET, hanging, AbortSignal.timeout(200));
		assert.equal(result.status, 'error');
	});
});
