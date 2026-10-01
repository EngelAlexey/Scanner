import { checkHsts } from '../src/checks/connection.ts';
import { checkHeaders } from '../src/checks/headers.ts';
import { FINDINGS } from '../src/contract/codes.ts';
import type { CheckResult } from '../src/contract/types.ts';
import { safeFetch } from '../src/net/safe-request.ts';
import { parseTarget } from '../src/net/target.ts';

const SHOWN_HEADERS = [
	'strict-transport-security',
	'content-security-policy',
	'content-security-policy-report-only',
	'x-frame-options',
	'x-content-type-options',
	'referrer-policy',
	'permissions-policy',
	'server',
	'x-powered-by'
] as const;

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const;

const args = process.argv.slice(2);
const asJson = args.includes('--json');
const input = args.find((arg) => !arg.startsWith('--'));

if (input === undefined) {
	console.error('Usage: pnpm scan <domain> [--json]');
	process.exit(2);
}

const target = parseTarget(input);
if (!target.ok) {
	console.error(`Rejected input: ${target.error}`);
	process.exit(1);
}

const startedAt = performance.now();
const result = await safeFetch(new URL(`https://${target.info.host}/`));
const elapsedMs = Math.round(performance.now() - startedAt);

if (!result.ok) {
	if (asJson) {
		console.log(JSON.stringify({ host: target.info.host, error: result.error, detail: result.detail, hops: result.hops, elapsedMs }, null, '\t'));
	} else {
		console.error(`Scan failed for ${target.info.host}: ${result.error}${result.detail ? ` (${result.detail})` : ''}`);
		for (const hop of result.hops) {
			console.error(`  ${hop.status} ${hop.url} -> ${hop.location}`);
		}
	}
	process.exit(1);
}

const { page } = result;
const secure = new URL(page.url).protocol === 'https:';
const sections: Record<string, CheckResult> = {
	connection: checkHsts(page.headers, secure),
	headers: checkHeaders(page.headers)
};
const findings = Object.values(sections)
	.flatMap((section) => section.findings)
	.toSorted((a, b) => SEVERITY_ORDER.indexOf(FINDINGS[a.code].severity) - SEVERITY_ORDER.indexOf(FINDINGS[b.code].severity));

if (asJson) {
	console.log(JSON.stringify({ host: target.info.host, finalUrl: page.url, status: page.status, hops: page.hops, elapsedMs, sections }, null, '\t'));
	process.exit(0);
}

const hostLabel = target.info.displayHost === target.info.host ? target.info.host : `${target.info.displayHost} (${target.info.host})`;
console.log(`Host:      ${hostLabel}`);
console.log(`Final URL: ${page.url} (${page.status}, ${elapsedMs} ms)`);
for (const hop of page.hops) {
	console.log(`Redirect:  ${hop.status} ${hop.url} -> ${hop.location}`);
}

console.log('\nHeaders');
for (const name of SHOWN_HEADERS) {
	const values = page.headers[name];
	console.log(`  ${values ? '+' : '-'} ${name}${values ? `: ${values.join(' | ')}` : ''}`);
}

console.log('\nFindings');
if (findings.length === 0) {
	console.log('  none');
}
for (const finding of findings) {
	const evidence = finding.evidence ? ` ${JSON.stringify(finding.evidence)}` : '';
	console.log(`  [${FINDINGS[finding.code].severity}] ${finding.code}${evidence}`);
}

console.log('\nPassed');
console.log(`  ${Object.values(sections).flatMap((section) => section.passed).join(', ') || 'none'}`);

const notes = Object.values(sections).flatMap((section) => section.notes);
if (notes.length > 0) {
	console.log('\nNotes');
	console.log(`  ${notes.join(', ')}`);
}
