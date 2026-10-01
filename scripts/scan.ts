import { FINDINGS } from '../src/contract/codes.ts';
import { parseTarget } from '../src/net/target.ts';
import { SHOWN_HEADERS, scanHeaders } from '../src/scan.ts';

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
const result = await scanHeaders(target.info);
const elapsedMs = Math.round(performance.now() - startedAt);

if (!result.ok) {
	if (asJson) {
		console.log(JSON.stringify({ host: target.info.host, error: result.error, detail: result.detail, elapsedMs }, null, '\t'));
	} else {
		console.error(`Scan failed for ${target.info.host}: ${result.error}${result.detail ? ` (${result.detail})` : ''}`);
	}
	process.exit(1);
}

const { scan } = result;

if (asJson) {
	console.log(JSON.stringify({ ...scan, elapsedMs }, null, '\t'));
	process.exit(0);
}

const sections = Object.values(scan.sections);
const findings = sections
	.flatMap((section) => section.findings)
	.toSorted((a, b) => SEVERITY_ORDER.indexOf(FINDINGS[a.code].severity) - SEVERITY_ORDER.indexOf(FINDINGS[b.code].severity));

const hostLabel = scan.displayHost === scan.host ? scan.host : `${scan.displayHost} (${scan.host})`;
console.log(`Host:      ${hostLabel}`);
console.log(`Final URL: ${scan.finalUrl} (${scan.status}, ${elapsedMs} ms)`);
for (const hop of scan.hops) {
	console.log(`Redirect:  ${hop.status} ${hop.url} -> ${hop.location}`);
}

console.log('\nHeaders');
for (const name of SHOWN_HEADERS) {
	const values = scan.headers[name] as readonly string[] | undefined;
	console.log(`  ${values ? '+' : '-'} ${name}${values ? `: ${values.join(' | ')}` : ''}`);
}

if (scan.blockedBy !== undefined) {
	console.log(`\nBlocked by ${scan.blockedBy}: no section was scored`);
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
console.log(`  ${sections.flatMap((section) => section.passed).join(', ') || 'none'}`);

const notes = sections.flatMap((section) => section.notes);
if (notes.length > 0) {
	console.log('\nNotes');
	console.log(`  ${notes.join(', ')}`);
}
