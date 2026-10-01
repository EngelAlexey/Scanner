import { FINDINGS, SECTIONS, SEVERITIES } from '../src/contract/codes.ts';
import { resolveHost } from '../src/net/resolver.ts';
import { parseTarget } from '../src/net/target.ts';
import { SHOWN_HEADERS, scanSite } from '../src/scan.ts';

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
const resolution = await resolveHost(target.info.host);
if (!resolution.ok) {
	console.error(`Scan failed for ${target.info.host}: ${resolution.error}`);
	process.exit(1);
}
const result = await scanSite(target.info, resolution);
const elapsedMs = Math.round(performance.now() - startedAt);

if (!result.ok) {
	if (asJson) {
		console.log(JSON.stringify({ host: target.info.host, error: result.error, elapsedMs }, null, '\t'));
	} else {
		console.error(`Scan failed for ${target.info.host}: ${result.error}`);
	}
	process.exit(1);
}

const { scan } = result;

if (asJson) {
	console.log(JSON.stringify({ ...scan, elapsedMs }, null, '\t'));
	process.exit(0);
}

const hostLabel = scan.displayHost === scan.host ? scan.host : `${scan.displayHost} (${scan.host})`;
console.log(`Host:      ${hostLabel}`);
console.log(`Final URL: ${scan.finalUrl ?? 'none'} (${scan.status ?? '-'}, ${elapsedMs} ms)`);
for (const hop of scan.hops) {
	console.log(`Redirect:  ${hop.status} ${hop.url} -> ${hop.location}`);
}
if (scan.blockedBy !== undefined) {
	console.log(`Blocked:   ${scan.blockedBy}`);
}

console.log('\nHeaders');
for (const name of SHOWN_HEADERS) {
	const values = scan.headers[name] as readonly string[] | undefined;
	console.log(`  ${values ? '+' : '-'} ${name}${values ? `: ${values.join(' | ')}` : ''}`);
}

for (const id of SECTIONS) {
	const section = scan.sections[id];
	console.log(`\n${id} [${section.status}]`);
	const findings = section.findings.toSorted((a, b) => SEVERITIES.indexOf(FINDINGS[a.code].severity) - SEVERITIES.indexOf(FINDINGS[b.code].severity));
	for (const finding of findings) {
		const evidence = finding.evidence ? ` ${JSON.stringify(finding.evidence)}` : '';
		console.log(`  [${FINDINGS[finding.code].severity}] ${finding.code}${evidence}`);
	}
	if (section.passed.length > 0) {
		console.log(`  passed: ${section.passed.join(', ')}`);
	}
	if (section.notes.length > 0) {
		console.log(`  notes: ${section.notes.join(', ')}`);
	}
}
