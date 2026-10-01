import { readFile } from 'node:fs/promises';
import { resolveHost } from '../src/net/resolver.ts';
import { parseTarget } from '../src/net/target.ts';
import { scanSite } from '../src/scan.ts';

const file = process.argv[2];
if (file === undefined) {
	console.error('Usage: pnpm calibrate <sites.txt>');
	process.exit(2);
}

const sites = (await readFile(file, 'utf8'))
	.split(/\r?\n/)
	.map((line) => line.trim())
	.filter((line) => line !== '' && !line.startsWith('#'));

function csv(values: readonly (string | number | boolean)[]): string {
	return values.map((value) => (/[",\n]/.test(String(value)) ? `"${String(value).replaceAll('"', '""')}"` : String(value))).join(',');
}

console.log(csv(['host', 'score', 'grade', 'partial', 'statuses', 'codes', 'elapsedMs', 'error']));
for (const site of sites) {
	const startedAt = performance.now();
	const target = parseTarget(site);
	if (!target.ok) {
		console.log(csv([site, '', '', '', '', '', 0, target.error]));
		continue;
	}
	const resolution = await resolveHost(target.info.host);
	if (!resolution.ok) {
		console.log(csv([target.info.host, '', '', '', '', '', Math.round(performance.now() - startedAt), resolution.error]));
		continue;
	}
	const result = await scanSite(target.info, resolution);
	const elapsed = Math.round(performance.now() - startedAt);
	if (!result.ok) {
		console.log(csv([target.info.host, '', '', '', '', '', elapsed, result.error]));
		continue;
	}
	const { scan } = result;
	const statuses = Object.entries(scan.sections)
		.filter(([, section]) => section.status !== 'ok')
		.map(([id, section]) => `${id}:${section.status}`)
		.join(' ');
	const codes = Object.values(scan.sections)
		.flatMap((section) => section.findings.map((finding) => finding.code))
		.join(' ');
	console.log(csv([scan.host, scan.score, scan.grade, scan.partial, statuses, codes, elapsed, '']));
}
