import { randomBytes } from 'node:crypto';
import type { SectionId } from '../contract/codes.ts';
import type { SectionResult } from '../contract/types.ts';
import type { SiteScan } from '../scan.ts';
import type { SqlClient } from './sql.ts';

export const REPORT_TTL_MS = 30 * 24 * 3_600_000;
export const FULL_REUSE_MS = 3_600_000;
export const PARTIAL_REUSE_MS = 5 * 60_000;
export const MAX_REPORT_BYTES = 8 * 1024;

const ID_PATTERN = /^[A-Za-z0-9_-]{22}$/;

export type ReportVersions = {
	readonly commit: string;
	readonly node: string;
	readonly openssl: string;
};

export type Report = SiteScan & {
	readonly id: string;
	readonly createdAt: string;
	readonly rescanAt: string;
	readonly expiresAt: string;
	readonly versions: ReportVersions;
};

export type ReportStore = {
	insert(report: Report): Promise<void>;
	findReusable(host: string, scoringVersion: string, now: Date): Promise<Report | undefined>;
	get(id: string, now: Date): Promise<Report | undefined>;
};

export function newReportId(): string {
	return randomBytes(16).toString('base64url');
}

export function isReportId(value: string): boolean {
	return ID_PATTERN.test(value);
}

export function reportVersions(env: NodeJS.ProcessEnv = process.env): ReportVersions {
	return {
		commit: env.VERCEL_GIT_COMMIT_SHA?.slice(0, 7) ?? 'dev',
		node: process.versions.node,
		openssl: process.versions.openssl
	};
}

function size(value: unknown): number {
	return Buffer.byteLength(JSON.stringify(value));
}

export function fitReport(report: Report): Report {
	if (size(report) <= MAX_REPORT_BYTES) {
		return report;
	}
	const strip = (section: SectionResult): SectionResult => ({ ...section, findings: section.findings.map(({ code }) => ({ code })) });
	const sections: Record<SectionId, SectionResult> = {
		connection: strip(report.sections.connection),
		headers: strip(report.sections.headers),
		cookies: strip(report.sections.cookies),
		content: strip(report.sections.content),
		email: strip(report.sections.email)
	};
	return { ...report, headers: {}, sections };
}

export function buildReport(scan: SiteScan, id: string, now: Date, versions: ReportVersions): Report {
	const reuse = scan.partial ? PARTIAL_REUSE_MS : FULL_REUSE_MS;
	return fitReport({
		...scan,
		id,
		createdAt: now.toISOString(),
		rescanAt: new Date(now.getTime() + reuse).toISOString(),
		expiresAt: new Date(now.getTime() + REPORT_TTL_MS).toISOString(),
		versions
	});
}

export function memoryReportStore(): ReportStore & { readonly reports: Map<string, Report> } {
	const reports = new Map<string, Report>();
	const alive = (report: Report, now: Date): boolean => Date.parse(report.expiresAt) > now.getTime();
	return {
		reports,
		async insert(report) {
			reports.set(report.id, report);
		},
		async findReusable(host, scoringVersion, now) {
			return [...reports.values()]
				.filter((report) => report.host === host && report.scoringVersion === scoringVersion && alive(report, now))
				.filter((report) => Date.parse(report.rescanAt) > now.getTime())
				.sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0];
		},
		async get(id, now) {
			const report = reports.get(id);
			return report !== undefined && alive(report, now) ? report : undefined;
		}
	};
}

export function sqlReportStore(sql: SqlClient): ReportStore {
	return {
		async insert(report) {
			await sql`
				insert into reports (id, host, status, scoring_version, data, created_at, finished_at, expires_at)
				values (${report.id}, ${report.host}, 'done', ${report.scoringVersion}, ${JSON.stringify(report)}::jsonb,
					${report.createdAt}, ${report.createdAt}, ${report.expiresAt})
			`;
		},
		async findReusable(host, scoringVersion, now) {
			const rows = await sql`
				select data from reports
				where host = ${host} and scoring_version = ${scoringVersion} and status = 'done'
					and expires_at > ${now.toISOString()} and (data->>'rescanAt')::timestamptz > ${now.toISOString()}
				order by created_at desc
				limit 1
			`;
			return rows[0]?.['data'] as Report | undefined;
		},
		async get(id, now) {
			const rows = await sql`select data from reports where id = ${id} and expires_at > ${now.toISOString()}`;
			return rows[0]?.['data'] as Report | undefined;
		}
	};
}
