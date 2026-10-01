import type { SqlClient } from './sql.ts';

export const RATE_LIMIT_RETENTION_MS = 48 * 3_600_000;

export type CleanupResult = {
	readonly rateLimits: number;
	readonly reports: number;
};

export async function cleanup(sql: SqlClient, now: Date): Promise<CleanupResult> {
	const cutoff = new Date(now.getTime() - RATE_LIMIT_RETENTION_MS).toISOString();
	const limits = await sql`
		with removed as (delete from rate_limits where window_start < ${cutoff} returning 1)
		select count(*)::int as count from removed
	`;
	const reports = await sql`
		with removed as (delete from reports where expires_at < ${now.toISOString()} returning 1)
		select count(*)::int as count from removed
	`;
	return { rateLimits: Number(limits[0]?.['count'] ?? 0), reports: Number(reports[0]?.['count'] ?? 0) };
}
