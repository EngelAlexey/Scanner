import { startOfHour } from '../security/client-ip.ts';
import type { SqlClient } from './sql.ts';

export const IP_LIMIT_PER_HOUR = 5;
export const DAILY_LIMIT = 500;

const HOUR_MS = 3_600_000;
const DAY_MS = 24 * HOUR_MS;

export type RateLimitStore = {
	hit(bucket: string, windowStart: Date): Promise<number>;
};

export type QuotaResult =
	| { readonly ok: true }
	| { readonly ok: false; readonly error: 'rate_limited' | 'daily_limit'; readonly retryAfter: number };

export function memoryRateLimitStore(): RateLimitStore & { readonly windows: Map<string, number> } {
	const windows = new Map<string, number>();
	return {
		windows,
		async hit(bucket, windowStart) {
			const key = `${bucket}@${windowStart.toISOString()}`;
			const hits = (windows.get(key) ?? 0) + 1;
			windows.set(key, hits);
			return hits;
		}
	};
}

export function sqlRateLimitStore(sql: SqlClient): RateLimitStore {
	return {
		async hit(bucket, windowStart) {
			const rows = await sql`
				insert into rate_limits (bucket, window_start, hits)
				values (${bucket}, ${windowStart.toISOString()}, 1)
				on conflict (bucket, window_start) do update set hits = rate_limits.hits + 1
				returning hits
			`;
			const hits = Number(rows[0]?.['hits']);
			if (!Number.isInteger(hits)) {
				throw new Error('rate limit counter missing');
			}
			return hits;
		}
	};
}

function startOfDay(now: Date): Date {
	return new Date(Math.floor(now.getTime() / DAY_MS) * DAY_MS);
}

function secondsUntil(end: number, now: Date): number {
	return Math.max(1, Math.ceil((end - now.getTime()) / 1000));
}

export async function consumeQuota(store: RateLimitStore, ipHash: string, now: Date): Promise<QuotaResult> {
	const hour = startOfHour(now);
	if ((await store.hit(`ip:${ipHash}`, hour)) > IP_LIMIT_PER_HOUR) {
		return { ok: false, error: 'rate_limited', retryAfter: secondsUntil(hour.getTime() + HOUR_MS, now) };
	}
	const day = startOfDay(now);
	if ((await store.hit('day', day)) > DAILY_LIMIT) {
		return { ok: false, error: 'daily_limit', retryAfter: secondsUntil(day.getTime() + DAY_MS, now) };
	}
	return { ok: true };
}
