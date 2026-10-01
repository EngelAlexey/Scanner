import type { TurnstileConfig } from '../config.ts';

export const SITEVERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
const TIMEOUT_MS = 5000;
const MAX_TOKEN_LENGTH = 2048;
const MAX_AGE_MS = 300_000;
const UNAVAILABLE_CODES = new Set(['internal-error', 'missing-input-secret', 'invalid-input-secret']);

export type TurnstileError = 'turnstile_failed' | 'turnstile_unavailable';
export type TurnstileResult = { readonly ok: true } | { readonly ok: false; readonly error: TurnstileError };

type Siteverify = {
	readonly 'success'?: unknown;
	readonly 'error-codes'?: unknown;
	readonly 'hostname'?: unknown;
	readonly 'action'?: unknown;
	readonly 'challenge_ts'?: unknown;
};

export type VerifyOptions = {
	readonly fetch?: typeof fetch;
	readonly now?: Date;
};

const failed: TurnstileResult = { ok: false, error: 'turnstile_failed' };
const unavailable: TurnstileResult = { ok: false, error: 'turnstile_unavailable' };

export async function verifyTurnstile(
	token: string,
	remoteIp: string,
	config: TurnstileConfig,
	options: VerifyOptions = {}
): Promise<TurnstileResult> {
	if (token === '' || token.length > MAX_TOKEN_LENGTH) {
		return failed;
	}
	let outcome: Siteverify;
	try {
		const response = await (options.fetch ?? fetch)(SITEVERIFY_URL, {
			method: 'POST',
			body: new URLSearchParams({ secret: config.secret, response: token, remoteip: remoteIp }),
			signal: AbortSignal.timeout(TIMEOUT_MS)
		});
		if (!response.ok) {
			return unavailable;
		}
		outcome = (await response.json()) as Siteverify;
	} catch {
		return unavailable;
	}
	if (outcome.success !== true) {
		const codes = Array.isArray(outcome['error-codes']) ? outcome['error-codes'] : [];
		return codes.some((code) => UNAVAILABLE_CODES.has(String(code))) ? unavailable : failed;
	}
	if (typeof outcome.hostname !== 'string' || !config.hostnames.includes(outcome.hostname.toLowerCase())) {
		return failed;
	}
	if (config.action !== null && outcome.action !== config.action) {
		return failed;
	}
	const issuedAt = typeof outcome.challenge_ts === 'string' ? Date.parse(outcome.challenge_ts) : Number.NaN;
	const age = (options.now ?? new Date()).getTime() - issuedAt;
	if (!Number.isFinite(age) || age > MAX_AGE_MS) {
		return failed;
	}
	return { ok: true };
}
