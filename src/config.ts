import { randomBytes } from 'node:crypto';
import { isLocalDev } from './security/availability.ts';

export const TURNSTILE_ACTION = 'scan';
export const TURNSTILE_TEST_SECRET = '1x0000000000000000000000000000000AA';
const TURNSTILE_TEST_HOSTNAMES = ['example.com'];
const TURNSTILE_TEST_SECRET_PATTERN = /^\dx0+AA$/;
const MIN_SECRET_LENGTH = 32;

export type TurnstileConfig = {
	readonly secret: string;
	readonly hostnames: readonly string[];
	readonly action: string | null;
};

export type ScanConfig = {
	readonly local: boolean;
	readonly ipHashSecret: string;
	readonly turnstile: TurnstileConfig;
	readonly databaseUrl: string | undefined;
};

export type ConfigResult = { readonly ok: true; readonly config: ScanConfig } | { readonly ok: false; readonly problems: readonly string[] };

let localIpHashSecret: string | undefined;

function list(value: string | undefined): string[] {
	return (value ?? '')
		.split(',')
		.map((item) => item.trim().toLowerCase())
		.filter((item) => item !== '');
}

function localSecret(): string {
	localIpHashSecret ??= randomBytes(32).toString('base64url');
	return localIpHashSecret;
}

export function readConfig(env: NodeJS.ProcessEnv = process.env): ConfigResult {
	const local = isLocalDev(env);
	const problems: string[] = [];

	const ipHashSecret = env.IP_HASH_SECRET ?? (local ? localSecret() : '');
	if (ipHashSecret.length < MIN_SECRET_LENGTH) {
		problems.push('IP_HASH_SECRET');
	}

	const turnstileSecret = env.TURNSTILE_SECRET_KEY ?? (local ? TURNSTILE_TEST_SECRET : '');
	const testing = TURNSTILE_TEST_SECRET_PATTERN.test(turnstileSecret);
	if (turnstileSecret === '' || (testing && !local)) {
		problems.push('TURNSTILE_SECRET_KEY');
	}
	const hostnames = testing ? TURNSTILE_TEST_HOSTNAMES : list(env.TURNSTILE_HOSTNAMES);
	if (hostnames.length === 0) {
		problems.push('TURNSTILE_HOSTNAMES');
	}

	const databaseUrl = env.DATABASE_URL === '' ? undefined : env.DATABASE_URL;
	if (databaseUrl === undefined && !local) {
		problems.push('DATABASE_URL');
	}

	if (problems.length > 0) {
		return { ok: false, problems };
	}
	return {
		ok: true,
		config: {
			local,
			ipHashSecret,
			turnstile: { secret: turnstileSecret, hostnames, action: testing ? null : TURNSTILE_ACTION },
			databaseUrl
		}
	};
}
