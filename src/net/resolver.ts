import { Resolver } from 'node:dns/promises';
import ipaddr from 'ipaddr.js';
import { checkPolicy, productionAddressPolicy, type AddressPolicy } from './address-policy.ts';

export type DnsClient = {
	resolve4(host: string): Promise<string[]>;
	resolve6(host: string): Promise<string[]>;
};

export type ResolveError = 'domain_not_found' | 'blocked_address' | 'dns_error';

export type Resolution =
	| { readonly ok: true; readonly ipv4: readonly string[]; readonly ipv6: readonly string[] }
	| { readonly ok: false; readonly error: ResolveError };

export type ResolveOptions = {
	readonly dns?: DnsClient;
	readonly policy?: AddressPolicy;
};

const MAX_ADDRESSES = 16;
const NO_ANSWER = new Set(['ENOTFOUND', 'ENODATA']);

let defaultClient: DnsClient | undefined;

export function publicDnsClient(): DnsClient {
	if (!defaultClient) {
		const resolver = new Resolver({ timeout: 1500, tries: 2 });
		resolver.setServers(['1.1.1.1', '1.0.0.1']);
		defaultClient = resolver;
	}
	return defaultClient;
}

type Answer = { readonly addresses: readonly string[] } | { readonly code: string };

async function ask(query: () => Promise<string[]>): Promise<Answer> {
	try {
		return { addresses: await query() };
	} catch (error) {
		return { code: (error as NodeJS.ErrnoException).code ?? 'UNKNOWN' };
	}
}

function byNumericValue(a: string, b: string): number {
	const left = ipaddr.parse(a).toByteArray();
	const right = ipaddr.parse(b).toByteArray();
	for (let i = 0; i < Math.min(left.length, right.length); i++) {
		const diff = (left[i] ?? 0) - (right[i] ?? 0);
		if (diff !== 0) {
			return diff;
		}
	}
	return left.length - right.length;
}

export async function resolveHost(host: string, options: ResolveOptions = {}): Promise<Resolution> {
	const dns = options.dns ?? publicDnsClient();
	const policy = checkPolicy(options.policy ?? productionAddressPolicy);
	const [a, aaaa] = await Promise.all([ask(() => dns.resolve4(host)), ask(() => dns.resolve6(host))]);
	for (const answer of [a, aaaa]) {
		if ('code' in answer && !NO_ANSWER.has(answer.code)) {
			return { ok: false, error: 'dns_error' };
		}
	}
	const ipv4 = 'addresses' in a ? [...a.addresses] : [];
	const ipv6 = 'addresses' in aaaa ? [...aaaa.addresses] : [];
	if (ipv4.length === 0 && ipv6.length === 0) {
		return { ok: false, error: 'domain_not_found' };
	}
	if (![...ipv4, ...ipv6].every((address) => policy.isAllowedAddress(address))) {
		return { ok: false, error: 'blocked_address' };
	}
	return {
		ok: true,
		ipv4: ipv4.sort(byNumericValue).slice(0, MAX_ADDRESSES),
		ipv6: ipv6.sort(byNumericValue).slice(0, MAX_ADDRESSES)
	};
}
