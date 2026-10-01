import type { DnsClient } from '../../src/net/resolver.ts';

export type FakeRecords = {
	readonly a?: readonly string[];
	readonly aaaa?: readonly string[];
	readonly error?: string;
};

export type FakeDns = DnsClient & { readonly queries: string[] };

function dnsError(code: string, host: string): NodeJS.ErrnoException {
	const error: NodeJS.ErrnoException = new Error(`${code} ${host}`);
	error.code = code;
	return error;
}

export function fakeDns(zone: Readonly<Record<string, FakeRecords>>): FakeDns {
	const queries: string[] = [];
	const answer = async (host: string, type: 'a' | 'aaaa'): Promise<string[]> => {
		queries.push(`${type} ${host}`);
		const records = zone[host];
		if (records === undefined) {
			throw dnsError('ENOTFOUND', host);
		}
		if (records.error !== undefined) {
			throw dnsError(records.error, host);
		}
		const list = records[type];
		if (list === undefined || list.length === 0) {
			throw dnsError('ENODATA', host);
		}
		return [...list];
	};
	return {
		queries,
		resolve4: (host) => answer(host, 'a'),
		resolve6: (host) => answer(host, 'aaaa')
	};
}
