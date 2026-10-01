import type { MxAnswer, RecordClient } from '../../src/net/dns-records.ts';
import type { DnsClient } from '../../src/net/resolver.ts';

type RecordType = 'a' | 'aaaa' | 'txt' | 'mx' | 'caa';

export type FakeRecords = {
	readonly a?: readonly string[];
	readonly aaaa?: readonly string[];
	readonly txt?: readonly (string | readonly string[])[];
	readonly mx?: readonly MxAnswer[];
	readonly caa?: readonly object[];
	readonly error?: string;
	readonly errors?: Partial<Record<RecordType, string>>;
};

export type FakeDns = DnsClient & RecordClient & { readonly queries: string[] };

function dnsError(code: string, host: string): NodeJS.ErrnoException {
	const error: NodeJS.ErrnoException = new Error(`${code} ${host}`);
	error.code = code;
	return error;
}

export function fakeDns(zone: Readonly<Record<string, FakeRecords>>): FakeDns {
	const queries: string[] = [];
	const answer = async <T>(host: string, type: RecordType, pick: (records: FakeRecords) => readonly T[] | undefined): Promise<T[]> => {
		queries.push(`${type} ${host}`);
		const records = zone[host];
		if (records === undefined) {
			throw dnsError('ENOTFOUND', host);
		}
		const error = records.errors?.[type] ?? records.error;
		if (error !== undefined) {
			throw dnsError(error, host);
		}
		const list = pick(records);
		if (list === undefined || list.length === 0) {
			throw dnsError('ENODATA', host);
		}
		return [...list];
	};
	return {
		queries,
		resolve4: (host) => answer(host, 'a', (records) => records.a),
		resolve6: (host) => answer(host, 'aaaa', (records) => records.aaaa),
		resolveTxt: (host) =>
			answer(host, 'txt', (records) => records.txt?.map((record) => (typeof record === 'string' ? [record] : [...record]))),
		resolveMx: (host) => answer(host, 'mx', (records) => records.mx),
		resolveCaa: (host) => answer(host, 'caa', (records) => records.caa)
	};
}
