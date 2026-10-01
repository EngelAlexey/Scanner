import ipaddr from 'ipaddr.js';
import type { PassedCheck } from '../contract/codes.ts';
import type { Finding, Note, SectionResult } from '../contract/types.ts';
import { createLookup, DnsFailure, LookupBudgetExceeded, type Lookup, type RecordClient } from '../net/dns-records.ts';
import type { HostInfo } from '../net/target.ts';
import { capEvidence } from './evidence.ts';

type Qualifier = '+' | '-' | '~' | '?';
type Outcome = { readonly finding?: Finding; readonly passed?: PassedCheck; readonly notes: readonly Note[] } | 'unknown';
type SpfState = { lookups: number; voids: number; ptr: boolean; permissive: boolean };

const MAX_SPF_LOOKUPS = 10;
const MAX_VOID_LOOKUPS = 2;
const MAX_SPF_DEPTH = 10;
const MAX_MX_RECORDS = 10;
const SPF_QUERY_LIMIT = 30;
const OTHER_QUERY_LIMIT = 12;
const SPF_RECORD = /^v=spf1(\s|$)/i;
const DMARC_RECORD = /^v\s*=\s*DMARC1\s*(;|$)/i;
const MODIFIER = /^([a-z][a-z0-9_.-]*)=(.*)$/i;
const MECHANISM = /^([+\-~?]?)(all|include|a|mx|ptr|ip4|ip6|exists)(?::(.*?))?(?:\/(\d+))?(?:\/\/(\d+))?$/i;
const DOMAIN_LABEL = /^(?!-)[a-z0-9_-]{1,63}(?<!-)$/i;

class SpfError extends Error {}

function validDomain(domain: string): boolean {
	const labels = domain.replace(/\.$/, '').split('.');
	return labels.length >= 2 && labels.every((label) => DOMAIN_LABEL.test(label));
}

function validRange(kind: 'ip4' | 'ip6', address: string | undefined, prefix: string | undefined): boolean {
	if (address === undefined) {
		return false;
	}
	const bits = prefix === undefined ? undefined : Number(prefix);
	if (kind === 'ip4') {
		return ipaddr.IPv4.isValidFourPartDecimal(address) && (bits === undefined || bits <= 32);
	}
	return ipaddr.IPv6.isValid(address) && (bits === undefined || bits <= 128);
}

function countLookup(state: SpfState): void {
	state.lookups++;
	if (state.lookups > MAX_SPF_LOOKUPS) {
		throw new SpfError('more than 10 DNS lookups');
	}
}

function countVoid(state: SpfState): void {
	state.voids++;
	if (state.voids > MAX_VOID_LOOKUPS) {
		throw new SpfError('more than 2 void lookups');
	}
}

async function spfRecords(domain: string, lookup: Lookup): Promise<string[]> {
	return (await lookup.txt(domain)).filter((record) => SPF_RECORD.test(record));
}

async function followDomain(target: string, state: SpfState, lookup: Lookup, chain: readonly string[]): Promise<Qualifier> {
	const domain = target.toLowerCase().replace(/\.$/, '');
	if (!validDomain(domain)) {
		throw new SpfError('invalid domain');
	}
	if (chain.includes(domain)) {
		throw new SpfError('loop');
	}
	const records = await spfRecords(domain, lookup);
	if (records.length === 0) {
		countVoid(state);
	}
	if (records.length !== 1) {
		throw new SpfError('included domain without exactly one SPF record');
	}
	return walk(domain, records[0] ?? '', state, lookup, [...chain, domain]);
}

async function resolveMechanism(kind: string, domain: string, state: SpfState, lookup: Lookup): Promise<void> {
	if (kind === 'mx') {
		const exchanges = await lookup.mx(domain);
		if (exchanges.length > MAX_MX_RECORDS) {
			throw new SpfError('more than 10 MX records');
		}
		if (exchanges.length === 0) {
			countVoid(state);
		}
		return;
	}
	const ipv4 = await lookup.a(domain);
	const ipv6 = ipv4.length > 0 || kind === 'exists' ? [] : await lookup.aaaa(domain);
	if (ipv4.length === 0 && ipv6.length === 0) {
		countVoid(state);
	}
}

async function walk(domain: string, record: string, state: SpfState, lookup: Lookup, chain: readonly string[]): Promise<Qualifier> {
	if (chain.length > MAX_SPF_DEPTH) {
		throw new SpfError('nested too deep');
	}
	let all: Qualifier | undefined;
	let redirect: string | undefined;
	let explanation = false;
	for (const term of record.trim().split(/\s+/).slice(1)) {
		const modifier = MODIFIER.exec(term);
		if (modifier !== null) {
			const name = modifier[1]?.toLowerCase();
			if ((name === 'redirect' && redirect !== undefined) || (name === 'exp' && explanation)) {
				throw new SpfError('repeated modifier');
			}
			if (name === 'redirect') {
				redirect = modifier[2] ?? '';
			}
			explanation ||= name === 'exp';
			continue;
		}
		const mechanism = MECHANISM.exec(term);
		if (mechanism === null) {
			throw new SpfError('unknown term');
		}
		const qualifier = (mechanism[1] || '+') as Qualifier;
		const kind = (mechanism[2] ?? '').toLowerCase();
		const target = mechanism[3];
		if (kind === 'ip4' || kind === 'ip6') {
			if (!validRange(kind, target, mechanism[4])) {
				throw new SpfError('invalid address range');
			}
			if (all === undefined && qualifier === '+' && mechanism[4] === '0') {
				state.permissive = true;
			}
			continue;
		}
		if ((kind === 'include' || kind === 'exists') && (target === undefined || target === '')) {
			throw new SpfError('missing domain');
		}
		if (all !== undefined) {
			continue;
		}
		if (kind === 'all') {
			all = qualifier;
			continue;
		}
		countLookup(state);
		if (kind === 'ptr') {
			state.ptr = true;
			continue;
		}
		const name = target ?? domain;
		if (name.includes('%')) {
			continue;
		}
		if (kind === 'include') {
			if ((await followDomain(name, state, lookup, chain)) === '+' && qualifier === '+') {
				state.permissive = true;
			}
			continue;
		}
		if (!validDomain(name)) {
			throw new SpfError('invalid domain');
		}
		await resolveMechanism(kind, name, state, lookup);
	}
	if (all === undefined && redirect !== undefined) {
		countLookup(state);
		return followDomain(redirect, state, lookup, chain);
	}
	return all ?? '?';
}

async function checkSpf(domain: string, lookup: Lookup): Promise<Outcome> {
	let records: string[];
	try {
		records = await spfRecords(domain, lookup);
	} catch (error) {
		if (error instanceof DnsFailure) {
			return 'unknown';
		}
		throw error;
	}
	if (records.length === 0) {
		return { finding: { code: 'spf-missing' }, notes: [] };
	}
	if (records.length > 1) {
		return { finding: { code: 'spf-invalid', evidence: capEvidence({ records }) }, notes: [] };
	}
	const record = records[0] ?? '';
	const state: SpfState = { lookups: 0, voids: 0, ptr: false, permissive: false };
	try {
		const all = await walk(domain, record, state, lookup, [domain]);
		const notes: Note[] = state.ptr ? ['spf-ptr-deprecated'] : [];
		if (state.permissive || all === '+' || all === '?') {
			return { finding: { code: 'spf-permissive', evidence: capEvidence({ record }) }, notes };
		}
		return { passed: 'spf', notes };
	} catch (error) {
		if (error instanceof SpfError || error instanceof LookupBudgetExceeded) {
			return { finding: { code: 'spf-invalid', evidence: capEvidence({ record }) }, notes: [] };
		}
		if (error instanceof DnsFailure) {
			return 'unknown';
		}
		throw error;
	}
}

function dmarcTags(record: string): Map<string, string> {
	const tags = new Map<string, string>();
	for (const part of record.split(';')) {
		const separator = part.indexOf('=');
		if (separator > 0) {
			tags.set(part.slice(0, separator).trim().toLowerCase(), part.slice(separator + 1).trim());
		}
	}
	return tags;
}

async function checkDmarc(domain: string, lookup: Lookup): Promise<Outcome> {
	let records: string[];
	try {
		records = (await lookup.txt(`_dmarc.${domain}`)).filter((record) => DMARC_RECORD.test(record.trim()));
	} catch (error) {
		if (error instanceof DnsFailure || error instanceof LookupBudgetExceeded) {
			return 'unknown';
		}
		throw error;
	}
	if (records.length !== 1) {
		return records.length === 0
			? { finding: { code: 'dmarc-missing' }, notes: [] }
			: { finding: { code: 'dmarc-missing', evidence: capEvidence({ records }) }, notes: [] };
	}
	const record = records[0] ?? '';
	const tags = dmarcTags(record);
	const declared = tags.get('p')?.toLowerCase();
	const policy = declared === 'quarantine' || declared === 'reject' ? declared : 'none';
	const testing = tags.get('t')?.toLowerCase() === 'y';
	const effective = testing ? (policy === 'reject' ? 'quarantine' : 'none') : policy;
	const notes: Note[] = testing ? ['dmarc-testing'] : [];
	if (effective === 'none') {
		return { finding: { code: 'dmarc-policy-none', evidence: capEvidence({ record }) }, notes };
	}
	return { passed: 'dmarc', notes };
}

async function receivesMail(domain: string, lookup: Lookup): Promise<boolean | 'unknown'> {
	try {
		const exchanges = await lookup.mx(domain);
		return exchanges.some((exchange) => exchange.exchange !== '' && exchange.exchange !== '.');
	} catch (error) {
		if (error instanceof DnsFailure || error instanceof LookupBudgetExceeded) {
			return 'unknown';
		}
		throw error;
	}
}

async function checkCaa(host: string, lookup: Lookup): Promise<Outcome> {
	const labels = host.split('.');
	try {
		for (let index = 0; index < labels.length - 1; index++) {
			if ((await lookup.caa(labels.slice(index).join('.'))).length > 0) {
				return { passed: 'caa', notes: [] };
			}
		}
	} catch (error) {
		if (error instanceof DnsFailure || error instanceof LookupBudgetExceeded) {
			return 'unknown';
		}
		throw error;
	}
	return { finding: { code: 'caa-missing' }, notes: [] };
}

export async function checkEmail(target: HostInfo, client: RecordClient, signal?: AbortSignal): Promise<SectionResult> {
	if (target.privateSuffix) {
		return { status: 'not_applicable', findings: [], passed: [], notes: [] };
	}
	const spfLookup = createLookup(client, SPF_QUERY_LIMIT, signal);
	const lookup = createLookup(client, OTHER_QUERY_LIMIT, signal);
	const [spf, dmarc, caa, mail] = await Promise.all([
		checkSpf(target.emailDomain, spfLookup),
		checkDmarc(target.emailDomain, lookup),
		checkCaa(target.host, lookup),
		receivesMail(target.emailDomain, lookup)
	]);
	const outcomes = [spf, dmarc, caa].filter((outcome): outcome is Exclude<Outcome, 'unknown'> => outcome !== 'unknown');
	if (outcomes.length === 0) {
		return { status: 'error', findings: [], passed: [], notes: [] };
	}
	const notes: Note[] = [...(mail === false ? (['no-mx'] as const) : []), ...outcomes.flatMap((outcome) => outcome.notes)];
	return {
		status: 'ok',
		findings: outcomes.flatMap((outcome) => (outcome.finding === undefined ? [] : [outcome.finding])),
		passed: outcomes.flatMap((outcome) => (outcome.passed === undefined ? [] : [outcome.passed])),
		notes
	};
}
