import { checkHsts, checkHttpRedirect, checkTls, preloadedTld } from './checks/connection.ts';
import { checkPageContent, checkSecurityTxt, decodeBody, extractPage, isHtml } from './checks/content.ts';
import { checkCookies } from './checks/cookies.ts';
import { checkEmail } from './checks/email.ts';
import { capEvidence } from './checks/evidence.ts';
import { checkHeaders } from './checks/headers.ts';
import type { SectionId } from './contract/codes.ts';
import type { CheckResult, Evidence, Finding, HeaderMap, Note, SectionResult } from './contract/types.ts';
import type { AddressPolicy } from './net/address-policy.ts';
import { detectBlock, type BlockProvider } from './net/blocking.ts';
import type { RecordClient } from './net/dns-records.ts';
import { publicDnsClient, type DnsClient, type Resolution } from './net/resolver.ts';
import { safeFetch, type FetchedPage, type FetchError, type FetchResult, type Hop } from './net/safe-request.ts';
import type { HostInfo } from './net/target.ts';
import { probeTls, type TlsProbe } from './net/tls-probe.ts';

export const SHOWN_HEADERS = [
	'strict-transport-security',
	'content-security-policy',
	'content-security-policy-report-only',
	'x-frame-options',
	'x-content-type-options',
	'referrer-policy',
	'permissions-policy',
	'server',
	'x-powered-by'
] as const;

export type SiteScan = {
	readonly host: string;
	readonly displayHost: string;
	readonly finalUrl: string | null;
	readonly status: number | null;
	readonly hops: readonly Hop[];
	readonly headers: Evidence;
	readonly blockedBy?: BlockProvider;
	readonly sections: Readonly<Record<SectionId, SectionResult>>;
};

export type SiteScanResult = { readonly ok: true; readonly scan: SiteScan } | { readonly ok: false; readonly error: FetchError };

export type ScanOptions = {
	readonly policy?: AddressPolicy;
	readonly dns?: DnsClient & RecordClient;
	readonly ports?: { readonly https: number; readonly http: number };
	readonly tlsCa?: readonly string[];
	readonly now?: Date;
	readonly budgetMs?: number;
};

const SCAN_BUDGET_MS = 25_000;
const SIDE_REQUEST_TIMEOUT_MS = 5000;
const HTTP_MAX_BYTES = 64 * 1024;
const SECURITY_TXT_MAX_BYTES = 32 * 1024;
const UNREACHABLE = new Set<FetchError>(['timeout', 'connection_failed']);
const CDN_SIGNATURES: readonly [string, (headers: HeaderMap) => boolean][] = [
	['Cloudflare', (headers) => headers['cf-ray'] !== undefined || /cloudflare/i.test(headers['server']?.[0] ?? '')],
	['Vercel', (headers) => headers['x-vercel-id'] !== undefined],
	['CloudFront', (headers) => headers['x-amz-cf-id'] !== undefined || /cloudfront/i.test(headers['via']?.join(' ') ?? '')],
	['Fastly', (headers) => headers['x-fastly-request-id'] !== undefined || /^cache-/i.test(headers['x-served-by']?.[0] ?? '')],
	['Akamai', (headers) => /akamai/i.test(headers['server']?.[0] ?? '') || headers['x-akamai-transformed'] !== undefined],
	['Netlify', (headers) => headers['x-nf-request-id'] !== undefined]
];

function section(status: SectionResult['status'], result: CheckResult = { findings: [], passed: [], notes: [] }): SectionResult {
	return { status, ...result };
}

function merge(...results: readonly CheckResult[]): CheckResult {
	return {
		findings: results.flatMap((result) => result.findings),
		passed: results.flatMap((result) => result.passed),
		notes: results.flatMap((result) => result.notes)
	};
}

function cdnNote(headers: HeaderMap): Note[] {
	const provider = CDN_SIGNATURES.find(([, matches]) => matches(headers))?.[0];
	return provider === undefined ? [] : [`cdn:${provider}`];
}

function urlFor(protocol: 'https' | 'http', host: string, port: number, path = '/'): URL {
	const standard = protocol === 'https' ? 443 : 80;
	return new URL(`${protocol}://${host}${port === standard ? '' : `:${port}`}${path}`);
}

function shownHeaders(page: FetchedPage | undefined): Evidence {
	const shown: Record<string, readonly string[]> = {};
	for (const name of SHOWN_HEADERS) {
		const values = page?.headers[name];
		if (values !== undefined) {
			shown[name] = values;
		}
	}
	return capEvidence(shown);
}

function connectionSection(host: string, tls: TlsProbe | undefined, https: FetchResult, http: FetchResult, page: FetchedPage | undefined, blocked: boolean, now: Date): SectionResult {
	if (tls === undefined) {
		return section('error', { findings: [], passed: [], notes: ['ipv6-only'] });
	}
	const downgrade: Finding[] =
		page?.stop?.reason === 'downgrade' ? [{ code: 'https-downgrade', evidence: capEvidence({ location: page.stop.location }) }] : [];
	const preloaded = preloadedTld(host);
	const hsts = page !== undefined && !blocked && page.url.startsWith('https:') ? checkHsts(page.headers, true, preloaded) : { findings: [], passed: [], notes: [] };
	const notes = https.ok ? cdnNote(https.page.headers) : [];
	return section('ok', merge(checkTls(tls, now), { findings: downgrade, passed: [], notes }, checkHttpRedirect(http, preloaded), hsts));
}

function webSections(page: FetchedPage | undefined, blocked: boolean, securityTxt: FetchResult, now: Date): Pick<Record<SectionId, SectionResult>, 'headers' | 'cookies' | 'content'> {
	if (page === undefined) {
		return { headers: section('error'), cookies: section('error'), content: section('error') };
	}
	if (blocked) {
		return { headers: section('blocked'), cookies: section('blocked'), content: section('blocked') };
	}
	if (page.stop !== undefined) {
		const notes: Note[] = page.stop.reason === 'offsite' ? [`redirects-offsite:${new URL(page.stop.location).host}`] : [];
		return { headers: section('error', { findings: [], passed: [], notes }), cookies: section('error'), content: section('error') };
	}
	const facts = isHtml(page) ? extractPage(decodeBody(page.body, page.headers['content-type']?.[0]), page.url) : undefined;
	const headers = checkHeaders(page.headers, facts === undefined ? {} : { metaCsp: facts.metaCsp, ...(facts.metaReferrer === undefined ? {} : { metaReferrer: facts.metaReferrer }) });
	const content = facts === undefined ? checkSecurityTxt(securityTxt, now) : merge(checkPageContent(page, facts), checkSecurityTxt(securityTxt, now));
	return { headers: section('ok', headers), cookies: section('ok', checkCookies(page.cookies, now)), content: section('ok', content) };
}

export async function scanSite(target: HostInfo, resolution: Extract<Resolution, { ok: true }>, options: ScanOptions = {}): Promise<SiteScanResult> {
	const now = options.now ?? new Date();
	const signal = AbortSignal.timeout(options.budgetMs ?? SCAN_BUDGET_MS);
	const ports = options.ports ?? { https: 443, http: 80 };
	const dns = options.dns ?? (publicDnsClient() as DnsClient & RecordClient);
	const fetchOptions = {
		...(options.policy === undefined ? {} : { policy: options.policy }),
		dns,
		resolutions: new Map([[target.host, resolution]]),
		signal
	};
	const address = resolution.ipv4[0];
	const sideRequest = { ...fetchOptions, timeoutMs: SIDE_REQUEST_TIMEOUT_MS };

	const [tls, https, http, securityTxt, email] = await Promise.all([
		address === undefined
			? undefined
			: probeTls(target.host, address, { port: ports.https, signal, ...(options.tlsCa === undefined ? {} : { ca: options.tlsCa }) }),
		safeFetch(urlFor('https', target.host, ports.https), fetchOptions),
		safeFetch(urlFor('http', target.host, ports.http), { ...sideRequest, stopAtHttps: true, maxBytes: HTTP_MAX_BYTES }),
		safeFetch(urlFor('https', target.host, ports.https, '/.well-known/security.txt'), { ...sideRequest, maxBytes: SECURITY_TXT_MAX_BYTES }),
		checkEmail(target, dns, signal)
	]);

	const httpDown = !http.ok && UNREACHABLE.has(http.error);
	if (!https.ok && UNREACHABLE.has(https.error) && (tls === undefined || !tls.handshake.ok) && httpDown && address !== undefined) {
		return { ok: false, error: https.error };
	}

	const page = https.ok ? https.page : undefined;
	const blockedBy = page !== undefined && page.stop === undefined ? detectBlock(page) : null;
	const blocked = blockedBy !== null;
	const web = webSections(page, blocked, securityTxt, now);
	const ipv6Only: Note[] = address === undefined ? ['ipv6-only'] : [];
	return {
		ok: true,
		scan: {
			host: target.host,
			displayHost: target.displayHost,
			finalUrl: page?.url ?? null,
			status: page?.status ?? null,
			hops: https.ok ? https.page.hops : https.hops,
			headers: shownHeaders(page),
			...(blockedBy === null ? {} : { blockedBy }),
			sections: {
				connection: connectionSection(target.host, tls, https, http, page, blocked, now),
				headers: address === undefined ? section('error', { findings: [], passed: [], notes: ipv6Only }) : web.headers,
				cookies: web.cookies,
				content: web.content,
				email
			}
		}
	};
}
