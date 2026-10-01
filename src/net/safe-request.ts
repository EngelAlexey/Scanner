import http from 'node:http';
import https from 'node:https';
import { isIP } from 'node:net';
import zlib from 'node:zlib';
import type { Readable } from 'node:stream';
import type { HeaderMap } from '../contract/types.ts';
import { checkPolicy, productionAddressPolicy, type AddressPolicy } from './address-policy.ts';
import { resolveHost, type DnsClient, type Resolution } from './resolver.ts';
import { validateHostname, type HostInfo } from './target.ts';

export const USER_AGENT = 'Mozilla/5.0 (compatible; AlexHerreraScanner/1.0; +https://www.alexherrera.dev/en/tools/scanner/about)';

const REQUEST_HEADERS = {
	'User-Agent': USER_AGENT,
	'Accept': 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
	'Accept-Language': 'es,en;q=0.8',
	'Accept-Encoding': 'gzip, br'
};

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const RETRYABLE_CODES = new Set(['ECONNRESET', 'ETIMEDOUT']);
const HEADER_OVERFLOW = 'HPE_HEADER_OVERFLOW';
const MAX_HEADER_BYTES = 64 * 1024;
const ADDRESS_ATTEMPTS = 2;

export const DEFAULT_TIMEOUT_MS = 10_000;
export const DEFAULT_MAX_BYTES = 2 * 1024 * 1024;
export const DEFAULT_MAX_REDIRECTS = 5;

export type FetchError =
	| 'invalid_url'
	| 'blocked_address'
	| 'domain_not_found'
	| 'dns_error'
	| 'ipv6_only'
	| 'timeout'
	| 'connection_failed'
	| 'headers_too_large'
	| 'too_many_redirects'
	| 'redirect_loop'
	| 'redirect_invalid'
	| 'redirect_blocked';

export type Hop = {
	readonly url: string;
	readonly status: number;
	readonly location: string;
};

export type SetCookie = {
	readonly host: string;
	readonly header: string;
};

export type FetchStop = {
	readonly reason: 'https' | 'offsite' | 'downgrade';
	readonly location: string;
};

export type FetchedPage = {
	readonly url: string;
	readonly status: number;
	readonly headers: HeaderMap;
	readonly body: Buffer;
	readonly truncated: boolean;
	readonly bodyReadable: boolean;
	readonly hops: readonly Hop[];
	readonly cookies: readonly SetCookie[];
	readonly stop?: FetchStop;
};

export type FetchResult =
	| { readonly ok: true; readonly page: FetchedPage }
	| { readonly ok: false; readonly error: FetchError; readonly hops: readonly Hop[]; readonly detail?: string };

export type FetchOptions = {
	readonly policy?: AddressPolicy;
	readonly dns?: DnsClient;
	readonly resolutions?: ReadonlyMap<string, Resolution>;
	readonly timeoutMs?: number;
	readonly maxBytes?: number;
	readonly maxRedirects?: number;
	readonly stopAtHttps?: boolean;
	readonly signal?: AbortSignal;
};

type RawResponse = {
	readonly status: number;
	readonly headers: HeaderMap;
	readonly body: Buffer;
	readonly truncated: boolean;
	readonly bodyReadable: boolean;
};

type UrlCheck = { readonly ok: true; readonly info: HostInfo } | { readonly ok: false; readonly reason: 'invalid' | 'blocked' };

function portOf(url: URL): number {
	if (url.port !== '') {
		return Number(url.port);
	}
	return url.protocol === 'https:' ? 443 : 80;
}

function checkUrl(url: URL, policy: AddressPolicy): UrlCheck {
	if (url.protocol !== 'https:' && url.protocol !== 'http:') {
		return { ok: false, reason: 'invalid' };
	}
	if (url.username !== '' || url.password !== '') {
		return { ok: false, reason: 'invalid' };
	}
	if (!policy.isAllowedPort(portOf(url))) {
		return { ok: false, reason: 'blocked' };
	}
	if (url.hostname.startsWith('[') || isIP(url.hostname) !== 0) {
		return { ok: false, reason: 'blocked' };
	}
	const host = validateHostname(url.hostname);
	if (!host.ok) {
		return { ok: false, reason: host.error === 'invalid_url' ? 'invalid' : 'blocked' };
	}
	return { ok: true, info: host.info };
}

function toHeaderMap(headers: NodeJS.Dict<string[]>): HeaderMap {
	const map: Record<string, readonly string[]> = {};
	for (const [name, values] of Object.entries(headers)) {
		if (values !== undefined) {
			map[name] = values;
		}
	}
	return map;
}

function createDecoder(encoding: string): zlib.Gunzip | zlib.BrotliDecompress | zlib.Inflate | 'identity' | 'unsupported' {
	switch (encoding) {
		case '':
		case 'identity':
			return 'identity';
		case 'gzip':
		case 'x-gzip':
			return zlib.createGunzip({ finishFlush: zlib.constants.Z_SYNC_FLUSH });
		case 'br':
			return zlib.createBrotliDecompress({ finishFlush: zlib.constants.BROTLI_OPERATION_FLUSH });
		case 'deflate':
			return zlib.createInflate({ finishFlush: zlib.constants.Z_SYNC_FLUSH });
		default:
			return 'unsupported';
	}
}

async function readLimited(
	response: http.IncomingMessage,
	encoding: string,
	maxBytes: number,
	signal: AbortSignal
): Promise<Pick<RawResponse, 'body' | 'truncated' | 'bodyReadable'>> {
	const decoder = createDecoder(encoding);
	if (decoder === 'unsupported') {
		response.destroy();
		return { body: Buffer.alloc(0), truncated: false, bodyReadable: false };
	}
	let rawBytes = 0;
	response.on('data', (chunk: Buffer) => {
		rawBytes += chunk.length;
	});
	const source: Readable = decoder === 'identity' ? response : response.pipe(decoder);
	const chunks: Buffer[] = [];
	let size = 0;
	let truncated = false;
	try {
		for await (const chunk of source) {
			const buffer = chunk as Buffer;
			const room = maxBytes - size;
			if (buffer.length > room) {
				chunks.push(buffer.subarray(0, room));
				size = maxBytes;
				truncated = true;
				break;
			}
			chunks.push(buffer);
			size += buffer.length;
			if (rawBytes > maxBytes) {
				truncated = true;
				break;
			}
		}
	} catch (error) {
		if (signal.aborted) {
			throw error;
		}
		return { body: Buffer.concat(chunks), truncated, bodyReadable: chunks.length > 0 };
	} finally {
		response.destroy();
		if (decoder !== 'identity') {
			decoder.destroy();
		}
	}
	return { body: Buffer.concat(chunks), truncated, bodyReadable: true };
}

function requestOnce(url: URL, address: string, maxBytes: number, signal: AbortSignal, lenientParser: boolean): Promise<RawResponse> {
	return new Promise((resolve, reject) => {
		const secure = url.protocol === 'https:';
		const options: https.RequestOptions = {
			host: address,
			port: portOf(url),
			method: 'GET',
			path: `${url.pathname}${url.search}`,
			headers: { ...REQUEST_HEADERS, Host: url.host, ...(secure ? {} : { 'Upgrade-Insecure-Requests': '1' }) },
			agent: false,
			maxHeaderSize: MAX_HEADER_BYTES,
			insecureHTTPParser: lenientParser,
			signal,
			...(secure ? { servername: url.hostname, rejectUnauthorized: false } : {})
		};
		const request = (secure ? https : http).request(options, (response) => {
			const status = response.statusCode ?? 0;
			const headers = toHeaderMap(response.headersDistinct);
			if (REDIRECT_STATUSES.has(status) && headers['location'] !== undefined) {
				response.destroy();
				resolve({ status, headers, body: Buffer.alloc(0), truncated: false, bodyReadable: false });
				return;
			}
			const encoding = (headers['content-encoding']?.join(',') ?? '').trim().toLowerCase();
			readLimited(response, encoding, maxBytes, signal).then(
				(body) => resolve({ status, headers, ...body }),
				reject
			);
		});
		request.on('error', reject);
		request.end();
	});
}

function errorCode(error: unknown): string {
	return (error as NodeJS.ErrnoException).code ?? '';
}

function isParserError(code: string): boolean {
	return code.startsWith('HPE_') && code !== HEADER_OVERFLOW;
}

function classify(error: unknown, signal: AbortSignal): FetchError {
	if (signal.aborted) {
		return 'timeout';
	}
	if (errorCode(error) === HEADER_OVERFLOW) {
		return 'headers_too_large';
	}
	return 'connection_failed';
}

async function requestWithRetry(url: URL, address: string, maxBytes: number, signal: AbortSignal): Promise<RawResponse> {
	try {
		return await requestOnce(url, address, maxBytes, signal, false);
	} catch (error) {
		const code = errorCode(error);
		if (signal.aborted || !(RETRYABLE_CODES.has(code) || isParserError(code))) {
			throw error;
		}
		return requestOnce(url, address, maxBytes, signal, isParserError(code));
	}
}

async function requestFirstReachable(url: URL, addresses: readonly string[], maxBytes: number, signal: AbortSignal): Promise<RawResponse> {
	let failure: unknown;
	for (const address of addresses.slice(0, ADDRESS_ATTEMPTS)) {
		try {
			return await requestWithRetry(url, address, maxBytes, signal);
		} catch (error) {
			const code = errorCode(error);
			if (signal.aborted || code === HEADER_OVERFLOW || isParserError(code)) {
				throw error;
			}
			failure = error;
		}
	}
	throw failure;
}

function trustedResolution(resolution: Resolution, policy: AddressPolicy): Resolution {
	if (resolution.ok && ![...resolution.ipv4, ...resolution.ipv6].every((address) => policy.isAllowedAddress(address))) {
		return { ok: false, error: 'blocked_address' };
	}
	return resolution;
}

export async function safeFetch(start: URL, options: FetchOptions = {}): Promise<FetchResult> {
	const policy = checkPolicy(options.policy ?? productionAddressPolicy);
	const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
	const maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
	const timeout = AbortSignal.timeout(options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
	const signal = options.signal ? AbortSignal.any([timeout, options.signal]) : timeout;
	const hops: Hop[] = [];
	const cookies: SetCookie[] = [];
	const visited = new Set<string>();
	const resolutions = new Map<string, Resolution>();
	for (const [host, seeded] of options.resolutions ?? []) {
		resolutions.set(host, trustedResolution(seeded, policy));
	}
	const fail = (error: FetchError, detail?: string): FetchResult =>
		detail === undefined ? { ok: false, error, hops } : { ok: false, error, hops, detail };

	const first = checkUrl(start, policy);
	if (!first.ok) {
		return fail(first.reason === 'invalid' ? 'invalid_url' : 'blocked_address');
	}
	const siteDomain = first.info.siteDomain;
	let url = new URL(start.href);
	url.hash = '';
	let secureReached = url.protocol === 'https:';

	for (;;) {
		visited.add(url.href);
		const host = validateHostname(url.hostname);
		const hostname = host.ok ? host.info.host : url.hostname;
		let resolution = resolutions.get(hostname);
		if (resolution === undefined) {
			resolution = await resolveHost(hostname, { policy, ...(options.dns ? { dns: options.dns } : {}) });
			resolutions.set(hostname, resolution);
		}
		if (!resolution.ok) {
			if (hops.length === 0) {
				return fail(resolution.error);
			}
			return fail(resolution.error === 'blocked_address' ? 'redirect_blocked' : 'redirect_invalid', hostname);
		}
		if (resolution.ipv4.length === 0) {
			return fail('ipv6_only', hostname);
		}

		let response: RawResponse;
		try {
			response = await requestFirstReachable(url, resolution.ipv4, maxBytes, signal);
		} catch (error) {
			return fail(classify(error, signal));
		}

		if (url.protocol === 'https:') {
			cookies.push(...(response.headers['set-cookie'] ?? []).map((header) => ({ host: url.hostname, header })));
		}

		const current = url;
		const respond = (stop?: FetchStop): FetchResult => ({
			ok: true,
			page: {
				url: current.href,
				status: response.status,
				headers: response.headers,
				body: response.body,
				truncated: response.truncated,
				bodyReadable: response.bodyReadable,
				hops,
				cookies,
				...(stop === undefined ? {} : { stop })
			}
		});

		const locations = [...new Set(response.headers['location'] ?? [])];
		if (!REDIRECT_STATUSES.has(response.status) || locations.length === 0) {
			return respond();
		}
		if (locations.length > 1) {
			return fail('redirect_invalid');
		}
		let next: URL;
		try {
			next = new URL(locations[0] ?? '', url);
		} catch {
			return fail('redirect_invalid');
		}
		next.hash = '';
		hops.push({ url: url.href, status: response.status, location: next.href });
		if (hops.length > maxRedirects) {
			return fail('too_many_redirects');
		}
		if (visited.has(next.href)) {
			return fail('redirect_loop', next.href);
		}
		if (options.stopAtHttps === true && next.protocol === 'https:') {
			return respond({ reason: 'https', location: next.href });
		}
		if (secureReached && next.protocol === 'http:') {
			return respond({ reason: 'downgrade', location: next.href });
		}
		const checked = checkUrl(next, policy);
		if (!checked.ok) {
			return fail(checked.reason === 'invalid' ? 'redirect_invalid' : 'redirect_blocked', next.host);
		}
		if (checked.info.siteDomain !== siteDomain) {
			return respond({ reason: 'offsite', location: next.href });
		}
		secureReached = secureReached || next.protocol === 'https:';
		url = next;
	}
}
