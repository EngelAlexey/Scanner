import { isIP } from 'node:net';
import { domainToUnicode } from 'node:url';
import { parse } from 'tldts';

export type HostInfo = {
	readonly host: string;
	readonly displayHost: string;
	readonly siteDomain: string;
	readonly emailDomain: string;
	readonly privateSuffix: boolean;
};

export type TargetError = 'invalid_url' | 'blocked_address';

export type HostResult = { readonly ok: true; readonly info: HostInfo } | { readonly ok: false; readonly error: TargetError };

const MAX_INPUT_LENGTH = 2048;
const MAX_HOST_LENGTH = 253;
const HAS_SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i;
const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
const SPECIAL_USE_TLDS = new Set(['localhost', 'local', 'test', 'example', 'invalid', 'onion', 'alt', 'arpa', 'internal']);

export function parseTarget(input: string): HostResult {
	const raw = input.trim();
	if (raw === '' || raw.length > MAX_INPUT_LENGTH) {
		return { ok: false, error: 'invalid_url' };
	}
	let url: URL;
	try {
		url = new URL(HAS_SCHEME.test(raw) ? raw : `https://${raw}`);
	} catch {
		return { ok: false, error: 'invalid_url' };
	}
	if (url.protocol !== 'https:' && url.protocol !== 'http:') {
		return { ok: false, error: 'invalid_url' };
	}
	if (url.username !== '' || url.password !== '') {
		return { ok: false, error: 'invalid_url' };
	}
	if (url.port !== '' && url.port !== '80' && url.port !== '443') {
		return { ok: false, error: 'invalid_url' };
	}
	return validateHostname(url.hostname);
}

export function validateHostname(hostname: string): HostResult {
	const host = hostname.endsWith('.') ? hostname.slice(0, -1) : hostname;
	if (host.startsWith('[') || isIP(host) !== 0) {
		return { ok: false, error: 'invalid_url' };
	}
	const labels = host.split('.');
	const tld = labels[labels.length - 1] ?? '';
	if (labels.length < 2 || SPECIAL_USE_TLDS.has(tld)) {
		return { ok: false, error: 'blocked_address' };
	}
	if (host.length > MAX_HOST_LENGTH || !labels.every((label) => LABEL.test(label))) {
		return { ok: false, error: 'invalid_url' };
	}
	const icann = parse(host, { allowPrivateDomains: false });
	if (icann.isIcann !== true) {
		return { ok: false, error: 'blocked_address' };
	}
	if (icann.domain === null) {
		return { ok: false, error: 'invalid_url' };
	}
	const site = parse(host, { allowPrivateDomains: true });
	return {
		ok: true,
		info: {
			host,
			displayHost: domainToUnicode(host) || host,
			siteDomain: site.domain ?? icann.domain,
			emailDomain: icann.domain,
			privateSuffix: site.isPrivate === true
		}
	};
}
