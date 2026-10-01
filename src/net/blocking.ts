import type { HeaderMap } from '../contract/types.ts';

export const BLOCK_RULES_VERSION = '1.0.0';

export type BlockProvider = 'cloudflare' | 'aws-waf' | 'cloudfront' | 'akamai' | 'imperva' | 'sucuri' | 'datadome' | 'rate-limit';

export type BlockCandidate = {
	readonly status: number;
	readonly headers: HeaderMap;
	readonly body: Buffer;
};

const BODY_SCAN_BYTES = 64 * 1024;
const CLOUDFLARE_PAGES = [/<title>Just a moment\.\.\.<\/title>/i, /cf-chl-/i, /Attention Required! \| Cloudflare/i, /cf-error-details/i];
const IMPERVA_PAGES = [/Incapsula incident ID/i, /_Incapsula_Resource/i];

function firstValue(headers: HeaderMap, name: string): string {
	return headers[name]?.[0]?.trim().toLowerCase() ?? '';
}

function hasHeader(headers: HeaderMap, name: string): boolean {
	return headers[name] !== undefined;
}

export function detectBlock({ status, headers, body }: BlockCandidate): BlockProvider | null {
	if (firstValue(headers, 'cf-mitigated') === 'challenge') {
		return 'cloudflare';
	}
	if (hasHeader(headers, 'x-sucuri-block')) {
		return 'sucuri';
	}
	if (hasHeader(headers, 'x-amzn-waf-action')) {
		return 'aws-waf';
	}
	if (status === 429) {
		return 'rate-limit';
	}
	if (status !== 403 && status !== 503) {
		return null;
	}
	const server = firstValue(headers, 'server');
	const page = body.subarray(0, BODY_SCAN_BYTES).toString('latin1');
	if (server.includes('cloudflare') && CLOUDFLARE_PAGES.some((pattern) => pattern.test(page))) {
		return 'cloudflare';
	}
	if (hasHeader(headers, 'x-iinfo') && (status === 403 || IMPERVA_PAGES.some((pattern) => pattern.test(page)))) {
		return 'imperva';
	}
	if (status !== 403) {
		return null;
	}
	if (server.includes('cloudfront')) {
		return 'cloudfront';
	}
	if (server.includes('akamaighost')) {
		return 'akamai';
	}
	if (hasHeader(headers, 'x-datadome')) {
		return 'datadome';
	}
	return null;
}
