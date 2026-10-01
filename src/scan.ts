import { checkHsts } from './checks/connection.ts';
import { capEvidence } from './checks/evidence.ts';
import { checkHeaders } from './checks/headers.ts';
import type { Evidence, SectionResult } from './contract/types.ts';
import { detectBlock, type BlockProvider } from './net/blocking.ts';
import { safeFetch, type FetchError, type FetchOptions, type Hop } from './net/safe-request.ts';
import type { HostInfo } from './net/target.ts';

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

export type HeaderScan = {
	readonly host: string;
	readonly displayHost: string;
	readonly finalUrl: string;
	readonly status: number;
	readonly hops: readonly Hop[];
	readonly headers: Evidence;
	readonly blockedBy?: BlockProvider;
	readonly sections: {
		readonly connection: SectionResult;
		readonly headers: SectionResult;
	};
};

export type HeaderScanResult =
	| { readonly ok: true; readonly scan: HeaderScan }
	| { readonly ok: false; readonly error: FetchError; readonly detail?: string };

const BLOCKED: SectionResult = { status: 'blocked', findings: [], passed: [], notes: [] };

export async function scanHeaders(target: HostInfo, options: FetchOptions = {}): Promise<HeaderScanResult> {
	const result = await safeFetch(new URL(`https://${target.host}/`), options);
	if (!result.ok) {
		return result.detail === undefined ? { ok: false, error: result.error } : { ok: false, error: result.error, detail: result.detail };
	}
	const { page } = result;
	const shown: Record<string, readonly string[]> = {};
	for (const name of SHOWN_HEADERS) {
		const values = page.headers[name];
		if (values !== undefined) {
			shown[name] = values;
		}
	}
	const blockedBy = detectBlock(page);
	const sections =
		blockedBy === null
			? {
					connection: { status: 'ok' as const, ...checkHsts(page.headers, new URL(page.url).protocol === 'https:') },
					headers: { status: 'ok' as const, ...checkHeaders(page.headers) }
				}
			: { connection: BLOCKED, headers: BLOCKED };
	return {
		ok: true,
		scan: {
			host: target.host,
			displayHost: target.displayHost,
			finalUrl: page.url,
			status: page.status,
			hops: page.hops,
			headers: capEvidence(shown),
			...(blockedBy === null ? {} : { blockedBy }),
			sections
		}
	};
}
