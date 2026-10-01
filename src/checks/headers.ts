import type { PassedCheck } from '../contract/codes.ts';
import type { CheckResult, Finding, HeaderMap, Note } from '../contract/types.ts';
import { capEvidence } from './evidence.ts';

type Directives = ReadonlyMap<string, readonly string[]>;

const BROAD_SCRIPT_SOURCES = new Set(['*', 'http:', 'https:', 'data:']);
const BROAD_FRAME_SOURCES = new Set(['*', 'http:', 'https:']);
const REFERRER_POLICIES = new Set([
	'no-referrer',
	'no-referrer-when-downgrade',
	'same-origin',
	'origin',
	'strict-origin',
	'origin-when-cross-origin',
	'strict-origin-when-cross-origin',
	'unsafe-url'
]);
const UNSAFE_REFERRER_POLICIES = new Set(['unsafe-url', 'no-referrer-when-downgrade']);
const RESTRICTED_FEATURES = ['camera', 'microphone', 'geolocation'] as const;
const PERMISSIONS_MEMBER = /^([a-z][a-z0-9_-]*)\s*=\s*(.+)$/;
const ALLOWLIST_WILDCARD = /(^|[\s(])\*(?=[\s)]|$)/;
const VERSION_HEADERS = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator'] as const;
const PRODUCT_VERSION = /(^|[\s(;,])[A-Za-z][\w.-]*\/v?\d+(\.\d+)*(?=$|[\s();,])/;
const BARE_VERSION = /\b\d+\.\d+(\.\d+)*\b/;

export type HeaderExtras = {
	readonly metaCsp?: readonly string[];
	readonly metaReferrer?: string;
};

function splitValues(values: readonly string[] | undefined): string[] {
	return (values ?? []).flatMap((value) => value.split(',')).map((value) => value.trim());
}

export function parseCspPolicies(values: readonly string[]): Directives[] {
	const policies: Directives[] = [];
	for (const policyText of values.flatMap((value) => value.split(','))) {
		const directives = new Map<string, readonly string[]>();
		for (const part of policyText.split(';')) {
			const tokens = part.trim().split(/\s+/).filter((token) => token !== '');
			const name = tokens[0]?.toLowerCase();
			if (name !== undefined && !directives.has(name)) {
				directives.set(name, tokens.slice(1).map((token) => token.toLowerCase()));
			}
		}
		if (directives.size > 0) {
			policies.push(directives);
		}
	}
	return policies;
}

export function restrictsScripts(policy: Directives): boolean {
	const sources = policy.get('script-src') ?? policy.get('default-src');
	if (sources === undefined) {
		return false;
	}
	const strictDynamic = sources.includes("'strict-dynamic'");
	const nonceOrHash = sources.some((source) => source.startsWith("'nonce-") || /^'sha(256|384|512)-/.test(source));
	const inlineAllowed = sources.includes("'unsafe-inline'") && !nonceOrHash && !strictDynamic;
	const broadSource = !strictDynamic && sources.some((source) => BROAD_SCRIPT_SOURCES.has(source));
	return !inlineAllowed && !broadSource;
}

function frameAncestorsVerdict(policy: Directives): boolean | undefined {
	const sources = policy.get('frame-ancestors');
	if (sources === undefined) {
		return undefined;
	}
	return !sources.some((source) => BROAD_FRAME_SOURCES.has(source));
}

export function xFrameOptionsProtects(values: readonly string[] | undefined): boolean {
	const options = new Set(splitValues(values).map((value) => value.toLowerCase()).filter((value) => value !== ''));
	if (options.size > 1) {
		return options.has('deny') || options.has('sameorigin') || options.has('allowall');
	}
	return options.has('deny') || options.has('sameorigin');
}

export function effectiveReferrerPolicy(values: readonly string[] | undefined, metaReferrer?: string): string | undefined {
	let policy: string | undefined;
	for (const token of splitValues(values).map((value) => value.toLowerCase())) {
		if (REFERRER_POLICIES.has(token)) {
			policy = token;
		}
	}
	const meta = metaReferrer?.trim().toLowerCase();
	if (meta !== undefined && REFERRER_POLICIES.has(meta)) {
		policy = meta;
	}
	return policy;
}

export function unrestrictedFeatures(values: readonly string[] | undefined): readonly string[] | 'unparseable' {
	if (values === undefined || values.length === 0) {
		return [...RESTRICTED_FEATURES];
	}
	const members = new Map<string, string>();
	for (const member of values.join(',').split(',')) {
		const trimmed = member.trim();
		if (trimmed === '') {
			continue;
		}
		const match = PERMISSIONS_MEMBER.exec(trimmed);
		if (match === null || match[1] === undefined || match[2] === undefined) {
			return 'unparseable';
		}
		members.set(match[1], match[2].trim());
	}
	return RESTRICTED_FEATURES.filter((feature) => {
		const allowlist = members.get(feature);
		return allowlist === undefined || ALLOWLIST_WILDCARD.test(allowlist);
	});
}

export function disclosedVersions(headers: HeaderMap): readonly string[] {
	const disclosed: string[] = [];
	for (const name of VERSION_HEADERS) {
		for (const value of headers[name] ?? []) {
			if (PRODUCT_VERSION.test(value) || (name.startsWith('x-') && BARE_VERSION.test(value))) {
				disclosed.push(`${name}: ${value}`);
			}
		}
	}
	return disclosed;
}

export function checkHeaders(headers: HeaderMap, extras: HeaderExtras = {}): CheckResult {
	const findings: Finding[] = [];
	const passed: PassedCheck[] = [];
	const notes: Note[] = [];

	const headerPolicies = parseCspPolicies(headers['content-security-policy'] ?? []);
	const enforcedPolicies = [...headerPolicies, ...parseCspPolicies(extras.metaCsp ?? [])];
	if (enforcedPolicies.length === 0) {
		findings.push({ code: 'csp-missing' });
		if (headers['content-security-policy-report-only'] !== undefined) {
			notes.push('csp-report-only');
		}
	} else if (!enforcedPolicies.some(restrictsScripts)) {
		findings.push({ code: 'csp-unsafe', evidence: capEvidence({ policy: headers['content-security-policy'] ?? extras.metaCsp ?? [] }) });
	} else {
		passed.push('csp');
	}

	const ancestorVerdicts = headerPolicies.map(frameAncestorsVerdict).filter((verdict) => verdict !== undefined);
	const framingProtected = ancestorVerdicts.length > 0
		? ancestorVerdicts.some((verdict) => verdict)
		: xFrameOptionsProtects(headers['x-frame-options']);
	if (framingProtected) {
		passed.push('framing');
	} else {
		findings.push({ code: 'framing-allowed', evidence: capEvidence({ xFrameOptions: headers['x-frame-options'] ?? [] }) });
	}

	const nosniff = splitValues(headers['x-content-type-options'])[0]?.toLowerCase();
	if (nosniff === 'nosniff') {
		passed.push('nosniff');
	} else {
		findings.push({ code: 'nosniff-missing' });
	}

	const referrer = effectiveReferrerPolicy(headers['referrer-policy'], extras.metaReferrer);
	if (referrer === undefined || UNSAFE_REFERRER_POLICIES.has(referrer)) {
		findings.push(referrer === undefined ? { code: 'referrer-policy-missing' } : { code: 'referrer-policy-missing', evidence: { value: referrer } });
	} else {
		passed.push('referrer-policy');
	}

	const unrestricted = unrestrictedFeatures(headers['permissions-policy']);
	if (unrestricted === 'unparseable') {
		findings.push({ code: 'permissions-policy-missing', evidence: { reason: 'unparseable' } });
	} else if (unrestricted.length > 0) {
		findings.push({ code: 'permissions-policy-missing', evidence: { features: unrestricted } });
	} else {
		passed.push('permissions-policy');
	}

	const versions = disclosedVersions(headers);
	if (versions.length > 0) {
		findings.push({ code: 'version-disclosure', evidence: capEvidence({ headers: versions }) });
	} else {
		passed.push('version');
	}

	return { findings, passed, notes };
}
