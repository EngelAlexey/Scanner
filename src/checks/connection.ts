import type { PassedCheck } from '../contract/codes.ts';
import type { CheckResult, Finding, HeaderMap } from '../contract/types.ts';
import type { FetchResult } from '../net/safe-request.ts';
import type { Handshake, TlsProbe } from '../net/tls-probe.ts';
import { capEvidence } from './evidence.ts';

export const HSTS_MIN_MAX_AGE = 31_536_000;

export type HstsPolicy = { readonly maxAge: number; readonly includeSubDomains: boolean; readonly preload: boolean };

export function parseHsts(value: string | undefined): HstsPolicy | undefined {
	if (value === undefined) {
		return undefined;
	}
	const directives = new Map<string, string>();
	for (const part of value.split(';')) {
		const trimmed = part.trim();
		if (trimmed === '') {
			continue;
		}
		const separator = trimmed.indexOf('=');
		const name = (separator === -1 ? trimmed : trimmed.slice(0, separator)).trim().toLowerCase();
		let directiveValue = separator === -1 ? '' : trimmed.slice(separator + 1).trim();
		if (directiveValue.length >= 2 && directiveValue.startsWith('"') && directiveValue.endsWith('"')) {
			directiveValue = directiveValue.slice(1, -1);
		}
		if (directives.has(name)) {
			return undefined;
		}
		directives.set(name, directiveValue);
	}
	const maxAge = directives.get('max-age');
	if (maxAge === undefined || !/^\d+$/.test(maxAge)) {
		return undefined;
	}
	return {
		maxAge: Number(maxAge),
		includeSubDomains: directives.has('includesubdomains'),
		preload: directives.has('preload')
	};
}

export function checkHsts(headers: HeaderMap, secure: boolean): CheckResult {
	const value = headers['strict-transport-security']?.[0];
	const policy = secure ? parseHsts(value) : undefined;
	if (policy === undefined || policy.maxAge === 0) {
		return {
			findings: [value === undefined ? { code: 'hsts-missing' } : { code: 'hsts-missing', evidence: capEvidence({ value }) }],
			passed: [],
			notes: []
		};
	}
	if (policy.maxAge < HSTS_MIN_MAX_AGE) {
		return { findings: [{ code: 'hsts-short', evidence: { maxAge: policy.maxAge } }], passed: [], notes: [] };
	}
	return { findings: [], passed: ['hsts'], notes: [] };
}

const EXPIRED_ERRORS = new Set(['CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID']);
const NAME_ERRORS = new Set(['ERR_TLS_CERT_ALTNAME_INVALID', 'NO_DNS_SUBJECT_ALT_NAME', 'HOSTNAME_MISMATCH']);
const INCOMPLETE_CHAIN = 'UNABLE_TO_VERIFY_LEAF_SIGNATURE';
const UNTRUSTED_ERRORS = new Set([
	'DEPTH_ZERO_SELF_SIGNED_CERT',
	'SELF_SIGNED_CERT_IN_CHAIN',
	'UNABLE_TO_GET_ISSUER_CERT',
	'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
	'CERT_UNTRUSTED',
	'CERT_REJECTED',
	'INVALID_CA',
	'CERT_SIGNATURE_FAILURE',
	'CA_KEY_TOO_SMALL',
	'EE_KEY_TOO_SMALL',
	'CA_MD_TOO_WEAK'
]);
const DAY_MS = 86_400_000;
const PROTOCOL_LABELS: Readonly<Record<string, string>> = {
	'TLSv1': 'TLS 1.0',
	'TLSv1.1': 'TLS 1.1',
	'TLSv1.2': 'TLS 1.2',
	'TLSv1.3': 'TLS 1.3'
};

export function isKnownCertificateError(code: string): boolean {
	return EXPIRED_ERRORS.has(code) || NAME_ERRORS.has(code) || UNTRUSTED_ERRORS.has(code) || code === INCOMPLETE_CHAIN;
}

function day(time: number): string {
	return new Date(time).toISOString().slice(0, 10);
}

function checkCertificate(handshake: Extract<Handshake, { ok: true }>, now: Date, findings: Finding[], passed: PassedCheck[]): void {
	const error = handshake.authorizationError;
	const validFrom = Date.parse(handshake.certificate.validFrom);
	const validTo = Date.parse(handshake.certificate.validTo);
	const outOfDates = Number.isNaN(validTo) || now.getTime() > validTo || now.getTime() < validFrom;
	const expired = outOfDates || (error !== null && EXPIRED_ERRORS.has(error));
	const mismatch = handshake.identityError !== null || (error !== null && NAME_ERRORS.has(error));
	const untrusted = error !== null && UNTRUSTED_ERRORS.has(error);
	const unknown = error !== null && !isKnownCertificateError(error);

	if (expired) {
		findings.push(Number.isNaN(validTo) ? { code: 'cert-expired' } : { code: 'cert-expired', evidence: { validTo: day(validTo) } });
	}
	if (mismatch) {
		findings.push({ code: 'cert-name-mismatch', evidence: capEvidence({ names: handshake.certificate.dnsNames }) });
	}
	if (untrusted) {
		findings.push(handshake.certificate.issuer === '' ? { code: 'cert-untrusted' } : { code: 'cert-untrusted', evidence: capEvidence({ issuer: handshake.certificate.issuer }) });
	}
	if (!expired && !mismatch && !untrusted && !unknown) {
		passed.push('certificate');
	}
	if (error === INCOMPLETE_CHAIN) {
		findings.push({ code: 'cert-chain-incomplete' });
	} else if (error === null || NAME_ERRORS.has(error)) {
		passed.push('cert-chain');
	}
	if (!expired) {
		const daysLeft = (validTo - now.getTime()) / DAY_MS;
		if (daysLeft < 7) {
			findings.push({ code: 'cert-expires-7d', evidence: { expires: day(validTo) } });
		} else if (daysLeft < 30) {
			findings.push({ code: 'cert-expires-30d', evidence: { expires: day(validTo) } });
		} else {
			passed.push('cert-expiry');
		}
	}
}

export function checkTls(probe: TlsProbe, now: Date): CheckResult {
	const findings: Finding[] = [];
	const passed: PassedCheck[] = [];
	const { handshake } = probe;
	if (handshake.ok) {
		passed.push('https');
		if (handshake.protocol === 'TLSv1.3') {
			passed.push('tls13');
		} else {
			findings.push({ code: 'tls13-missing', evidence: { protocol: PROTOCOL_LABELS[handshake.protocol] ?? handshake.protocol } });
		}
		checkCertificate(handshake, now, findings, passed);
	} else {
		findings.push({ code: 'https-unavailable' });
	}
	const legacy = [
		...(probe.tls10 === 'accepted' ? ['TLS 1.0'] : []),
		...(probe.tls11 === 'accepted' ? ['TLS 1.1'] : [])
	];
	if (legacy.length > 0) {
		findings.push({ code: 'tls-legacy', evidence: { versions: legacy } });
	} else if (probe.tls10 === 'rejected' && probe.tls11 === 'rejected') {
		passed.push('tls-legacy');
	}
	return { findings, passed, notes: [] };
}

export function checkHttpRedirect(result: FetchResult): CheckResult {
	if (!result.ok) {
		if (result.error === 'connection_failed' || result.error === 'timeout') {
			return { findings: [], passed: ['http-redirect'], notes: ['http-not-served'] };
		}
		return { findings: [], passed: [], notes: [] };
	}
	const { stop, url } = result.page;
	if (stop !== undefined && stop.location.startsWith('https:')) {
		return { findings: [], passed: ['http-redirect'], notes: [] };
	}
	return { findings: [{ code: 'http-no-redirect', evidence: capEvidence({ url: stop?.location ?? url }) }], passed: [], notes: [] };
}
