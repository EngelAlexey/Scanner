import type { CheckResult, HeaderMap } from '../contract/types.ts';
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
