import { getDomain } from 'tldts';
import type { CheckResult, Finding, Note } from '../contract/types.ts';
import type { SetCookie } from '../net/safe-request.ts';
import { capEvidence } from './evidence.ts';

type SameSite = 'strict' | 'lax' | 'none' | 'invalid' | 'absent';

export type ParsedCookie = {
	readonly name: string;
	readonly domain: string;
	readonly path: string;
	readonly secure: boolean;
	readonly httpOnly: boolean;
	readonly sameSite: SameSite;
	readonly deleted: boolean;
};

const SESSION_NAMES = new Set(
	[
		'phpsessid',
		'jsessionid',
		'asp.net_sessionid',
		'connect.sid',
		'laravel_session',
		'next-auth.session-token',
		'__secure-next-auth.session-token',
		'authjs.session-token',
		'__secure-authjs.session-token',
		'sessionid',
		'rack.session',
		'ci_session',
		'cfid',
		'cftoken',
		'_session_id'
	].map((name) => name.toLowerCase())
);
const SESSION_PATTERNS = [/^wordpress_(logged_in|sec)_[0-9a-f]{32}$/i, /^_[a-z0-9_]+_session$/i, /^s?sess[0-9a-f]{32}$/i, /^aspsessionid[a-z]+$/i];
const SESSION_WORDS = /sess|session|sid|auth|token|jwt/i;
const NEVER_SESSION = [
	/^(xsrf-token|csrftoken|_csrf|csrf_token|csrf-token|__requestverificationtoken)$/i,
	/^\.aspnetcore\.antiforgery/i,
	/^(_ga|_ga_.+|_gid|_gat.*|_gcl_.+|_fbp|_fbc|_hj.+|_clck|_clsk|mp_.+|ajs_.+|amplitude_.+)$/i,
	/^(__cf_bm|cf_clearance|__cflb|awsalb.*|awselb|arraffinity.*|incap_ses_.+|visid_incap_.+|nlbi_.+|bigipserver.+|ts01.+)$/i,
	/^(cookieconsent_status|cookieconsent|optanonconsent|optanonalertboxclosed|euconsent-v2|cmplz_.+|didomi_token|usprivacy)$/i
];

export function isSessionCookie(name: string): boolean {
	if (NEVER_SESSION.some((pattern) => pattern.test(name))) {
		return false;
	}
	return SESSION_NAMES.has(name.toLowerCase()) || SESSION_PATTERNS.some((pattern) => pattern.test(name)) || SESSION_WORDS.test(name);
}

function domainMatches(host: string, domain: string): boolean {
	return host === domain || host.endsWith(`.${domain}`);
}

export function parseSetCookie(header: string, host: string, now: Date): ParsedCookie | undefined {
	const [pair = '', ...attributes] = header.split(';');
	const separator = pair.indexOf('=');
	const name = separator === -1 ? '' : pair.slice(0, separator).trim();
	if (name === '') {
		return undefined;
	}
	let domain = host;
	let path = '/';
	let secure = false;
	let httpOnly = false;
	let sameSite: SameSite = 'absent';
	let maxAge: number | undefined;
	let expires: number | undefined;
	for (const attribute of attributes) {
		const equals = attribute.indexOf('=');
		const key = (equals === -1 ? attribute : attribute.slice(0, equals)).trim().toLowerCase();
		const value = equals === -1 ? '' : attribute.slice(equals + 1).trim();
		if (key === 'secure') {
			secure = true;
		} else if (key === 'httponly') {
			httpOnly = true;
		} else if (key === 'samesite') {
			const lowered = value.toLowerCase();
			sameSite = lowered === 'strict' || lowered === 'lax' || lowered === 'none' ? lowered : 'invalid';
		} else if (key === 'domain' && value !== '') {
			const declared = value.replace(/^\./, '').toLowerCase();
			if (!domainMatches(host, declared) || getDomain(declared) === null) {
				return undefined;
			}
			domain = declared;
		} else if (key === 'path' && value.startsWith('/')) {
			path = value;
		} else if (key === 'max-age' && /^-?\d+$/.test(value)) {
			maxAge = Number(value);
		} else if (key === 'expires') {
			const time = Date.parse(value);
			expires = Number.isNaN(time) ? undefined : time;
		}
	}
	const deleted = maxAge !== undefined ? maxAge <= 0 : expires !== undefined && expires <= now.getTime();
	return { name, domain, path, secure, httpOnly, sameSite, deleted };
}

function finding(code: Finding['code'], names: readonly string[]): Finding[] {
	return names.length === 0 ? [] : [{ code, evidence: capEvidence({ cookies: [...new Set(names)].sort() }) }];
}

export function checkCookies(setCookies: readonly SetCookie[], now: Date): CheckResult {
	const latest = new Map<string, ParsedCookie>();
	for (const { host, header } of setCookies) {
		const cookie = parseSetCookie(header, host.toLowerCase(), now);
		if (cookie !== undefined) {
			latest.set(`${cookie.name}|${cookie.domain}|${cookie.path}`, cookie);
		}
	}
	const notes: Note[] = [];
	const kept: ParsedCookie[] = [];
	for (const cookie of latest.values()) {
		if (cookie.deleted) {
			continue;
		}
		if (cookie.sameSite === 'none' && !cookie.secure) {
			if (!notes.includes('cookie-samesite-none-rejected')) {
				notes.push('cookie-samesite-none-rejected');
			}
			continue;
		}
		kept.push(cookie);
	}
	const session = kept.filter((cookie) => isSessionCookie(cookie.name));
	const other = kept.filter((cookie) => !isSessionCookie(cookie.name));
	const names = (cookies: readonly ParsedCookie[], test: (cookie: ParsedCookie) => boolean): string[] =>
		cookies.filter(test).map((cookie) => cookie.name);
	const findings = [
		...finding('session-cookie-no-secure', names(session, (cookie) => !cookie.secure)),
		...finding('session-cookie-no-httponly', names(session, (cookie) => !cookie.httpOnly)),
		...finding('cookie-no-samesite', names(session, (cookie) => cookie.sameSite === 'absent' || cookie.sameSite === 'invalid')),
		...finding('cookie-no-secure', names(other, (cookie) => !cookie.secure)),
		...finding('cookie-no-httponly', names(other, (cookie) => !cookie.httpOnly))
	];
	return { findings, passed: findings.length === 0 ? ['cookies'] : [], notes };
}
