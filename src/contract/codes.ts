// Closed list of everything a scan can report. Each finding has a fixed section
// and severity, so the grade depends only on which codes appear in a report.
// The portfolio keeps one MDX explanation per finding code (codes.json is
// exported from this file), so a new code needs its explanation as well.

export const SECTIONS = ['connection', 'headers', 'cookies', 'content', 'email'] as const;
export type SectionId = (typeof SECTIONS)[number];

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

type FindingSpec = { readonly section: SectionId; readonly severity: Severity };

export const FINDINGS = {
	'https-unavailable': { section: 'connection', severity: 'critical' },
	'https-downgrade': { section: 'connection', severity: 'critical' },
	'http-no-redirect': { section: 'connection', severity: 'high' },
	'cert-expired': { section: 'connection', severity: 'critical' },
	'cert-name-mismatch': { section: 'connection', severity: 'critical' },
	'cert-untrusted': { section: 'connection', severity: 'critical' },
	'cert-chain-incomplete': { section: 'connection', severity: 'medium' },
	'cert-expires-30d': { section: 'connection', severity: 'medium' },
	'cert-expires-7d': { section: 'connection', severity: 'high' },
	'tls-legacy': { section: 'connection', severity: 'high' },
	'tls13-missing': { section: 'connection', severity: 'info' },
	'hsts-missing': { section: 'connection', severity: 'high' },
	'hsts-short': { section: 'connection', severity: 'low' },
	'csp-missing': { section: 'headers', severity: 'medium' },
	'csp-unsafe': { section: 'headers', severity: 'medium' },
	'framing-allowed': { section: 'headers', severity: 'medium' },
	'nosniff-missing': { section: 'headers', severity: 'low' },
	'referrer-policy-missing': { section: 'headers', severity: 'low' },
	'permissions-policy-missing': { section: 'headers', severity: 'low' },
	'version-disclosure': { section: 'headers', severity: 'low' },
	'session-cookie-no-secure': { section: 'cookies', severity: 'high' },
	'cookie-no-secure': { section: 'cookies', severity: 'low' },
	'session-cookie-no-httponly': { section: 'cookies', severity: 'high' },
	'cookie-no-httponly': { section: 'cookies', severity: 'info' },
	'cookie-no-samesite': { section: 'cookies', severity: 'medium' },
	'form-insecure-action': { section: 'content', severity: 'critical' },
	'mixed-content': { section: 'content', severity: 'medium' },
	'sri-missing': { section: 'content', severity: 'low' },
	'security-txt-missing': { section: 'content', severity: 'info' },
	'spf-missing': { section: 'email', severity: 'high' },
	'spf-permissive': { section: 'email', severity: 'high' },
	'spf-invalid': { section: 'email', severity: 'medium' },
	'dmarc-missing': { section: 'email', severity: 'high' },
	'dmarc-policy-none': { section: 'email', severity: 'medium' },
	'caa-missing': { section: 'email', severity: 'low' }
} as const satisfies Record<string, FindingSpec>;

export type FindingCode = keyof typeof FINDINGS;
export const FINDING_CODES = Object.keys(FINDINGS) as FindingCode[];

// Checks that passed, shown under "Qué hace bien su sitio", grouped by section.
export const PASSED_CHECKS = {
	'https': 'connection',
	'http-redirect': 'connection',
	'certificate': 'connection',
	'cert-chain': 'connection',
	'cert-expiry': 'connection',
	'tls-legacy': 'connection',
	'tls13': 'connection',
	'hsts': 'connection',
	'csp': 'headers',
	'framing': 'headers',
	'nosniff': 'headers',
	'referrer-policy': 'headers',
	'permissions-policy': 'headers',
	'version': 'headers',
	'cookies': 'cookies',
	'forms': 'content',
	'mixed-content': 'content',
	'sri': 'content',
	'security-txt': 'content',
	'spf': 'email',
	'dmarc': 'email',
	'caa': 'email'
} as const satisfies Record<string, SectionId>;

export type PassedCheck = keyof typeof PASSED_CHECKS;

// Observations never change the score. `cdn` is stored with its provider,
// as in `cdn:cloudflare`.
export const NOTES = [
	'cdn',
	'no-mx',
	'http-not-served',
	'ipv6-only',
	'redirects-offsite',
	'content-truncated',
	'http2-only',
	'csp-report-only',
	'mixed-content-passive',
	'cookie-samesite-none-rejected',
	'spf-ptr-deprecated',
	'dmarc-testing'
] as const;

export type NoteCode = (typeof NOTES)[number];
