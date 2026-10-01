export const SECTIONS = ['connection', 'headers', 'cookies', 'content', 'email'] as const;
export type SectionId = (typeof SECTIONS)[number];

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

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

type FindingSpec = { readonly section: SectionId; readonly severity: Severity; readonly check: PassedCheck };

export const FINDINGS = {
	'https-unavailable': { section: 'connection', severity: 'critical', check: 'https' },
	'https-downgrade': { section: 'connection', severity: 'critical', check: 'https' },
	'http-no-redirect': { section: 'connection', severity: 'high', check: 'http-redirect' },
	'cert-expired': { section: 'connection', severity: 'critical', check: 'certificate' },
	'cert-name-mismatch': { section: 'connection', severity: 'critical', check: 'certificate' },
	'cert-untrusted': { section: 'connection', severity: 'critical', check: 'certificate' },
	'cert-chain-incomplete': { section: 'connection', severity: 'medium', check: 'cert-chain' },
	'cert-expires-30d': { section: 'connection', severity: 'medium', check: 'cert-expiry' },
	'cert-expires-7d': { section: 'connection', severity: 'high', check: 'cert-expiry' },
	'tls-legacy': { section: 'connection', severity: 'high', check: 'tls-legacy' },
	'tls13-missing': { section: 'connection', severity: 'info', check: 'tls13' },
	'hsts-missing': { section: 'connection', severity: 'high', check: 'hsts' },
	'hsts-short': { section: 'connection', severity: 'low', check: 'hsts' },
	'csp-missing': { section: 'headers', severity: 'medium', check: 'csp' },
	'csp-unsafe': { section: 'headers', severity: 'medium', check: 'csp' },
	'framing-allowed': { section: 'headers', severity: 'medium', check: 'framing' },
	'nosniff-missing': { section: 'headers', severity: 'low', check: 'nosniff' },
	'referrer-policy-missing': { section: 'headers', severity: 'low', check: 'referrer-policy' },
	'permissions-policy-missing': { section: 'headers', severity: 'low', check: 'permissions-policy' },
	'version-disclosure': { section: 'headers', severity: 'low', check: 'version' },
	'session-cookie-no-secure': { section: 'cookies', severity: 'high', check: 'cookies' },
	'cookie-no-secure': { section: 'cookies', severity: 'low', check: 'cookies' },
	'session-cookie-no-httponly': { section: 'cookies', severity: 'high', check: 'cookies' },
	'cookie-no-httponly': { section: 'cookies', severity: 'info', check: 'cookies' },
	'cookie-no-samesite': { section: 'cookies', severity: 'medium', check: 'cookies' },
	'form-insecure-action': { section: 'content', severity: 'critical', check: 'forms' },
	'mixed-content': { section: 'content', severity: 'medium', check: 'mixed-content' },
	'sri-missing': { section: 'content', severity: 'low', check: 'sri' },
	'security-txt-missing': { section: 'content', severity: 'info', check: 'security-txt' },
	'spf-missing': { section: 'email', severity: 'high', check: 'spf' },
	'spf-permissive': { section: 'email', severity: 'high', check: 'spf' },
	'spf-invalid': { section: 'email', severity: 'medium', check: 'spf' },
	'dmarc-missing': { section: 'email', severity: 'high', check: 'dmarc' },
	'dmarc-policy-none': { section: 'email', severity: 'medium', check: 'dmarc' },
	'caa-missing': { section: 'email', severity: 'low', check: 'caa' }
} as const satisfies Record<string, FindingSpec>;

export type FindingCode = keyof typeof FINDINGS;
export const FINDING_CODES = Object.keys(FINDINGS) as FindingCode[];

export const NOTES = [
	'cdn',
	'hsts-preloaded',
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
