import { parse, type DefaultTreeAdapterTypes } from 'parse5';
import type { PassedCheck } from '../contract/codes.ts';
import type { CheckResult, Finding, HeaderMap, Note } from '../contract/types.ts';
import type { FetchedPage, FetchResult } from '../net/safe-request.ts';
import { capEvidence } from './evidence.ts';
import { parseCspPolicies } from './headers.ts';

type Element = DefaultTreeAdapterTypes.Element;
type Node = DefaultTreeAdapterTypes.Node;

export type PageFacts = {
	readonly formActions: readonly string[];
	readonly activeResources: readonly string[];
	readonly passiveResources: readonly string[];
	readonly scripts: readonly { readonly src: string; readonly integrity: boolean }[];
	readonly metaCsp: readonly string[];
	readonly metaReferrer: string | undefined;
};

const HTML_TYPES = /^(text\/html|application\/xhtml\+xml)\b/i;
const PLAIN_TEXT = /^text\/plain\b/i;
const ACTIVE_SOURCES: Readonly<Record<string, string>> = { script: 'src', iframe: 'src', frame: 'src', object: 'data', embed: 'src' };
const PASSIVE_SOURCES: Readonly<Record<string, string>> = { img: 'src', audio: 'src', video: 'src', source: 'src', track: 'src' };
const PINNED_CDNS = [
	/^https?:\/\/cdn\.jsdelivr\.net\/npm\/(@[^/]+\/)?[^/@]+@\d+\.\d+\.\d+[^/]*\//i,
	/^https?:\/\/unpkg\.com\/(@[^/]+\/)?[^/@]+@\d+\.\d+\.\d+[^/]*\//i,
	/^https?:\/\/cdnjs\.cloudflare\.com\/ajax\/libs\/[^/]+\/\d+(\.\d+)+[^/]*\//i,
	/^https?:\/\/code\.jquery\.com\//i,
	/^https?:\/\/ajax\.googleapis\.com\/ajax\/libs\//i,
	/^https?:\/\/stackpath\.bootstrapcdn\.com\//i,
	/^https?:\/\/ga\.jspm\.io\//i
];

function attribute(element: Element, name: string): string | undefined {
	return element.attrs.find((attr) => attr.name === name)?.value;
}

function absolute(value: string | undefined, base: URL): string | undefined {
	if (value === undefined || value.trim() === '') {
		return undefined;
	}
	try {
		return new URL(value.trim(), base).href;
	} catch {
		return undefined;
	}
}

function elements(root: Node): Element[] {
	const found: Element[] = [];
	const stack: Node[] = [root];
	while (stack.length > 0) {
		const node = stack.pop();
		if (node === undefined) {
			continue;
		}
		if ('tagName' in node) {
			found.push(node);
		}
		if ('childNodes' in node && node.nodeName !== 'template') {
			stack.push(...[...node.childNodes].reverse());
		}
	}
	return found;
}

function isInHead(element: Element): boolean {
	for (let parent = element.parentNode; parent !== null; parent = 'parentNode' in parent ? parent.parentNode : null) {
		if (parent.nodeName === 'head') {
			return true;
		}
	}
	return false;
}

export function decodeBody(body: Buffer, contentType: string | undefined): string {
	const charset = /charset\s*=\s*"?([\w-]+)/i.exec(contentType ?? '')?.[1];
	try {
		return new TextDecoder(charset ?? 'utf-8').decode(body);
	} catch {
		return new TextDecoder('utf-8').decode(body);
	}
}

export function extractPage(html: string, pageUrl: string): PageFacts {
	const all = elements(parse(html));
	const baseHref = all.find((element) => element.tagName === 'base' && attribute(element, 'href') !== undefined);
	const base = new URL(absolute(baseHref === undefined ? undefined : attribute(baseHref, 'href'), new URL(pageUrl)) ?? pageUrl);
	const formActions: string[] = [];
	const activeResources: string[] = [];
	const passiveResources: string[] = [];
	const scripts: { src: string; integrity: boolean }[] = [];
	const metaCsp: string[] = [];
	let metaReferrer: string | undefined;

	for (const element of all) {
		const tag = element.tagName;
		if (tag === 'form') {
			const action = absolute(attribute(element, 'action'), base);
			if (action !== undefined) {
				formActions.push(action);
			}
		} else if ((tag === 'button' || tag === 'input') && attribute(element, 'formaction') !== undefined) {
			const action = absolute(attribute(element, 'formaction'), base);
			if (action !== undefined) {
				formActions.push(action);
			}
		}
		const activeAttribute = ACTIVE_SOURCES[tag];
		if (activeAttribute !== undefined) {
			const source = absolute(attribute(element, activeAttribute), base);
			if (source !== undefined) {
				activeResources.push(source);
				if (tag === 'script') {
					scripts.push({ src: source, integrity: (attribute(element, 'integrity') ?? '').trim() !== '' });
				}
			}
		}
		if (tag === 'link' && /(^|\s)stylesheet(\s|$)/i.test(attribute(element, 'rel') ?? '')) {
			const source = absolute(attribute(element, 'href'), base);
			if (source !== undefined) {
				activeResources.push(source);
			}
		}
		const passiveAttribute = PASSIVE_SOURCES[tag];
		if (passiveAttribute !== undefined) {
			const source = absolute(attribute(element, passiveAttribute), base);
			if (source !== undefined) {
				passiveResources.push(source);
			}
		}
		if (tag === 'meta') {
			const equiv = attribute(element, 'http-equiv')?.toLowerCase();
			const content = attribute(element, 'content');
			if (equiv === 'content-security-policy' && content !== undefined && isInHead(element)) {
				metaCsp.push(content);
			}
			if (attribute(element, 'name')?.toLowerCase() === 'referrer' && content !== undefined) {
				metaReferrer = content;
			}
		}
	}
	return { formActions, activeResources, passiveResources, scripts, metaCsp, metaReferrer };
}

function upgradesInsecureRequests(headers: HeaderMap, facts: PageFacts): boolean {
	return parseCspPolicies([...(headers['content-security-policy'] ?? []), ...facts.metaCsp]).some((policy) =>
		policy.has('upgrade-insecure-requests')
	);
}

function isPlainHttp(url: string): boolean {
	return url.startsWith('http:');
}

function unique(values: readonly string[]): string[] {
	return [...new Set(values)].sort();
}

export function isHtml(page: FetchedPage): boolean {
	return HTML_TYPES.test(page.headers['content-type']?.[0] ?? '') && page.bodyReadable;
}

export function checkPageContent(page: FetchedPage, facts: PageFacts): CheckResult {
	const findings: Finding[] = [];
	const passed: PassedCheck[] = [];
	const notes: Note[] = page.truncated ? ['content-truncated'] : [];

	const insecureForms = unique(facts.formActions.filter(isPlainHttp));
	if (insecureForms.length > 0) {
		findings.push({ code: 'form-insecure-action', evidence: capEvidence({ actions: insecureForms }) });
	} else {
		passed.push('forms');
	}

	const upgraded = upgradesInsecureRequests(page.headers, facts);
	const active = upgraded ? [] : unique(facts.activeResources.filter(isPlainHttp));
	if (active.length > 0) {
		findings.push({ code: 'mixed-content', evidence: capEvidence({ resources: active }) });
	} else {
		passed.push('mixed-content');
	}
	if (!upgraded && facts.passiveResources.some(isPlainHttp)) {
		notes.push('mixed-content-passive');
	}

	const unprotected = unique(facts.scripts.filter((script) => !script.integrity && PINNED_CDNS.some((cdn) => cdn.test(script.src))).map((script) => script.src));
	if (unprotected.length > 0) {
		findings.push({ code: 'sri-missing', evidence: capEvidence({ scripts: unprotected }) });
	} else {
		passed.push('sri');
	}
	return { findings, passed, notes };
}

export function checkSecurityTxt(result: FetchResult | undefined, now: Date): CheckResult {
	const missing: CheckResult = { findings: [{ code: 'security-txt-missing' }], passed: [], notes: [] };
	if (result === undefined || !result.ok || result.page.status !== 200 || result.page.stop !== undefined) {
		return missing;
	}
	if (!PLAIN_TEXT.test(result.page.headers['content-type']?.[0] ?? '')) {
		return missing;
	}
	const text = decodeBody(result.page.body, result.page.headers['content-type']?.[0]);
	const contact = /^contact:\s*\S+/im.test(text);
	const expires = Date.parse(/^expires:\s*(.+?)\s*$/im.exec(text)?.[1] ?? '');
	if (!contact || Number.isNaN(expires) || expires <= now.getTime()) {
		return missing;
	}
	return { findings: [], passed: ['security-txt'], notes: [] };
}
