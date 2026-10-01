import { FINDING_CODES, FINDINGS, SEVERITIES, type FindingCode, type SectionId, type Severity } from './contract/codes.ts';
import type { SectionResult } from './contract/types.ts';

export const SCORING_VERSION = '1.2.0';

export const PENALTIES: Readonly<Record<Severity, number>> = { critical: 40, high: 15, medium: 7, low: 3, info: 0 };

export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';

export type Scoring = {
	readonly score: number;
	readonly grade: Grade;
	readonly partial: boolean;
	readonly urgent: readonly FindingCode[];
};

const URGENT_SEVERITIES: ReadonlySet<Severity> = new Set(['critical', 'high']);

export function gradeFor(score: number, critical: boolean): Grade {
	const grade: Grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F';
	return critical && (grade === 'A' || grade === 'B' || grade === 'C') ? 'D' : grade;
}

export function presentCodes(sections: Readonly<Record<SectionId, SectionResult>>): FindingCode[] {
	const codes = new Set<FindingCode>();
	for (const section of Object.values(sections)) {
		if (section.status === 'ok') {
			for (const finding of section.findings) {
				codes.add(finding.code);
			}
		}
	}
	return [...codes];
}

export function byPriority(raised: ReadonlySet<FindingCode> = new Set()): (a: FindingCode, b: FindingCode) => number {
	return (a, b) =>
		Number(!raised.has(a)) - Number(!raised.has(b)) ||
		SEVERITIES.indexOf(FINDINGS[a].severity) - SEVERITIES.indexOf(FINDINGS[b].severity) ||
		FINDING_CODES.indexOf(a) - FINDING_CODES.indexOf(b);
}

export function score(sections: Readonly<Record<SectionId, SectionResult>>, raised: ReadonlySet<FindingCode> = new Set()): Scoring {
	const codes = presentCodes(sections);
	const penalty = codes.reduce((sum, code) => sum + PENALTIES[FINDINGS[code].severity], 0);
	const total = Math.max(0, 100 - penalty);
	const critical = codes.some((code) => FINDINGS[code].severity === 'critical');
	const partial = Object.values(sections).some((section) => section.status === 'error' || section.status === 'blocked');
	const urgent = codes.filter((code) => URGENT_SEVERITIES.has(FINDINGS[code].severity) || raised.has(code)).sort(byPriority(raised));
	return { score: total, grade: gradeFor(total, critical), partial, urgent };
}
