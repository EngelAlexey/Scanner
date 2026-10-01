import type { FindingCode, NoteCode, PassedCheck } from './codes.ts';

export type SectionStatus = 'pending' | 'ok' | 'error' | 'blocked' | 'not_applicable';

export type Evidence = Readonly<Record<string, string | number | boolean | readonly string[]>>;

export type Finding = {
	readonly code: FindingCode;
	readonly evidence?: Evidence;
};

export type Note = NoteCode | `${NoteCode}:${string}`;

export type CheckResult = {
	readonly findings: readonly Finding[];
	readonly passed: readonly PassedCheck[];
	readonly notes: readonly Note[];
};

export type HeaderMap = Readonly<Record<string, readonly string[]>>;
