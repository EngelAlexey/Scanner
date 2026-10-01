import type { Evidence } from '../contract/types.ts';

export const MAX_EVIDENCE_ITEMS = 5;
export const MAX_EVIDENCE_LENGTH = 120;

const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/g;

function capText(text: string): string {
	const clean = text.replace(CONTROL_CHARACTERS, '');
	return clean.length > MAX_EVIDENCE_LENGTH ? `${clean.slice(0, MAX_EVIDENCE_LENGTH - 1)}…` : clean;
}

export function capEvidence(evidence: Record<string, string | number | boolean | readonly string[]>): Evidence {
	const capped: Record<string, string | number | boolean | readonly string[]> = {};
	for (const [key, value] of Object.entries(evidence)) {
		if (typeof value === 'string') {
			capped[key] = capText(value);
		} else if (typeof value === 'number' || typeof value === 'boolean') {
			capped[key] = value;
		} else {
			capped[key] = value.slice(0, MAX_EVIDENCE_ITEMS).map(capText);
		}
	}
	return capped;
}
