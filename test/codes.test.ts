import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { FINDINGS, FINDING_CODES, NOTES, PASSED_CHECKS, SECTIONS, SEVERITIES } from '../src/contract/codes.ts';

const KEBAB = /^[a-z0-9]+(-[a-z0-9]+)*$/;

describe('finding codes', () => {
	test('the closed list has 35 codes', () => {
		assert.equal(FINDING_CODES.length, 35);
	});

	test('every code is kebab-case', () => {
		for (const code of FINDING_CODES) {
			assert.match(code, KEBAB, `${code} is not kebab-case`);
		}
	});

	test('every code has a known section and severity', () => {
		for (const code of FINDING_CODES) {
			const { section, severity } = FINDINGS[code];
			assert.ok(SECTIONS.includes(section), `${code} has an unknown section: ${section}`);
			assert.ok(SEVERITIES.includes(severity), `${code} has an unknown severity: ${severity}`);
		}
	});

	test('every code belongs to a check of its own section', () => {
		for (const code of FINDING_CODES) {
			const { section, check } = FINDINGS[code];
			assert.equal(PASSED_CHECKS[check], section, `${code} points to ${check}, which is not in ${section}`);
		}
	});

	test('every check has at least one finding that can fail it', () => {
		const failing = new Set(FINDING_CODES.map((code) => FINDINGS[code].check));
		for (const check of Object.keys(PASSED_CHECKS)) {
			assert.ok(failing.has(check as keyof typeof PASSED_CHECKS), `${check} has no finding`);
		}
	});

	test('every section has at least one finding', () => {
		for (const section of SECTIONS) {
			assert.ok(
				FINDING_CODES.some((code) => FINDINGS[code].section === section),
				`${section} has no findings`
			);
		}
	});
});

describe('passed checks and observations', () => {
	test('every passed check belongs to a known section', () => {
		for (const [check, section] of Object.entries(PASSED_CHECKS)) {
			assert.match(check, KEBAB, `${check} is not kebab-case`);
			assert.ok(SECTIONS.includes(section), `${check} has an unknown section: ${section}`);
		}
	});

	test('observation codes are unique and kebab-case', () => {
		assert.equal(new Set(NOTES).size, NOTES.length);
		for (const note of NOTES) {
			assert.match(note, KEBAB, `${note} is not kebab-case`);
		}
	});
});
