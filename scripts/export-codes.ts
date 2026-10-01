import { FINDINGS, NOTES, PASSED_CHECKS } from '../src/contract/codes.ts';

console.log(JSON.stringify({ findings: FINDINGS, passed: PASSED_CHECKS, notes: NOTES }, null, '\t'));
