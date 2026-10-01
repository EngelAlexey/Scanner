import { FINDINGS, NOTES, PASSED_CHECKS } from '../src/contract/codes.ts';
import { USER_AGENT } from '../src/net/safe-request.ts';

console.log(JSON.stringify({ userAgent: USER_AGENT, findings: FINDINGS, passed: PASSED_CHECKS, notes: NOTES }, null, '\t'));
