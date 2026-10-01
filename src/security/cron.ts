import { timingSafeEqual } from 'node:crypto';

const MIN_SECRET_LENGTH = 32;

export function isCronRequest(request: Request, env: NodeJS.ProcessEnv = process.env): boolean {
	const secret = env.CRON_SECRET ?? '';
	if (secret.length < MIN_SECRET_LENGTH) {
		return false;
	}
	const expected = Buffer.from(`Bearer ${secret}`);
	const received = Buffer.from(request.headers.get('authorization') ?? '');
	return received.length === expected.length && timingSafeEqual(received, expected);
}
