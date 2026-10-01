import { isCronRequest } from '../../src/security/cron.ts';
import { json } from '../../src/security/response-headers.ts';
import { cleanup } from '../../src/store/cleanup.ts';
import { sqlClient } from '../../src/store/sql.ts';

export async function GET(request: Request): Promise<Response> {
	if (!isCronRequest(request)) {
		return json({ error: 'unauthorized' }, 401);
	}
	const databaseUrl = process.env.DATABASE_URL;
	if (databaseUrl === undefined || databaseUrl === '') {
		return json({ error: 'unavailable' }, 503);
	}
	return json({ ok: true, ...(await cleanup(sqlClient(databaseUrl), new Date())) });
}
