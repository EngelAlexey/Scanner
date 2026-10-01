import { neon, type NeonQueryFunction } from '@neondatabase/serverless';

export type SqlClient = NeonQueryFunction<false, false>;

const clients = new Map<string, SqlClient>();

export function sqlClient(databaseUrl: string): SqlClient {
	let client = clients.get(databaseUrl);
	if (client === undefined) {
		client = neon(databaseUrl);
		clients.set(databaseUrl, client);
	}
	return client;
}
