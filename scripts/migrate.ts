import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { neon } from '@neondatabase/serverless';

const MIGRATIONS_DIR = join(import.meta.dirname, '..', 'migrations');

const databaseUrl = process.env.DATABASE_URL;
if (databaseUrl === undefined || databaseUrl === '') {
	console.error('DATABASE_URL is not set');
	process.exit(2);
}

const sql = neon(databaseUrl);
await sql.query('create table if not exists schema_migrations (name text primary key, applied_at timestamptz not null default now())');

const files = (await readdir(MIGRATIONS_DIR)).filter((file) => file.endsWith('.sql')).sort();
for (const file of files) {
	const applied = await sql.query('select 1 from schema_migrations where name = $1', [file]);
	if (applied.length > 0) {
		console.log(`skip    ${file}`);
		continue;
	}
	const statements = (await readFile(join(MIGRATIONS_DIR, file), 'utf8'))
		.split(/;\s*(?:\r?\n|$)/)
		.map((statement) => statement.trim())
		.filter((statement) => statement !== '');
	await sql.transaction([
		...statements.map((statement) => sql.query(statement)),
		sql.query('insert into schema_migrations (name) values ($1)', [file])
	]);
	console.log(`applied ${file} (${statements.length} statements)`);
}
