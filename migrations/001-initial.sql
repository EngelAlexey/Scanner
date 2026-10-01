create table if not exists reports (
	id text primary key,
	host text not null,
	status text not null check (status in ('running', 'done', 'failed')),
	scoring_version text not null,
	data jsonb not null default '{}',
	created_at timestamptz not null default now(),
	finished_at timestamptz,
	expires_at timestamptz not null default now() + interval '30 days'
);

create index if not exists reports_host_created_at on reports (host, created_at desc);
create index if not exists reports_expires_at on reports (expires_at);

create table if not exists rate_limits (
	bucket text not null,
	window_start timestamptz not null,
	hits integer not null,
	primary key (bucket, window_start)
);
